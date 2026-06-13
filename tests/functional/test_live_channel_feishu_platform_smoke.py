"""Opt-in live Feishu platform smoke.

This maintainer-only gate hits a real Feishu tenant when explicitly enabled.
Credentials come from environment variables or the local OpenSquilla config;
do not store them in fixtures or repository files.
"""

from __future__ import annotations

import json
import os
import tempfile
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import pytest

from opensquilla.channels.feishu import FeishuChannel, FeishuChannelConfig
from opensquilla.tools.builtin.feishu_platform import (
    _platform_json,
    clear_feishu_channels,
    feishu_doc_create,
    feishu_doc_list_blocks,
    feishu_doc_read_raw,
    feishu_drive_search,
    feishu_drive_upload_artifact,
    feishu_perm_grant_member,
    feishu_scopes_status,
    feishu_wiki_get_node,
    feishu_wiki_list_nodes,
    feishu_wiki_list_spaces,
    register_feishu_channel,
)
from opensquilla.tools.builtin.file_authoring import create_csv
from opensquilla.tools.types import CallerKind, ToolContext, current_tool_context

pytestmark = pytest.mark.live_channel


@dataclass(frozen=True)
class LiveFeishuCredentials:
    app_id: str
    app_secret: str
    channel_name: str
    api_base: str
    domain: Literal["feishu", "lark"]
    source: str


@dataclass
class LiveCheck:
    name: str
    status: str
    detail: dict[str, Any] = field(default_factory=dict)


def _require_live_credentials() -> LiveFeishuCredentials:
    if os.environ.get("OPENSQUILLA_FEISHU_LIVE") != "1":
        pytest.skip("set OPENSQUILLA_FEISHU_LIVE=1 to run live Feishu platform smoke")
    app_id = os.environ.get("OPENSQUILLA_FEISHU_APP_ID", "").strip()
    app_secret = os.environ.get("OPENSQUILLA_FEISHU_APP_SECRET", "").strip()
    if app_id or app_secret:
        if not app_id or not app_secret:
            pytest.skip("set both OPENSQUILLA_FEISHU_APP_ID and OPENSQUILLA_FEISHU_APP_SECRET")
        return LiveFeishuCredentials(
            app_id=app_id,
            app_secret=app_secret,
            channel_name=os.environ.get("OPENSQUILLA_FEISHU_CHANNEL", "env"),
            api_base=os.environ.get(
                "OPENSQUILLA_FEISHU_API_BASE",
                "https://open.feishu.cn/open-apis",
            ),
            domain="lark" if os.environ.get("OPENSQUILLA_FEISHU_DOMAIN") == "lark" else "feishu",
            source="env",
        )
    credentials = _load_live_config_credentials()
    if credentials is None:
        pytest.skip(
            "set OPENSQUILLA_FEISHU_APP_ID/OPENSQUILLA_FEISHU_APP_SECRET or configure a Feishu "
            "channel in OPENSQUILLA_FEISHU_CONFIG_PATH, OPENSQUILLA_GATEWAY_CONFIG_PATH, or "
            "~/.opensquilla/config.toml"
        )
    return credentials


def _load_live_config_credentials() -> LiveFeishuCredentials | None:
    from opensquilla.gateway.config import GatewayConfig

    config_path = (
        os.environ.get("OPENSQUILLA_FEISHU_CONFIG_PATH")
        or os.environ.get("OPENSQUILLA_GATEWAY_CONFIG_PATH")
        or None
    )
    candidates: list[str | Path | None] = [config_path]
    if config_path is None:
        userprofile = os.environ.get("USERPROFILE", "").strip()
        if userprofile:
            userprofile_config = Path(userprofile) / ".opensquilla" / "config.toml"
            if userprofile_config.is_file():
                candidates.append(userprofile_config)

    for candidate in candidates:
        config = GatewayConfig.load(candidate)
        credentials = _credentials_from_gateway_config(config)
        if credentials is not None:
            return credentials
    return None


def _credentials_from_gateway_config(config: Any) -> LiveFeishuCredentials | None:
    feishu_entries = [
        entry for entry in config.channels.channels if getattr(entry, "type", None) == "feishu"
    ]
    if not feishu_entries:
        return None

    preferred_name = os.environ.get("OPENSQUILLA_FEISHU_CHANNEL", "").strip()
    if preferred_name:
        selected = next((entry for entry in feishu_entries if entry.name == preferred_name), None)
    else:
        selected = next((entry for entry in feishu_entries if entry.enabled), feishu_entries[0])
    if selected is None:
        return None

    app_id = getattr(selected, "app_id", "").strip()
    app_secret = getattr(selected, "app_secret", "").strip()
    if not app_id or not app_secret:
        return None
    return LiveFeishuCredentials(
        app_id=app_id,
        app_secret=app_secret,
        channel_name=selected.name,
        api_base=selected.api_base,
        domain=selected.domain,
        source="config",
    )


def test_live_feishu_credentials_prefer_explicit_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENSQUILLA_FEISHU_LIVE", "1")
    monkeypatch.setenv("OPENSQUILLA_FEISHU_APP_ID", "cli_from_env")
    monkeypatch.setenv("OPENSQUILLA_FEISHU_APP_SECRET", "secret_from_env")

    credentials = _require_live_credentials()

    assert credentials.app_id == "cli_from_env"
    assert credentials.app_secret == "secret_from_env"
    assert credentials.source == "env"


def test_live_feishu_credentials_fall_back_to_enabled_config_channel(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        """
[[channels.channels]]
name = "old-feishu"
type = "feishu"
enabled = false
app_id = "cli_old"
app_secret = "secret_old"

[[channels.channels]]
name = "feishu"
type = "feishu"
enabled = true
app_id = "cli_from_config"
app_secret = "secret_from_config"
connection_mode = "websocket"
api_base = "https://open.feishu.cn/open-apis"
domain = "feishu"
""".lstrip(),
        encoding="utf-8",
    )
    monkeypatch.setenv("OPENSQUILLA_FEISHU_LIVE", "1")
    monkeypatch.delenv("OPENSQUILLA_FEISHU_APP_ID", raising=False)
    monkeypatch.delenv("OPENSQUILLA_FEISHU_APP_SECRET", raising=False)
    monkeypatch.setenv("OPENSQUILLA_FEISHU_CONFIG_PATH", str(config_path))

    credentials = _require_live_credentials()

    assert credentials.app_id == "cli_from_config"
    assert credentials.app_secret == "secret_from_config"
    assert credentials.channel_name == "feishu"
    assert credentials.source == "config"


def test_live_feishu_credentials_fall_back_to_windows_userprofile(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    wrong_home = tmp_path / "wrong-home"
    userprofile = tmp_path / "windows-user"
    config_dir = userprofile / ".opensquilla"
    config_dir.mkdir(parents=True)
    (config_dir / "config.toml").write_text(
        """
[[channels.channels]]
name = "feishu"
type = "feishu"
enabled = true
app_id = "cli_from_userprofile"
app_secret = "secret_from_userprofile"
""".lstrip(),
        encoding="utf-8",
    )
    monkeypatch.setenv("OPENSQUILLA_FEISHU_LIVE", "1")
    monkeypatch.delenv("OPENSQUILLA_FEISHU_APP_ID", raising=False)
    monkeypatch.delenv("OPENSQUILLA_FEISHU_APP_SECRET", raising=False)
    monkeypatch.delenv("OPENSQUILLA_FEISHU_CONFIG_PATH", raising=False)
    monkeypatch.delenv("OPENSQUILLA_GATEWAY_CONFIG_PATH", raising=False)
    monkeypatch.setenv("HOME", str(wrong_home))
    monkeypatch.setenv("USERPROFILE", str(userprofile))

    credentials = _load_live_config_credentials()

    assert credentials is not None
    assert credentials.app_id == "cli_from_userprofile"
    assert credentials.app_secret == "secret_from_userprofile"
    assert credentials.source == "config"


async def _json_result(awaitable: Awaitable[str]) -> dict[str, Any]:
    payload = json.loads(await awaitable)
    if not isinstance(payload, dict):
        raise AssertionError(f"expected JSON object, got: {payload!r}")
    return payload


def _check_success(name: str, payload: dict[str, Any], **detail: Any) -> LiveCheck:
    assert payload.get("status") != "error", payload
    return LiveCheck(name=name, status="PASS", detail=detail or _compact(payload))


def _check_missing_scope(name: str, payload: dict[str, Any]) -> LiveCheck:
    if payload.get("status") == "error" and payload.get("error_type") == "missing_scope":
        diagnostic = payload.get("diagnostic")
        assert isinstance(diagnostic, dict)
        scopes = diagnostic.get("required_scopes")
        assert isinstance(scopes, list) and scopes, payload
        return LiveCheck(
            name=name,
            status="EXPECTED_MISSING_SCOPE",
            detail={
                "feature": diagnostic.get("feature"),
                "code": diagnostic.get("code"),
                "required_scopes": scopes,
            },
        )
    return _check_success(name, payload)


def _compact(value: Any) -> Any:
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            if key == "content" and isinstance(item, str):
                result[key] = {"length": len(item), "preview": item[:80]}
            elif key == "grant_url":
                result[key] = "<redacted>"
            elif key == "features" and isinstance(item, dict):
                result[key] = sorted(item)
            else:
                result[key] = _compact(item)
        return result
    if isinstance(value, list):
        return [_compact(item) for item in value[:5]]
    return value


def _document_id(payload: dict[str, Any]) -> str:
    document = payload.get("document")
    assert isinstance(document, dict), payload
    value = document.get("document_id")
    assert isinstance(value, str) and value, payload
    return value


async def _record(
    checks: list[LiveCheck],
    name: str,
    func: Callable[[], Awaitable[LiveCheck]],
) -> LiveCheck:
    try:
        check = await func()
    except Exception as exc:
        check = LiveCheck(
            name=name,
            status="FAIL",
            detail={"type": type(exc).__name__, "message": str(exc)},
        )
    checks.append(check)
    return check


def _assert_no_failures(checks: list[LiveCheck]) -> None:
    failures = [check for check in checks if check.status == "FAIL"]
    assert not failures, [check.__dict__ for check in failures]


@pytest.mark.asyncio
async def test_feishu_platform_live_smoke() -> None:
    credentials = _require_live_credentials()
    marker = f"opensquilla-live-smoke-{int(time.time())}"
    checks: list[LiveCheck] = []
    channel = FeishuChannel(
        FeishuChannelConfig(
            app_id=credentials.app_id,
            app_secret=credentials.app_secret,
            connection_mode="webhook",
            api_base=credentials.api_base,
            domain=credentials.domain,
        )
    )
    register_feishu_channel("live", channel)

    try:
        await _record(
            checks,
            "tenant_access_token",
            lambda: _tenant_access_token_check(channel),
        )
        await _record(checks, "bot_info", lambda: _bot_info_check(channel))
        await _record(
            checks,
            "scopes_status",
            lambda: _scopes_status_check(),
        )

        doc_check = await _record(
            checks,
            "doc_create",
            lambda: _doc_create_check(marker),
        )
        document_id = str(doc_check.detail.get("document_id") or "")
        if document_id:
            await _record(
                checks,
                "doc_read_raw",
                lambda: _doc_read_raw_check(document_id),
            )
            await _record(
                checks,
                "doc_list_blocks",
                lambda: _doc_list_blocks_check(document_id),
            )
        else:
            checks.append(
                LiveCheck("doc_read_raw", "SKIP", {"reason": "doc_create returned no document_id"})
            )
            checks.append(
                LiveCheck(
                    "doc_list_blocks",
                    "SKIP",
                    {"reason": "doc_create returned no document_id"},
                )
            )

        root_token = await _root_folder_token(channel, checks)
        if root_token:
            await _record(
                checks,
                "drive_upload_csv",
                lambda: _drive_upload_csv_check(root_token, marker),
            )
        else:
            checks.append(
                LiveCheck(
                    "drive_upload_csv",
                    "SKIP",
                    {"reason": "drive root folder token unavailable"},
                )
            )

        await _record(checks, "drive_search", lambda: _drive_search_check(marker))
        await _run_wiki_checks(checks)
        await _record(
            checks,
            "permission_grant_member_dry_run",
            lambda: _permission_dry_run_check(document_id),
        )
        if (
            os.environ.get("OPENSQUILLA_FEISHU_LIVE_MUTATE_PERM") == "1"
            and os.environ.get("OPENSQUILLA_FEISHU_TEST_OPEN_ID")
            and document_id
        ):
            await _record(
                checks,
                "permission_grant_member_mutation",
                lambda: _permission_mutation_check(document_id),
            )
        else:
            checks.append(
                LiveCheck(
                    "permission_grant_member_mutation",
                    "SKIP",
                    {
                        "reason": (
                            "requires OPENSQUILLA_FEISHU_TEST_OPEN_ID, "
                            "OPENSQUILLA_FEISHU_LIVE_MUTATE_PERM=1, and doc_create success"
                        )
                    },
                )
            )
    finally:
        await channel.stop()
        clear_feishu_channels()

    _assert_no_failures(checks)


async def _tenant_access_token_check(channel: FeishuChannel) -> LiveCheck:
    token = await channel._get_token()
    assert token
    return LiveCheck(
        name="tenant_access_token",
        status="PASS",
        detail={"token_received": True, "token_length": len(token)},
    )


async def _bot_info_check(channel: FeishuChannel) -> LiveCheck:
    await channel._refresh_bot_identity()
    assert channel.bot_open_id
    return LiveCheck(name="bot_info", status="PASS", detail={"bot_open_id_present": True})


async def _scopes_status_check() -> LiveCheck:
    payload = await _json_result(feishu_scopes_status(channel="live"))
    return _check_success("scopes_status", payload, features=sorted(payload.get("features", {})))


async def _doc_create_check(marker: str) -> LiveCheck:
    payload = await _json_result(feishu_doc_create(title=f"{marker} doc", channel="live"))
    document_id = _document_id(payload)
    return _check_success("doc_create", payload, document_id=document_id)


async def _doc_read_raw_check(document_id: str) -> LiveCheck:
    payload = await _json_result(feishu_doc_read_raw(document_id=document_id, channel="live"))
    assert "content" in payload, payload
    return _check_success("doc_read_raw", payload, content_length=len(str(payload["content"])))


async def _doc_list_blocks_check(document_id: str) -> LiveCheck:
    payload = await _json_result(feishu_doc_list_blocks(document_id=document_id, channel="live"))
    assert isinstance(payload.get("items"), list), payload
    return _check_success("doc_list_blocks", payload, block_count=len(payload["items"]))


async def _root_folder_token(channel: FeishuChannel, checks: list[LiveCheck]) -> str | None:
    try:
        payload = await _platform_json(channel, "GET", "/drive/explorer/v2/root_folder/meta")
    except Exception as exc:
        checks.append(
            LiveCheck(
                "drive_root_folder_meta",
                "FAIL",
                {"type": type(exc).__name__, "message": str(exc)},
            )
        )
        return None
    token = payload.get("token")
    status = "PASS" if isinstance(token, str) and token else "FAIL"
    checks.append(
        LiveCheck(
            "drive_root_folder_meta",
            status,
            {"token_present": bool(token), "id_present": bool(payload.get("id"))},
        )
    )
    return token if isinstance(token, str) else None


async def _drive_upload_csv_check(root_token: str, marker: str) -> LiveCheck:
    with tempfile.TemporaryDirectory(prefix="opensquilla-feishu-live-") as tmp_dir:
        ctx = ToolContext(
            is_owner=False,
            caller_kind=CallerKind.CHANNEL,
            source_name="live",
            channel_kind="feishu",
            channel_id="live-drive",
            sender_id="live-smoke",
            artifact_media_root=str(Path(tmp_dir) / "media"),
            artifact_session_id="live-session",
            session_key=f"agent:main:feishu:live:{marker}",
        )
        token = current_tool_context.set(ctx)
        try:
            artifact = await _json_result(
                create_csv(rows=[["kind", "value"], ["live", marker]], name=f"{marker}.csv")
            )
            artifact_id = artifact.get("artifact", {}).get("id")
            assert isinstance(artifact_id, str) and artifact_id, artifact
            payload = await _json_result(
                feishu_drive_upload_artifact(artifact_id=artifact_id, parent_node=root_token)
            )
        finally:
            current_tool_context.reset(token)
    return _check_missing_scope("drive_upload_csv", payload)


async def _drive_search_check(marker: str) -> LiveCheck:
    payload = await _json_result(feishu_drive_search(query=marker, channel="live"))
    return _check_missing_scope("drive_search", payload)


async def _run_wiki_checks(checks: list[LiveCheck]) -> None:
    spaces_payload = await _json_result(feishu_wiki_list_spaces(channel="live"))
    spaces_check = _check_missing_scope("wiki_list_spaces", spaces_payload)
    checks.append(spaces_check)
    if spaces_check.status == "EXPECTED_MISSING_SCOPE":
        checks.append(LiveCheck("wiki_list_nodes", "SKIP", {"reason": "wiki scopes missing"}))
        checks.append(LiveCheck("wiki_get_node", "SKIP", {"reason": "wiki scopes missing"}))
        return

    items = spaces_payload.get("items")
    if not isinstance(items, list) or not items:
        checks.append(LiveCheck("wiki_list_nodes", "SKIP", {"reason": "no wiki spaces returned"}))
        checks.append(LiveCheck("wiki_get_node", "SKIP", {"reason": "no wiki spaces returned"}))
        return
    first_space = items[0]
    assert isinstance(first_space, dict), spaces_payload
    space_id = first_space.get("space_id")
    assert isinstance(space_id, str) and space_id, spaces_payload
    nodes_payload = await _json_result(feishu_wiki_list_nodes(space_id=space_id, channel="live"))
    nodes_check = _check_missing_scope("wiki_list_nodes", nodes_payload)
    checks.append(nodes_check)
    if nodes_check.status == "EXPECTED_MISSING_SCOPE":
        checks.append(LiveCheck("wiki_get_node", "SKIP", {"reason": "wiki node scopes missing"}))
        return
    nodes = nodes_payload.get("items")
    if not isinstance(nodes, list) or not nodes:
        checks.append(LiveCheck("wiki_get_node", "SKIP", {"reason": "no wiki nodes returned"}))
        return
    first_node = nodes[0]
    assert isinstance(first_node, dict), nodes_payload
    node_token = first_node.get("node_token") or first_node.get("token")
    assert isinstance(node_token, str) and node_token, nodes_payload
    node_payload = await _json_result(feishu_wiki_get_node(token=node_token, channel="live"))
    checks.append(_check_missing_scope("wiki_get_node", node_payload))


async def _permission_dry_run_check(document_id: str) -> LiveCheck:
    payload = await _json_result(
        feishu_perm_grant_member(
            token=document_id or "dry_run_token",
            doc_type="docx" if document_id else "file",
            member_type="openid",
            member_id=os.environ.get("OPENSQUILLA_FEISHU_TEST_OPEN_ID", "ou_placeholder"),
            perm="view",
            channel="live",
        )
    )
    assert payload.get("status") == "dry_run", payload
    return LiveCheck(
        name="permission_grant_member_dry_run",
        status="PASS",
        detail={"operation": payload.get("operation")},
    )


async def _permission_mutation_check(document_id: str) -> LiveCheck:
    payload = await _json_result(
        feishu_perm_grant_member(
            token=document_id,
            doc_type="docx",
            member_type="openid",
            member_id=os.environ["OPENSQUILLA_FEISHU_TEST_OPEN_ID"],
            perm="view",
            dry_run=False,
            channel="live",
        )
    )
    return _check_missing_scope("permission_grant_member_mutation", payload)
