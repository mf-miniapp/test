"""Feishu platform tools for channel-safe chat, media, and scope diagnostics."""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import TYPE_CHECKING, Any, cast

import structlog

from opensquilla.artifacts import ArtifactStore
from opensquilla.channels.contract import (
    CHANNEL_PLATFORM_CATEGORIES,
    ChannelPlatformCapability,
    ChannelPlatformCapabilityStatus,
    ChannelPlatformCategories,
    ChannelPlatformManifest,
    ChannelSendResult,
)
from opensquilla.tools.registry import tool
from opensquilla.tools.types import ToolError, current_tool_context

if TYPE_CHECKING:
    from opensquilla.channels.feishu import FeishuApiError, FeishuChannel

log = structlog.get_logger(__name__)

_channels: dict[str, FeishuChannel] = {}
_MISSING_SCOPE_CODES = {99991663, 99991672}
_MISSING_SCOPE_NOTICE_COOLDOWN_S = 300.0
_missing_scope_notices: dict[tuple[str, str, int | None, tuple[str, ...]], float] = {}
_monotonic = time.monotonic
_SCOPE_RE = re.compile(r"\b[a-z][a-z0-9_.-]*(?::[a-z0-9_.-]+)+\b")

@dataclass(frozen=True)
class FeishuFeatureCapability:
    category: str
    tools: tuple[str, ...]
    required_scopes: tuple[str, ...]
    mutates: bool = False
    dry_run_supported: bool = False
    default_channel_visible: bool = False


_FEATURE_CAPABILITIES: dict[str, FeishuFeatureCapability] = {
    "chat_send": FeishuFeatureCapability(
        category="chat",
        tools=("feishu_chat_send",),
        required_scopes=("im:message", "im:message:send_as_bot"),
        mutates=True,
    ),
    "chat_reply": FeishuFeatureCapability(
        category="chat",
        tools=("feishu_chat_reply",),
        required_scopes=("im:message", "im:message:send_as_bot"),
        mutates=True,
    ),
    "chat_read": FeishuFeatureCapability(
        category="chat",
        tools=("feishu_chat_read",),
        required_scopes=("im:message", "im:message:readonly"),
    ),
    "chat_edit": FeishuFeatureCapability(
        category="chat",
        tools=("feishu_chat_edit",),
        required_scopes=("im:message", "im:message:update", "im:message:send_as_bot"),
        mutates=True,
    ),
    "doc_create": FeishuFeatureCapability(
        category="doc",
        tools=("feishu_doc_create",),
        required_scopes=("docx:document",),
        mutates=True,
        default_channel_visible=True,
    ),
    "doc_read": FeishuFeatureCapability(
        category="doc",
        tools=("feishu_doc_read_raw", "feishu_doc_list_blocks"),
        required_scopes=("docx:document", "docx:document:readonly"),
        default_channel_visible=True,
    ),
    "drive_meta": FeishuFeatureCapability(
        category="drive",
        tools=("feishu_drive_meta",),
        required_scopes=("drive:file:readonly",),
        default_channel_visible=True,
    ),
    "drive_search": FeishuFeatureCapability(
        category="drive",
        tools=("feishu_drive_search",),
        required_scopes=("drive:file:readonly",),
        default_channel_visible=True,
    ),
    "drive_upload": FeishuFeatureCapability(
        category="drive",
        tools=("feishu_drive_upload_artifact",),
        required_scopes=("drive:drive", "drive:file", "drive:file:upload"),
        mutates=True,
        default_channel_visible=True,
    ),
    "media_upload": FeishuFeatureCapability(
        category="media",
        tools=("feishu_media_upload_artifact",),
        required_scopes=("im:resource", "im:resource:upload"),
        mutates=True,
        default_channel_visible=True,
    ),
    "perm_member": FeishuFeatureCapability(
        category="perm",
        tools=("feishu_perm_grant_member",),
        required_scopes=("drive:permission:member",),
        mutates=True,
        dry_run_supported=True,
    ),
    "wiki_read": FeishuFeatureCapability(
        category="wiki",
        tools=(
            "feishu_wiki_get_node",
            "feishu_wiki_list_nodes",
            "feishu_wiki_list_spaces",
        ),
        required_scopes=("wiki:space:retrieve", "wiki:wiki", "wiki:wiki:readonly"),
        default_channel_visible=True,
    ),
}
_FEATURE_SCOPES: dict[str, tuple[str, ...]] = {
    feature: capability.required_scopes
    for feature, capability in _FEATURE_CAPABILITIES.items()
}
_VALID_PERMISSION_LEVELS = {"view", "edit", "full_access"}

_FEISHU_PLATFORM_CATEGORY_MAP: dict[str, str] = {
    "chat": ChannelPlatformCategories.CHAT,
    "media": ChannelPlatformCategories.MEDIA,
    "doc": ChannelPlatformCategories.DOCS,
    "drive": ChannelPlatformCategories.DRIVE,
    "wiki": ChannelPlatformCategories.WIKI,
    "perm": ChannelPlatformCategories.PERMISSIONS,
}


def _unique_preserve_order(values: list[str]) -> tuple[str, ...]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        out.append(value)
    return tuple(out)


def build_feishu_platform_manifest() -> ChannelPlatformManifest:
    """Build Feishu's provider-level capability manifest from tool metadata."""

    feature_rows: dict[str, list[FeishuFeatureCapability]] = {}
    for capability in _FEATURE_CAPABILITIES.values():
        category = _FEISHU_PLATFORM_CATEGORY_MAP[capability.category]
        feature_rows.setdefault(category, []).append(capability)

    capabilities: list[ChannelPlatformCapability] = []
    for category in CHANNEL_PLATFORM_CATEGORIES:
        rows = feature_rows.get(category, [])
        if category == ChannelPlatformCategories.FILES:
            rows = feature_rows.get(ChannelPlatformCategories.MEDIA, [])
        if category == ChannelPlatformCategories.ATTACHMENTS:
            capabilities.append(
                ChannelPlatformCapability(
                    category=category,
                    status=ChannelPlatformCapabilityStatus.SUPPORTED,
                    notes=("Feishu message resources can be resolved by the adapter.",),
                )
            )
            continue
        if category == ChannelPlatformCategories.THREADS:
            capabilities.append(
                ChannelPlatformCapability(
                    category=category,
                    status=ChannelPlatformCapabilityStatus.SUPPORTED,
                    notes=("Thread reply uses Feishu message metadata when present.",),
                )
            )
            continue
        if category == ChannelPlatformCategories.CARDS:
            capabilities.append(
                ChannelPlatformCapability(
                    category=category,
                    status=ChannelPlatformCapabilityStatus.SUPPORTED,
                    notes=("Feishu supports cards and interactive cards.",),
                )
            )
            continue
        if category == ChannelPlatformCategories.SCOPES:
            capabilities.append(
                ChannelPlatformCapability(
                    category=category,
                    status=ChannelPlatformCapabilityStatus.SUPPORTED,
                    tools=("feishu_scopes_status",),
                    default_channel_visible=True,
                )
            )
            continue
        if not rows:
            capabilities.append(
                ChannelPlatformCapability(
                    category=category,
                    status=ChannelPlatformCapabilityStatus.UNSUPPORTED,
                )
            )
            continue

        status = (
            ChannelPlatformCapabilityStatus.CONFIG_REQUIRED
            if category == ChannelPlatformCategories.PERMISSIONS
            else ChannelPlatformCapabilityStatus.SUPPORTED
        )
        capabilities.append(
            ChannelPlatformCapability(
                category=category,
                status=status,
                tools=_unique_preserve_order(
                    [tool for row in rows for tool in row.tools]
                ),
                required_scopes=_unique_preserve_order(
                    [scope for row in rows for scope in row.required_scopes]
                ),
                mutates=any(row.mutates for row in rows),
                dry_run_supported=any(row.dry_run_supported for row in rows),
                default_channel_visible=any(row.default_channel_visible for row in rows),
            )
        )

    return ChannelPlatformManifest(
        channel_type="feishu",
        capabilities=tuple(capabilities),
    )


def register_feishu_channel(name: str, channel: FeishuChannel) -> None:
    """Register a live Feishu adapter for platform tools."""
    _channels[name] = channel


def clear_feishu_channels() -> None:
    """Clear registered Feishu adapters. Intended for tests and channel restarts."""
    _channels.clear()
    clear_feishu_scope_notice_cache()


def clear_feishu_scope_notice_cache() -> None:
    """Clear missing-scope duplicate notices. Intended for tests and gateway restarts."""
    _missing_scope_notices.clear()


def unregister_feishu_channel(name: str) -> None:
    """Remove one Feishu adapter from platform-tool routing."""
    _channels.pop(name, None)
    for key in list(_missing_scope_notices):
        if key[0] == name:
            _missing_scope_notices.pop(key, None)


def _current_channel_name(explicit: str | None) -> str:
    if explicit:
        return explicit
    ctx = current_tool_context.get()
    if ctx is not None and ctx.source_name:
        return ctx.source_name
    if len(_channels) == 1:
        return next(iter(_channels))
    raise ToolError("feishu channel is not specified")


def _channel(explicit: str | None) -> tuple[str, FeishuChannel]:
    name = _current_channel_name(explicit)
    channel = _channels.get(name)
    if channel is None:
        available = ", ".join(sorted(_channels)) or "none"
        raise ToolError(f"unknown Feishu channel: {name}. Available: {available}")
    return name, channel


def _grant_url(channel: FeishuChannel) -> str:
    base = channel.config.api_base.split("/open-apis", 1)[0]
    return f"{base}/app/{channel.config.app_id}/permissions"


def _required_scopes(data: dict[str, Any], message: str) -> list[str]:
    scopes: set[str] = set()
    error = data.get("error")
    if isinstance(error, dict):
        violations = error.get("permission_violations")
        if isinstance(violations, list):
            for item in violations:
                if not isinstance(item, dict):
                    continue
                subject = item.get("subject")
                if isinstance(subject, str) and ":" in subject:
                    scopes.add(subject)
    scopes.update(_SCOPE_RE.findall(message))
    return sorted(scopes)


def _is_missing_scope(exc: FeishuApiError) -> bool:
    message = str(exc).lower()
    return exc.code in _MISSING_SCOPE_CODES or (
        "scope" in message and ("permission" in message or "access denied" in message)
    )


def _coerce_feishu_api_error(exc: Exception) -> FeishuApiError | None:
    from opensquilla.channels.feishu import FeishuApiError

    if isinstance(exc, FeishuApiError):
        return exc
    return None


def _scope_diagnostic(
    *,
    channel: FeishuChannel,
    feature: str,
    exc: FeishuApiError,
) -> dict[str, Any]:
    required = _required_scopes(exc.data, str(exc))
    if not required:
        required = list(_FEATURE_SCOPES.get(feature, ()))
    return {
        "feature": feature,
        "code": exc.code,
        "message": str(exc),
        "required_scopes": required,
        "grant_url": _grant_url(channel),
    }


def _error_payload(
    *,
    channel_name: str,
    channel: FeishuChannel,
    feature: str,
    exc: FeishuApiError,
) -> str:
    if not _is_missing_scope(exc):
        raise ToolError(f"Feishu {feature} failed: {exc}") from exc
    diagnostic = _scope_diagnostic(channel=channel, feature=feature, exc=exc)
    key = (
        channel_name,
        feature,
        exc.code,
        tuple(str(scope) for scope in diagnostic.get("required_scopes", [])),
    )
    now = _monotonic()
    last_notice = _missing_scope_notices.get(key)
    _missing_scope_notices[key] = now
    if last_notice is not None and now - last_notice < _MISSING_SCOPE_NOTICE_COOLDOWN_S:
        diagnostic["notice"] = "duplicate_missing_scope"
        diagnostic["cooldown_s"] = max(
            0,
            round(_MISSING_SCOPE_NOTICE_COOLDOWN_S - (now - last_notice), 3),
        )
    return json.dumps(
        {
            "status": "error",
            "channel": channel_name,
            "error_type": "missing_scope",
            "diagnostic": diagnostic,
        },
        ensure_ascii=False,
    )


def _json_result(payload: dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False)


def _response_data(channel: FeishuChannel, resp: Any, fallback: str) -> dict[str, Any]:
    try:
        data = resp.json()
    except ValueError:
        resp.raise_for_status()
        raise
    if isinstance(data, dict):
        channel._raise_api_error(data, fallback)
        resp.raise_for_status()
        return data
    resp.raise_for_status()
    return {"data": data}


async def _platform_json(
    channel: FeishuChannel,
    method: str,
    path: str,
    *,
    params: dict[str, Any] | None = None,
    json_body: dict[str, Any] | None = None,
) -> dict[str, Any]:
    await channel._rate_limiter.acquire()
    headers = await channel._auth_headers()
    client = channel._get_client()
    resp = await client.request(method, path, params=params, json=json_body, headers=headers)
    data = _response_data(channel, resp, f"{path} failed")
    payload = data.get("data", {})
    return payload if isinstance(payload, dict) else {"data": payload}


def _platform_error_payload_or_reraise(
    *,
    channel_name: str,
    channel: FeishuChannel,
    feature: str,
    exc: Exception,
) -> str:
    api_error = _coerce_feishu_api_error(exc)
    if api_error is None:
        raise exc
    return _error_payload(
        channel_name=channel_name,
        channel=channel,
        feature=feature,
        exc=api_error,
    )


def _artifact_target() -> tuple[str, str, str]:
    ctx = current_tool_context.get()
    if ctx is None:
        raise ToolError("feishu_media_upload_artifact requires tool context")
    if not ctx.artifact_media_root:
        raise ToolError("artifact storage is not configured for this turn")
    if not ctx.artifact_session_id:
        raise ToolError("artifact session scope is not configured for this turn")
    if not ctx.channel_id:
        raise ToolError("channel target is not available for this turn")
    return ctx.artifact_media_root, ctx.artifact_session_id, ctx.channel_id


def _artifact_session_scope(tool_name: str) -> tuple[str, str]:
    ctx = current_tool_context.get()
    if ctx is None:
        raise ToolError(f"{tool_name} requires tool context")
    if not ctx.artifact_media_root:
        raise ToolError("artifact storage is not configured for this turn")
    if not ctx.artifact_session_id:
        raise ToolError("artifact session scope is not configured for this turn")
    return ctx.artifact_media_root, ctx.artifact_session_id


def _reject_channel_override(kind: str, value: str | None) -> None:
    ctx = current_tool_context.get()
    if ctx is not None and not ctx.is_owner and value:
        raise ToolError(f"Feishu {kind} override is not allowed for channel callers")


@tool(
    name="feishu_doc_create",
    description="Create an empty Feishu Docx document. Use artifact upload for generated files.",
    params={
        "title": {"type": "string", "description": "Document title."},
        "folder_token": {
            "type": "string",
            "description": "Optional Drive folder token where the document should be created.",
        },
        "channel": {"type": "string", "description": "Optional configured Feishu channel name."},
    },
    required=["title"],
)
async def feishu_doc_create(
    title: str,
    folder_token: str | None = None,
    channel: str | None = None,
) -> str:
    _reject_channel_override("channel override", channel)
    channel_name, adapter = _channel(channel)
    body = {"title": title}
    if folder_token:
        body["folder_token"] = folder_token
    try:
        result = await _platform_json(
            adapter,
            "POST",
            "/docx/v1/documents",
            json_body=body,
        )
    except Exception as exc:
        return _platform_error_payload_or_reraise(
            channel_name=channel_name,
            channel=adapter,
            feature="doc_create",
            exc=exc,
        )
    return _json_result({"status": "ok", "channel": channel_name, **result})


@tool(
    name="feishu_doc_read_raw",
    description="Read raw text content for a Feishu Docx document by document_id.",
    params={
        "document_id": {"type": "string", "description": "Feishu Docx document_id."},
        "channel": {"type": "string", "description": "Optional configured Feishu channel name."},
    },
    required=["document_id"],
)
async def feishu_doc_read_raw(document_id: str, channel: str | None = None) -> str:
    _reject_channel_override("channel override", channel)
    channel_name, adapter = _channel(channel)
    try:
        result = await _platform_json(
            adapter,
            "GET",
            f"/docx/v1/documents/{document_id}/raw_content",
        )
    except Exception as exc:
        return _platform_error_payload_or_reraise(
            channel_name=channel_name,
            channel=adapter,
            feature="doc_read",
            exc=exc,
        )
    return _json_result({"status": "ok", "channel": channel_name, **result})


@tool(
    name="feishu_doc_list_blocks",
    description="List blocks for a Feishu Docx document.",
    params={
        "document_id": {"type": "string", "description": "Feishu Docx document_id."},
        "page_size": {"type": "integer", "description": "Maximum blocks to return."},
        "page_token": {"type": "string", "description": "Optional pagination token."},
        "channel": {"type": "string", "description": "Optional configured Feishu channel name."},
    },
    required=["document_id"],
)
async def feishu_doc_list_blocks(
    document_id: str,
    page_size: int = 20,
    page_token: str | None = None,
    channel: str | None = None,
) -> str:
    _reject_channel_override("channel override", channel)
    channel_name, adapter = _channel(channel)
    params: dict[str, Any] = {"page_size": page_size}
    if page_token:
        params["page_token"] = page_token
    try:
        result = await _platform_json(
            adapter,
            "GET",
            f"/docx/v1/documents/{document_id}/blocks",
            params=params,
        )
    except Exception as exc:
        return _platform_error_payload_or_reraise(
            channel_name=channel_name,
            channel=adapter,
            feature="doc_read",
            exc=exc,
        )
    return _json_result({"status": "ok", "channel": channel_name, **result})


@tool(
    name="feishu_scopes_status",
    description=(
        "Report Feishu feature scope requirements and grant guidance for chat, media, "
        "thread replies, and read/edit operations. Does not mutate permissions."
    ),
    params={
        "channel": {
            "type": "string",
            "description": "Optional configured Feishu channel name. Defaults to current channel.",
        }
    },
)
async def feishu_scopes_status(channel: str | None = None) -> str:
    channel_name, adapter = _channel(channel)
    return _json_result(
        {
            "status": "ok",
            "channel": channel_name,
            "grant_url": _grant_url(adapter),
            "features": {
                feature: {
                    "required_scopes": list(capability.required_scopes),
                    "state": "not_checked",
                    "category": capability.category,
                    "tools": list(capability.tools),
                    "mutates": capability.mutates,
                    "dry_run_supported": capability.dry_run_supported,
                    "default_channel_visible": capability.default_channel_visible,
                }
                for feature, capability in _FEATURE_CAPABILITIES.items()
            },
            "note": (
                "Feishu does not expose a side-effect-free app-scope introspection API here; "
                "OpenSquilla reports required scopes and normalizes missing-scope API errors."
            ),
        }
    )


@tool(
    name="feishu_chat_send",
    description="Send a text message through a configured Feishu channel.",
    params={
        "target": {"type": "string", "description": "Feishu chat_id or open_id."},
        "text": {"type": "string", "description": "Message text."},
        "channel": {"type": "string", "description": "Optional configured Feishu channel name."},
    },
    required=["target", "text"],
)
async def feishu_chat_send(target: str, text: str, channel: str | None = None) -> str:
    channel_name, adapter = _channel(channel)
    try:
        message_id = await adapter.send_text(target, text)
    except Exception as exc:
        api_error = _coerce_feishu_api_error(exc)
        if api_error is None:
            raise
        return _error_payload(
            channel_name=channel_name,
            channel=adapter,
            feature="chat_send",
            exc=api_error,
        )
    return _json_result({"status": "sent", "channel": channel_name, "message_id": message_id})


@tool(
    name="feishu_chat_reply",
    description="Reply to a Feishu message by message_id using the native reply endpoint.",
    params={
        "message_id": {"type": "string", "description": "Feishu message_id to reply to."},
        "text": {"type": "string", "description": "Reply text."},
        "channel": {"type": "string", "description": "Optional configured Feishu channel name."},
    },
    required=["message_id", "text"],
)
async def feishu_chat_reply(message_id: str, text: str, channel: str | None = None) -> str:
    channel_name, adapter = _channel(channel)
    try:
        reply_id = await adapter.reply_text(message_id, text)
    except Exception as exc:
        api_error = _coerce_feishu_api_error(exc)
        if api_error is None:
            raise
        return _error_payload(
            channel_name=channel_name,
            channel=adapter,
            feature="chat_reply",
            exc=api_error,
        )
    return _json_result(
        {
            "status": "sent",
            "channel": channel_name,
            "message_id": reply_id,
            "reply_to_message_id": message_id,
        }
    )


@tool(
    name="feishu_chat_read",
    description="Read one Feishu message by message_id.",
    params={
        "message_id": {"type": "string", "description": "Feishu message_id to read."},
        "channel": {"type": "string", "description": "Optional configured Feishu channel name."},
    },
    required=["message_id"],
)
async def feishu_chat_read(message_id: str, channel: str | None = None) -> str:
    channel_name, adapter = _channel(channel)
    try:
        message = await adapter.read_message(message_id)
    except Exception as exc:
        api_error = _coerce_feishu_api_error(exc)
        if api_error is None:
            raise
        return _error_payload(
            channel_name=channel_name,
            channel=adapter,
            feature="chat_read",
            exc=api_error,
        )
    return _json_result({"status": "ok", "channel": channel_name, "message": message})


@tool(
    name="feishu_chat_edit",
    description="Edit a Feishu text message by message_id.",
    params={
        "message_id": {"type": "string", "description": "Feishu message_id to edit."},
        "text": {"type": "string", "description": "Replacement text."},
        "channel": {"type": "string", "description": "Optional configured Feishu channel name."},
    },
    required=["message_id", "text"],
)
async def feishu_chat_edit(message_id: str, text: str, channel: str | None = None) -> str:
    channel_name, adapter = _channel(channel)
    try:
        await adapter.edit(message_id, text)
    except Exception as exc:
        api_error = _coerce_feishu_api_error(exc)
        if api_error is None:
            raise
        return _error_payload(
            channel_name=channel_name,
            channel=adapter,
            feature="chat_edit",
            exc=api_error,
        )
    return _json_result({"status": "edited", "channel": channel_name, "message_id": message_id})


@tool(
    name="feishu_drive_search",
    description="Search Feishu Drive files by keyword.",
    params={
        "query": {"type": "string", "description": "Drive search keyword."},
        "page_size": {"type": "integer", "description": "Maximum files to return."},
        "page_token": {"type": "string", "description": "Optional pagination token."},
        "channel": {"type": "string", "description": "Optional configured Feishu channel name."},
    },
    required=["query"],
)
async def feishu_drive_search(
    query: str,
    page_size: int = 20,
    page_token: str | None = None,
    channel: str | None = None,
) -> str:
    _reject_channel_override("channel override", channel)
    channel_name, adapter = _channel(channel)
    body: dict[str, Any] = {"search_key": query, "count": page_size}
    if page_token:
        body["page_token"] = page_token
    try:
        result = await _platform_json(
            adapter,
            "POST",
            "/suite/docs-api/search/object",
            json_body=body,
        )
    except Exception as exc:
        return _platform_error_payload_or_reraise(
            channel_name=channel_name,
            channel=adapter,
            feature="drive_search",
            exc=exc,
        )
    return _json_result({"status": "ok", "channel": channel_name, **result})


@tool(
    name="feishu_drive_meta",
    description="Fetch Feishu Drive metadata for one document/file token.",
    params={
        "doc_token": {"type": "string", "description": "Drive document/file token."},
        "doc_type": {"type": "string", "description": "Drive doc type, such as docx, sheet, file."},
        "with_url": {"type": "boolean", "description": "Whether to include URLs when available."},
        "channel": {"type": "string", "description": "Optional configured Feishu channel name."},
    },
    required=["doc_token"],
)
async def feishu_drive_meta(
    doc_token: str,
    doc_type: str = "docx",
    with_url: bool = True,
    channel: str | None = None,
) -> str:
    _reject_channel_override("channel override", channel)
    channel_name, adapter = _channel(channel)
    try:
        result = await _platform_json(
            adapter,
            "POST",
            "/suite/docs-api/meta",
            json_body={
                "request_docs": [{"docs_token": doc_token, "docs_type": doc_type}],
                "with_url": with_url,
            },
        )
    except Exception as exc:
        return _platform_error_payload_or_reraise(
            channel_name=channel_name,
            channel=adapter,
            feature="drive_meta",
            exc=exc,
        )
    return _json_result({"status": "ok", "channel": channel_name, **result})


@tool(
    name="feishu_drive_upload_artifact",
    description=(
        "Upload an already-published OpenSquilla artifact to Feishu Drive. "
        "Accepts artifact ids only, not local file paths."
    ),
    params={
        "artifact_id": {"type": "string", "description": "OpenSquilla artifact id."},
        "parent_node": {"type": "string", "description": "Destination Drive folder token."},
        "parent_type": {
            "type": "string",
            "description": "Drive parent type. Defaults to explorer.",
        },
        "session_id": {
            "type": "string",
            "description": "Optional artifact session id. Defaults to current turn session.",
        },
        "channel": {"type": "string", "description": "Optional configured Feishu channel name."},
    },
    required=["artifact_id", "parent_node"],
)
async def feishu_drive_upload_artifact(
    artifact_id: str,
    parent_node: str,
    parent_type: str = "explorer",
    session_id: str | None = None,
    channel: str | None = None,
) -> str:
    media_root, current_session_id = _artifact_session_scope("feishu_drive_upload_artifact")
    _reject_channel_override("session override", session_id)
    _reject_channel_override("channel override", channel)
    channel_name, adapter = _channel(channel)
    store = ArtifactStore(media_root)
    ref, path = store.resolve_for_download(
        artifact_id,
        session_id=session_id or current_session_id,
    )
    await adapter._rate_limiter.acquire()
    headers = await adapter._auth_headers()
    client = adapter._get_client()
    with TemporaryDirectory(prefix="opensquilla-feishu-drive-") as tmp_dir:
        upload_path = Path(tmp_dir) / ref.name
        upload_path.write_bytes(path.read_bytes())
        try:
            with open(upload_path, "rb") as f:
                resp = await client.post(
                    "/drive/v1/files/upload_all",
                    data={
                        "file_name": upload_path.name,
                        "parent_type": parent_type,
                        "parent_node": parent_node,
                        "size": str(upload_path.stat().st_size),
                    },
                    files={"file": f},
                    headers=headers,
                )
            data = _response_data(adapter, resp, "drive upload failed")
        except Exception as exc:
            return _platform_error_payload_or_reraise(
                channel_name=channel_name,
                channel=adapter,
                feature="drive_upload",
                exc=exc,
            )
    result = data.get("data", {})
    payload = result if isinstance(result, dict) else {"data": result}
    return _json_result({"status": "uploaded", "channel": channel_name, **payload})


@tool(
    name="feishu_wiki_list_spaces",
    description="List accessible Feishu Wiki spaces.",
    params={
        "page_size": {"type": "integer", "description": "Maximum spaces to return."},
        "page_token": {"type": "string", "description": "Optional pagination token."},
        "channel": {"type": "string", "description": "Optional configured Feishu channel name."},
    },
)
async def feishu_wiki_list_spaces(
    page_size: int = 20,
    page_token: str | None = None,
    channel: str | None = None,
) -> str:
    _reject_channel_override("channel override", channel)
    channel_name, adapter = _channel(channel)
    params: dict[str, Any] = {"page_size": page_size}
    if page_token:
        params["page_token"] = page_token
    try:
        result = await _platform_json(adapter, "GET", "/wiki/v2/spaces", params=params)
    except Exception as exc:
        return _platform_error_payload_or_reraise(
            channel_name=channel_name,
            channel=adapter,
            feature="wiki_read",
            exc=exc,
        )
    return _json_result({"status": "ok", "channel": channel_name, **result})


@tool(
    name="feishu_wiki_list_nodes",
    description="List Feishu Wiki nodes in a space.",
    params={
        "space_id": {"type": "string", "description": "Wiki space id."},
        "parent_node_token": {"type": "string", "description": "Optional parent node token."},
        "page_size": {"type": "integer", "description": "Maximum nodes to return."},
        "page_token": {"type": "string", "description": "Optional pagination token."},
        "channel": {"type": "string", "description": "Optional configured Feishu channel name."},
    },
    required=["space_id"],
)
async def feishu_wiki_list_nodes(
    space_id: str,
    parent_node_token: str | None = None,
    page_size: int = 20,
    page_token: str | None = None,
    channel: str | None = None,
) -> str:
    _reject_channel_override("channel override", channel)
    channel_name, adapter = _channel(channel)
    params: dict[str, Any] = {"page_size": page_size}
    if parent_node_token:
        params["parent_node_token"] = parent_node_token
    if page_token:
        params["page_token"] = page_token
    try:
        result = await _platform_json(
            adapter,
            "GET",
            f"/wiki/v2/spaces/{space_id}/nodes",
            params=params,
        )
    except Exception as exc:
        return _platform_error_payload_or_reraise(
            channel_name=channel_name,
            channel=adapter,
            feature="wiki_read",
            exc=exc,
        )
    return _json_result({"status": "ok", "channel": channel_name, **result})


@tool(
    name="feishu_wiki_get_node",
    description="Resolve one Feishu Wiki node by token.",
    params={
        "token": {"type": "string", "description": "Wiki node token."},
        "obj_type": {"type": "string", "description": "Optional node object type."},
        "channel": {"type": "string", "description": "Optional configured Feishu channel name."},
    },
    required=["token"],
)
async def feishu_wiki_get_node(
    token: str,
    obj_type: str | None = None,
    channel: str | None = None,
) -> str:
    _reject_channel_override("channel override", channel)
    channel_name, adapter = _channel(channel)
    params: dict[str, Any] = {"token": token}
    if obj_type:
        params["obj_type"] = obj_type
    try:
        result = await _platform_json(
            adapter,
            "GET",
            "/wiki/v2/spaces/get_node",
            params=params,
        )
    except Exception as exc:
        return _platform_error_payload_or_reraise(
            channel_name=channel_name,
            channel=adapter,
            feature="wiki_read",
            exc=exc,
        )
    return _json_result({"status": "ok", "channel": channel_name, **result})


@tool(
    name="feishu_perm_grant_member",
    description=(
        "Grant a Feishu Drive document collaborator permission. Defaults to dry-run; "
        "set dry_run=false only after the user confirms the exact target and member."
    ),
    params={
        "token": {"type": "string", "description": "Drive document/file/wiki token."},
        "doc_type": {
            "type": "string",
            "description": "Permission object type, such as doc, docx, sheet, file, wiki.",
        },
        "member_type": {
            "type": "string",
            "description": "Member id type, such as openid, userid, email, openchat.",
        },
        "member_id": {"type": "string", "description": "Member id matching member_type."},
        "perm": {"type": "string", "description": "Permission: view, edit, or full_access."},
        "need_notification": {
            "type": "boolean",
            "description": "Whether Feishu should notify the member.",
        },
        "dry_run": {
            "type": "boolean",
            "description": "When true, return the permission plan without calling Feishu.",
        },
        "channel": {"type": "string", "description": "Optional configured Feishu channel name."},
    },
    required=["token", "doc_type", "member_type", "member_id", "perm"],
)
async def feishu_perm_grant_member(
    token: str,
    doc_type: str,
    member_type: str,
    member_id: str,
    perm: str,
    need_notification: bool = False,
    dry_run: bool = True,
    channel: str | None = None,
) -> str:
    _reject_channel_override("channel override", channel)
    normalized_perm = perm.strip()
    if normalized_perm not in _VALID_PERMISSION_LEVELS:
        allowed = ", ".join(sorted(_VALID_PERMISSION_LEVELS))
        raise ToolError(f"unsupported Feishu permission: {perm}. Expected one of: {allowed}")

    channel_name, adapter = _channel(channel)
    path = f"/drive/v1/permissions/{token}/members"
    params = {"type": doc_type, "need_notification": str(bool(need_notification)).lower()}
    body = {"member_type": member_type, "member_id": member_id, "perm": normalized_perm}
    plan = {
        "path": path,
        "method": "POST",
        "params": params,
        "body": body,
    }
    log.info(
        "feishu.permission_grant_planned",
        channel=channel_name,
        token=token,
        doc_type=doc_type,
        member_type=member_type,
        member_id=member_id,
        perm=normalized_perm,
        dry_run=dry_run,
    )
    if dry_run:
        return _json_result(
            {
                "status": "dry_run",
                "channel": channel_name,
                "operation": "grant_member",
                "plan": plan,
            }
        )

    try:
        result = await _platform_json(
            adapter,
            "POST",
            path,
            params=params,
            json_body=body,
        )
    except Exception as exc:
        return _platform_error_payload_or_reraise(
            channel_name=channel_name,
            channel=adapter,
            feature="perm_member",
            exc=exc,
        )
    log.info(
        "feishu.permission_grant_applied",
        channel=channel_name,
        token=token,
        doc_type=doc_type,
        member_type=member_type,
        member_id=member_id,
        perm=normalized_perm,
    )
    return _json_result({"status": "granted", "channel": channel_name, **result})


@tool(
    name="feishu_media_upload_artifact",
    description=(
        "Upload an already-published OpenSquilla artifact to the current Feishu chat. "
        "Accepts artifact ids only, not local file paths."
    ),
    params={
        "artifact_id": {"type": "string", "description": "OpenSquilla artifact id."},
        "session_id": {
            "type": "string",
            "description": "Optional artifact session id. Defaults to current turn session.",
        },
        "target": {
            "type": "string",
            "description": "Optional Feishu chat_id/open_id. Defaults to current channel target.",
        },
        "channel": {"type": "string", "description": "Optional configured Feishu channel name."},
    },
    required=["artifact_id"],
)
async def feishu_media_upload_artifact(
    artifact_id: str,
    session_id: str | None = None,
    target: str | None = None,
    channel: str | None = None,
) -> str:
    media_root, current_session_id, current_target = _artifact_target()
    _reject_channel_override("session override", session_id)
    _reject_channel_override("target override", target)
    _reject_channel_override("channel override", channel)
    channel_name, adapter = _channel(channel)
    store = ArtifactStore(media_root)
    ref, path = store.resolve_for_download(
        artifact_id,
        session_id=session_id or current_session_id,
    )
    with TemporaryDirectory(prefix="opensquilla-feishu-artifact-") as tmp_dir:
        delivery_path = Path(tmp_dir) / ref.name
        delivery_path.write_bytes(path.read_bytes())
        try:
            result = await adapter.send_file(target or current_target, str(delivery_path))
        except Exception as exc:
            api_error = _coerce_feishu_api_error(exc)
            if api_error is None:
                raise
            return _error_payload(
                channel_name=channel_name,
                channel=adapter,
                feature="media_upload",
                exc=api_error,
            )
    send_result = cast(ChannelSendResult, result)
    return _json_result(
        {
            "status": send_result.status.value,
            "channel": channel_name,
            "target_id": send_result.target_id,
            "provider_message_id": send_result.provider_message_id,
            "provider_file_id": send_result.provider_file_id,
        }
    )
