from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from opensquilla.artifacts import ArtifactStore
from opensquilla.channels.feishu import FeishuChannel, FeishuChannelConfig, _TokenState
from opensquilla.tools.policy import apply_tool_policy_from_config
from opensquilla.tools.registry import (
    ToolProfile,
    filter_by_profile,
    get_default_registry,
    profile_allows_tool,
    resolve_profile,
)
from opensquilla.tools.types import CallerKind, ToolContext, current_tool_context


def _channel() -> FeishuChannel:
    channel = FeishuChannel(
        FeishuChannelConfig(app_id="app", app_secret="secret", connection_mode="webhook")
    )
    channel._token_state = _TokenState(token="tenant-token", expires_at=999999999.0)
    return channel


def _channel_tool_context(tmp_path: Path) -> ToolContext:
    return ToolContext(
        is_owner=False,
        caller_kind=CallerKind.CHANNEL,
        source_name="feishu-main",
        channel_kind="feishu-main",
        channel_id="oc_group",
        sender_id="ou_sender",
        artifact_media_root=str(tmp_path / "media"),
        artifact_session_id="session-1",
        session_key="agent:main:feishu-main:group:oc_group",
    )


def _registered_channel_context(tmp_path: Path) -> ToolContext:
    return _channel_tool_context(tmp_path)


@pytest.mark.asyncio
async def test_feishu_chat_reply_uses_native_reply_endpoint() -> None:
    import opensquilla.tools.builtin.feishu_platform as feishu_platform

    requests: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        body = await request.aread()
        if request.url.path == "/open-apis/im/v1/messages/om_parent/reply":
            payload = json.loads(body)
            assert payload["msg_type"] == "text"
            assert json.loads(payload["content"]) == {"text": "native reply"}
            return httpx.Response(200, json={"code": 0, "data": {"message_id": "om_reply"}})
        raise AssertionError(f"unexpected request: {request.method} {request.url}")

    channel = _channel()
    channel._client = httpx.AsyncClient(
        base_url="https://open.feishu.cn/open-apis",
        transport=httpx.MockTransport(handler),
    )
    feishu_platform.register_feishu_channel("feishu-main", channel)

    try:
        result = json.loads(
            await feishu_platform.feishu_chat_reply(
                message_id="om_parent",
                text="native reply",
                channel="feishu-main",
            )
        )
    finally:
        await channel.stop()
        feishu_platform.clear_feishu_channels()

    assert result == {
        "status": "sent",
        "channel": "feishu-main",
        "message_id": "om_reply",
        "reply_to_message_id": "om_parent",
    }
    assert [request.url.path for request in requests] == [
        "/open-apis/im/v1/messages/om_parent/reply"
    ]


@pytest.mark.asyncio
async def test_feishu_thread_inbound_reply_uses_native_reply_endpoint() -> None:
    from opensquilla.channels.types import OutgoingMessage

    requests: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        body = await request.aread()
        if request.url.path == "/open-apis/im/v1/messages/om_topic/reply":
            payload = json.loads(body)
            assert payload["msg_type"] == "text"
            assert json.loads(payload["content"]) == {"text": "thread reply"}
            return httpx.Response(200, json={"code": 0, "data": {"message_id": "om_reply"}})
        raise AssertionError(f"unexpected request: {request.method} {request.url}")

    channel = _channel()
    channel._client = httpx.AsyncClient(
        base_url="https://open.feishu.cn/open-apis",
        transport=httpx.MockTransport(handler),
    )
    inbound = channel.parse_event(
        {
            "header": {"event_id": "evt-thread", "event_type": "im.message.receive_v1"},
            "event": {
                "sender": {"sender_id": {"open_id": "ou_user"}},
                "message": {
                    "message_id": "om_topic",
                    "chat_id": "oc_topic",
                    "chat_type": "topic_group",
                    "thread_id": "omt_topic",
                    "message_type": "text",
                    "content": json.dumps({"text": "question"}),
                },
            },
        }
    )
    reply = channel.build_reply_message("thread reply", inbound)

    try:
        assert isinstance(reply, OutgoingMessage)
        assert reply.metadata["reply_message_id"] == "om_topic"
        assert reply.metadata["native_thread_id"] == "omt_topic"
        await channel.send(reply)
    finally:
        await channel.stop()

    assert [request.url.path for request in requests] == [
        "/open-apis/im/v1/messages/om_topic/reply"
    ]


@pytest.mark.asyncio
async def test_feishu_chat_send_read_and_edit_call_im_endpoints() -> None:
    import opensquilla.tools.builtin.feishu_platform as feishu_platform

    seen: list[tuple[str, str]] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        body = await request.aread()
        seen.append((request.method, request.url.path))
        if request.method == "POST" and request.url.path == "/open-apis/im/v1/messages":
            assert request.url.params["receive_id_type"] == "chat_id"
            payload = json.loads(body)
            assert payload["receive_id"] == "oc_group"
            assert payload["msg_type"] == "text"
            assert json.loads(payload["content"]) == {"text": "hello"}
            return httpx.Response(200, json={"code": 0, "data": {"message_id": "om_sent"}})
        if request.method == "GET" and request.url.path == "/open-apis/im/v1/messages/om_read":
            return httpx.Response(
                200,
                json={"code": 0, "data": {"items": [{"message_id": "om_read"}]}},
            )
        if request.method == "PUT" and request.url.path == "/open-apis/im/v1/messages/om_edit":
            payload = json.loads(body)
            assert payload["msg_type"] == "text"
            assert json.loads(payload["content"]) == {"text": "updated"}
            return httpx.Response(200, json={"code": 0})
        raise AssertionError(f"unexpected request: {request.method} {request.url}")

    channel = _channel()
    channel._client = httpx.AsyncClient(
        base_url="https://open.feishu.cn/open-apis",
        transport=httpx.MockTransport(handler),
    )
    feishu_platform.register_feishu_channel("feishu-main", channel)

    try:
        sent = json.loads(
            await feishu_platform.feishu_chat_send(
                target="oc_group",
                text="hello",
                channel="feishu-main",
            )
        )
        read = json.loads(
            await feishu_platform.feishu_chat_read(
                message_id="om_read",
                channel="feishu-main",
            )
        )
        edited = json.loads(
            await feishu_platform.feishu_chat_edit(
                message_id="om_edit",
                text="updated",
                channel="feishu-main",
            )
        )
    finally:
        await channel.stop()
        feishu_platform.clear_feishu_channels()

    assert sent["message_id"] == "om_sent"
    assert read["message"]["items"] == [{"message_id": "om_read"}]
    assert edited == {"status": "edited", "channel": "feishu-main", "message_id": "om_edit"}
    assert seen == [
        ("POST", "/open-apis/im/v1/messages"),
        ("GET", "/open-apis/im/v1/messages/om_read"),
        ("PUT", "/open-apis/im/v1/messages/om_edit"),
    ]


@pytest.mark.asyncio
async def test_feishu_doc_wiki_drive_tools_call_platform_endpoints() -> None:
    import opensquilla.tools.builtin.feishu_platform as feishu_platform

    seen: list[tuple[str, str]] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, request.url.path))
        body = await request.aread()
        if request.method == "POST" and request.url.path == "/open-apis/docx/v1/documents":
            payload = json.loads(body)
            assert payload == {"title": "Launch Notes"}
            return httpx.Response(
                200,
                json={"code": 0, "data": {"document": {"document_id": "doc_token"}}},
            )
        if request.method == "GET" and request.url.path == (
            "/open-apis/docx/v1/documents/doc_token/raw_content"
        ):
            return httpx.Response(
                200,
                json={"code": 0, "data": {"content": "# Launch Notes"}},
            )
        if request.method == "POST" and request.url.path == (
            "/open-apis/suite/docs-api/search/object"
        ):
            payload = json.loads(body)
            assert payload["search_key"] == "Launch"
            return httpx.Response(
                200,
                json={"code": 0, "data": {"files": [{"token": "doc_token"}]}},
            )
        if request.method == "POST" and request.url.path == "/open-apis/suite/docs-api/meta":
            payload = json.loads(body)
            assert payload["request_docs"] == [{"docs_token": "doc_token", "docs_type": "docx"}]
            return httpx.Response(
                200,
                json={"code": 0, "data": {"metas": [{"doc_token": "doc_token"}]}},
            )
        if request.method == "GET" and request.url.path == "/open-apis/wiki/v2/spaces":
            return httpx.Response(
                200,
                json={"code": 0, "data": {"items": [{"space_id": "spc"}]}},
            )
        if request.method == "GET" and request.url.path == "/open-apis/wiki/v2/spaces/spc/nodes":
            assert request.url.params["parent_node_token"] == "parent"
            return httpx.Response(
                200,
                json={"code": 0, "data": {"items": [{"node_token": "node"}]}},
            )
        if request.method == "GET" and request.url.path == "/open-apis/wiki/v2/spaces/get_node":
            assert request.url.params["token"] == "node"
            return httpx.Response(
                200,
                json={"code": 0, "data": {"node": {"node_token": "node"}}},
            )
        raise AssertionError(f"unexpected request: {request.method} {request.url}")

    channel = _channel()
    channel._client = httpx.AsyncClient(
        base_url="https://open.feishu.cn/open-apis",
        transport=httpx.MockTransport(handler),
    )
    feishu_platform.register_feishu_channel("feishu-main", channel)

    try:
        created = json.loads(
            await feishu_platform.feishu_doc_create(title="Launch Notes", channel="feishu-main")
        )
        raw = json.loads(
            await feishu_platform.feishu_doc_read_raw(
                document_id="doc_token",
                channel="feishu-main",
            )
        )
        search = json.loads(
            await feishu_platform.feishu_drive_search(query="Launch", channel="feishu-main")
        )
        meta = json.loads(
            await feishu_platform.feishu_drive_meta(
                doc_token="doc_token",
                doc_type="docx",
                channel="feishu-main",
            )
        )
        spaces = json.loads(await feishu_platform.feishu_wiki_list_spaces(channel="feishu-main"))
        nodes = json.loads(
            await feishu_platform.feishu_wiki_list_nodes(
                space_id="spc",
                parent_node_token="parent",
                channel="feishu-main",
            )
        )
        node = json.loads(
            await feishu_platform.feishu_wiki_get_node(
                token="node",
                channel="feishu-main",
            )
        )
    finally:
        await channel.stop()
        feishu_platform.clear_feishu_channels()

    assert created["document"]["document_id"] == "doc_token"
    assert raw["content"] == "# Launch Notes"
    assert search["files"] == [{"token": "doc_token"}]
    assert meta["metas"] == [{"doc_token": "doc_token"}]
    assert spaces["items"] == [{"space_id": "spc"}]
    assert nodes["items"] == [{"node_token": "node"}]
    assert node["node"] == {"node_token": "node"}
    assert seen == [
        ("POST", "/open-apis/docx/v1/documents"),
        ("GET", "/open-apis/docx/v1/documents/doc_token/raw_content"),
        ("POST", "/open-apis/suite/docs-api/search/object"),
        ("POST", "/open-apis/suite/docs-api/meta"),
        ("GET", "/open-apis/wiki/v2/spaces"),
        ("GET", "/open-apis/wiki/v2/spaces/spc/nodes"),
        ("GET", "/open-apis/wiki/v2/spaces/get_node"),
    ]


@pytest.mark.asyncio
async def test_feishu_media_upload_artifact_is_artifact_bound(tmp_path: Path) -> None:
    import opensquilla.tools.builtin.feishu_platform as feishu_platform

    ctx = _channel_tool_context(tmp_path)
    store = ArtifactStore(ctx.artifact_media_root or "")
    source = tmp_path / "report.pdf"
    source.write_bytes(b"%PDF-1.4\n")
    ref = store.publish_file(
        source,
        session_id=ctx.artifact_session_id or "",
        session_key=ctx.session_key or "",
        name="report.pdf",
        mime="application/pdf",
        source="test",
    )
    requests: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        body = await request.aread()
        if request.url.path == "/open-apis/im/v1/files":
            assert b'file_type"\r\n\r\npdf' in body
            assert b"report.pdf" in body
            return httpx.Response(200, json={"code": 0, "data": {"file_key": "file-key"}})
        if request.url.path == "/open-apis/im/v1/messages":
            payload = json.loads(body)
            assert payload["receive_id"] == "oc_group"
            assert payload["msg_type"] == "file"
            assert json.loads(payload["content"]) == {"file_key": "file-key"}
            return httpx.Response(200, json={"code": 0, "data": {"message_id": "om_file"}})
        raise AssertionError(f"unexpected request: {request.method} {request.url}")

    channel = _channel()
    channel._client = httpx.AsyncClient(
        base_url="https://open.feishu.cn/open-apis",
        transport=httpx.MockTransport(handler),
    )
    feishu_platform.register_feishu_channel("feishu-main", channel)
    token = current_tool_context.set(ctx)

    try:
        result = json.loads(
            await feishu_platform.feishu_media_upload_artifact(
                artifact_id=ref.id,
            )
        )
    finally:
        current_tool_context.reset(token)
        await channel.stop()
        feishu_platform.clear_feishu_channels()

    assert result["status"] == "sent"
    assert result["target_id"] == "oc_group"
    assert result["provider_file_id"] == "file-key"
    assert [request.url.path for request in requests] == [
        "/open-apis/im/v1/files",
        "/open-apis/im/v1/messages",
    ]


@pytest.mark.asyncio
async def test_feishu_drive_upload_artifact_is_artifact_bound(tmp_path: Path) -> None:
    import opensquilla.tools.builtin.feishu_platform as feishu_platform

    ctx = _channel_tool_context(tmp_path)
    store = ArtifactStore(ctx.artifact_media_root or "")
    source = tmp_path / "report.xlsx"
    source.write_bytes(b"xlsx bytes")
    ref = store.publish_file(
        source,
        session_id=ctx.artifact_session_id or "",
        session_key=ctx.session_key or "",
        name="report.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        source="test",
    )
    requests: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        body = await request.aread()
        if request.url.path == "/open-apis/drive/v1/files/upload_all":
            assert b'report.xlsx' in body
            assert b'parent_type"\r\n\r\nexplorer' in body
            assert b'parent_node"\r\n\r\nfld_token' in body
            return httpx.Response(
                200,
                json={"code": 0, "data": {"file_token": "file_token"}},
            )
        raise AssertionError(f"unexpected request: {request.method} {request.url}")

    channel = _channel()
    channel._client = httpx.AsyncClient(
        base_url="https://open.feishu.cn/open-apis",
        transport=httpx.MockTransport(handler),
    )
    feishu_platform.register_feishu_channel("feishu-main", channel)
    token = current_tool_context.set(ctx)

    try:
        result = json.loads(
            await feishu_platform.feishu_drive_upload_artifact(
                artifact_id=ref.id,
                parent_node="fld_token",
            )
        )
    finally:
        current_tool_context.reset(token)
        await channel.stop()
        feishu_platform.clear_feishu_channels()

    assert result["status"] == "uploaded"
    assert result["file_token"] == "file_token"
    assert [request.url.path for request in requests] == ["/open-apis/drive/v1/files/upload_all"]


@pytest.mark.asyncio
async def test_feishu_drive_upload_missing_scope_returns_diagnostic(tmp_path: Path) -> None:
    import opensquilla.tools.builtin.feishu_platform as feishu_platform

    ctx = _channel_tool_context(tmp_path)
    store = ArtifactStore(ctx.artifact_media_root or "")
    source = tmp_path / "report.xlsx"
    source.write_bytes(b"xlsx bytes")
    ref = store.publish_file(
        source,
        session_id=ctx.artifact_session_id or "",
        session_key=ctx.session_key or "",
        name="report.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        source="test",
    )

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/open-apis/drive/v1/files/upload_all":
            return httpx.Response(
                400,
                json={
                    "code": 99991672,
                    "msg": (
                        "Access denied. One of the following scopes is required: "
                        "[drive:drive, drive:file, drive:file:upload]."
                    ),
                    "error": {
                        "permission_violations": [
                            {"type": "action_scope_required", "subject": "drive:drive"},
                            {"type": "action_scope_required", "subject": "drive:file"},
                            {"type": "action_scope_required", "subject": "drive:file:upload"},
                        ]
                    },
                },
            )
        raise AssertionError(f"unexpected request: {request.method} {request.url}")

    channel = _channel()
    channel._client = httpx.AsyncClient(
        base_url="https://open.feishu.cn/open-apis",
        transport=httpx.MockTransport(handler),
    )
    feishu_platform.register_feishu_channel("feishu-main", channel)
    token = current_tool_context.set(ctx)

    try:
        result = json.loads(
            await feishu_platform.feishu_drive_upload_artifact(
                artifact_id=ref.id,
                parent_node="fld_token",
            )
        )
    finally:
        current_tool_context.reset(token)
        await channel.stop()
        feishu_platform.clear_feishu_channels()

    assert result["status"] == "error"
    assert result["error_type"] == "missing_scope"
    assert result["diagnostic"]["feature"] == "drive_upload"
    assert result["diagnostic"]["required_scopes"] == [
        "drive:drive",
        "drive:file",
        "drive:file:upload",
    ]


@pytest.mark.asyncio
async def test_feishu_media_upload_rejects_channel_target_override(tmp_path: Path) -> None:
    import opensquilla.tools.builtin.feishu_platform as feishu_platform

    ctx = _registered_channel_context(tmp_path)
    store = ArtifactStore(ctx.artifact_media_root or "")
    source = tmp_path / "report.pdf"
    source.write_bytes(b"%PDF-1.4\n")
    ref = store.publish_file(
        source,
        session_id=ctx.artifact_session_id or "",
        session_key=ctx.session_key or "",
        name="report.pdf",
        mime="application/pdf",
        source="test",
    )
    feishu_platform.register_feishu_channel("feishu-main", _channel())
    token = current_tool_context.set(ctx)

    try:
        with pytest.raises(Exception, match="target override"):
            await feishu_platform.feishu_media_upload_artifact(
                artifact_id=ref.id,
                target="oc_other",
            )
    finally:
        current_tool_context.reset(token)
        feishu_platform.clear_feishu_channels()


@pytest.mark.asyncio
async def test_feishu_media_upload_rejects_channel_session_override(tmp_path: Path) -> None:
    import opensquilla.tools.builtin.feishu_platform as feishu_platform

    ctx = _registered_channel_context(tmp_path)
    store = ArtifactStore(ctx.artifact_media_root or "")
    source = tmp_path / "report.pdf"
    source.write_bytes(b"%PDF-1.4\n")
    ref = store.publish_file(
        source,
        session_id="other-session",
        session_key="agent:main:feishu-main:group:other",
        name="report.pdf",
        mime="application/pdf",
        source="test",
    )
    feishu_platform.register_feishu_channel("feishu-main", _channel())
    token = current_tool_context.set(ctx)

    try:
        with pytest.raises(Exception, match="session override"):
            await feishu_platform.feishu_media_upload_artifact(
                artifact_id=ref.id,
                session_id="other-session",
            )
    finally:
        current_tool_context.reset(token)
        feishu_platform.clear_feishu_channels()


@pytest.mark.asyncio
async def test_feishu_media_upload_rejects_channel_adapter_override(tmp_path: Path) -> None:
    import opensquilla.tools.builtin.feishu_platform as feishu_platform

    ctx = _registered_channel_context(tmp_path)
    store = ArtifactStore(ctx.artifact_media_root or "")
    source = tmp_path / "report.pdf"
    source.write_bytes(b"%PDF-1.4\n")
    ref = store.publish_file(
        source,
        session_id=ctx.artifact_session_id or "",
        session_key=ctx.session_key or "",
        name="report.pdf",
        mime="application/pdf",
        source="test",
    )
    feishu_platform.register_feishu_channel("feishu-main", _channel())
    feishu_platform.register_feishu_channel("feishu-other", _channel())
    token = current_tool_context.set(ctx)

    try:
        with pytest.raises(Exception, match="channel override"):
            await feishu_platform.feishu_media_upload_artifact(
                artifact_id=ref.id,
                channel="feishu-other",
            )
    finally:
        current_tool_context.reset(token)
        feishu_platform.clear_feishu_channels()


@pytest.mark.asyncio
async def test_feishu_drive_upload_rejects_channel_session_override(tmp_path: Path) -> None:
    import opensquilla.tools.builtin.feishu_platform as feishu_platform

    ctx = _registered_channel_context(tmp_path)
    store = ArtifactStore(ctx.artifact_media_root or "")
    source = tmp_path / "report.xlsx"
    source.write_bytes(b"xlsx bytes")
    ref = store.publish_file(
        source,
        session_id="other-session",
        session_key="agent:main:feishu-main:group:other",
        name="report.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        source="test",
    )
    feishu_platform.register_feishu_channel("feishu-main", _channel())
    token = current_tool_context.set(ctx)

    try:
        with pytest.raises(Exception, match="session override"):
            await feishu_platform.feishu_drive_upload_artifact(
                artifact_id=ref.id,
                session_id="other-session",
                parent_node="fld_token",
            )
    finally:
        current_tool_context.reset(token)
        feishu_platform.clear_feishu_channels()


@pytest.mark.asyncio
async def test_feishu_missing_scope_error_returns_stable_diagnostic() -> None:
    import opensquilla.tools.builtin.feishu_platform as feishu_platform

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/open-apis/im/v1/messages/om_parent/reply":
            return httpx.Response(
                200,
                json={
                    "code": 99991663,
                    "msg": "No permissions. Required scopes: im:message:send_as_bot",
                },
            )
        raise AssertionError(f"unexpected request: {request.method} {request.url}")

    channel = _channel()
    channel._client = httpx.AsyncClient(
        base_url="https://open.feishu.cn/open-apis",
        transport=httpx.MockTransport(handler),
    )
    feishu_platform.register_feishu_channel("feishu-main", channel)

    try:
        result = json.loads(
            await feishu_platform.feishu_chat_reply(
                message_id="om_parent",
                text="reply",
                channel="feishu-main",
            )
        )
    finally:
        await channel.stop()
        feishu_platform.clear_feishu_channels()

    assert result["status"] == "error"
    assert result["error_type"] == "missing_scope"
    assert result["diagnostic"]["feature"] == "chat_reply"
    assert result["diagnostic"]["required_scopes"] == ["im:message:send_as_bot"]
    assert "open.feishu.cn" in result["diagnostic"]["grant_url"]


@pytest.mark.asyncio
async def test_feishu_http_missing_scope_error_returns_stable_diagnostic() -> None:
    import opensquilla.tools.builtin.feishu_platform as feishu_platform

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/open-apis/wiki/v2/spaces":
            return httpx.Response(
                400,
                json={
                    "code": 99991672,
                    "msg": (
                        "Access denied. One of the following scopes is required: "
                        "[wiki:wiki:readonly]."
                    ),
                    "error": {
                        "permission_violations": [
                            {
                                "type": "action_scope_required",
                                "subject": "wiki:wiki:readonly",
                            }
                        ]
                    },
                },
            )
        raise AssertionError(f"unexpected request: {request.method} {request.url}")

    channel = _channel()
    channel._client = httpx.AsyncClient(
        base_url="https://open.feishu.cn/open-apis",
        transport=httpx.MockTransport(handler),
    )
    feishu_platform.register_feishu_channel("feishu-main", channel)

    try:
        result = json.loads(await feishu_platform.feishu_wiki_list_spaces(channel="feishu-main"))
    finally:
        await channel.stop()
        feishu_platform.clear_feishu_channels()

    assert result["status"] == "error"
    assert result["error_type"] == "missing_scope"
    assert result["diagnostic"]["feature"] == "wiki_read"
    assert result["diagnostic"]["required_scopes"] == ["wiki:wiki:readonly"]


@pytest.mark.asyncio
async def test_feishu_missing_scope_error_marks_duplicate_notice_with_cooldown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import opensquilla.tools.builtin.feishu_platform as feishu_platform

    calls: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if request.url.path == "/open-apis/im/v1/messages/om_parent/reply":
            return httpx.Response(
                200,
                json={
                    "code": 99991663,
                    "msg": "No permissions. Required scopes: im:message:send_as_bot",
                },
            )
        raise AssertionError(f"unexpected request: {request.method} {request.url}")

    ticks = iter([10.0, 11.0, 400.0])
    monkeypatch.setattr(feishu_platform, "_monotonic", lambda: next(ticks))

    channel = _channel()
    channel._client = httpx.AsyncClient(
        base_url="https://open.feishu.cn/open-apis",
        transport=httpx.MockTransport(handler),
    )
    feishu_platform.clear_feishu_scope_notice_cache()
    feishu_platform.register_feishu_channel("feishu-main", channel)

    try:
        first = json.loads(
            await feishu_platform.feishu_chat_reply(
                message_id="om_parent",
                text="reply",
                channel="feishu-main",
            )
        )
        second = json.loads(
            await feishu_platform.feishu_chat_reply(
                message_id="om_parent",
                text="reply",
                channel="feishu-main",
            )
        )
        third = json.loads(
            await feishu_platform.feishu_chat_reply(
                message_id="om_parent",
                text="reply",
                channel="feishu-main",
            )
        )
    finally:
        await channel.stop()
        feishu_platform.clear_feishu_channels()
        feishu_platform.clear_feishu_scope_notice_cache()

    assert len(calls) == 3
    assert "notice" not in first["diagnostic"]
    assert second["diagnostic"]["notice"] == "duplicate_missing_scope"
    assert second["diagnostic"]["cooldown_s"] > 0
    assert "notice" not in third["diagnostic"]


@pytest.mark.asyncio
async def test_channel_manager_reregisters_feishu_platform_tools_on_restart(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import opensquilla.channels.manager as manager_mod
    import opensquilla.tools.builtin.feishu_platform as feishu_platform

    channel = _channel()
    entry = SimpleNamespace(
        enabled=True,
        name="feishu-main",
        type="feishu",
        agent_id="main",
        debounce_window_s=0.0,
    )
    monkeypatch.setattr(manager_mod, "build_managed_channel", lambda _entry: channel)
    monkeypatch.setattr(
        channel,
        "start",
        lambda: manager_mod.asyncio.sleep(0),
    )
    feishu_platform.clear_feishu_channels()
    manager = manager_mod.ChannelManager.from_config(
        [entry],
        turn_runner=None,
        session_manager=None,
    )

    try:
        await manager.restart_channel("feishu-main")
        result = json.loads(await feishu_platform.feishu_scopes_status(channel="feishu-main"))
    finally:
        await manager.stop_channel("feishu-main")
        await channel.stop()
        feishu_platform.clear_feishu_channels()

    assert result["status"] == "ok"


@pytest.mark.asyncio
async def test_channel_manager_stop_all_unregisters_channels_without_tasks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import opensquilla.channels.manager as manager_mod
    import opensquilla.tools.builtin.feishu_platform as feishu_platform

    channel = _channel()
    entry = SimpleNamespace(
        enabled=True,
        name="feishu-main",
        type="feishu",
        agent_id="main",
        debounce_window_s=0.0,
    )
    monkeypatch.setattr(manager_mod, "build_managed_channel", lambda _entry: channel)
    feishu_platform.clear_feishu_channels()
    manager = manager_mod.ChannelManager.from_config(
        [entry],
        turn_runner=None,
        session_manager=None,
    )

    try:
        await manager.stop_all()
        with pytest.raises(Exception, match="unknown Feishu channel"):
            await feishu_platform.feishu_scopes_status(channel="feishu-main")
    finally:
        await channel.stop()
        feishu_platform.clear_feishu_channels()


def test_feishu_scopes_status_is_channel_default_visible() -> None:
    import opensquilla.tools.builtin  # noqa: F401

    registry = get_default_registry()
    channel_ctx = ToolContext(is_owner=False, caller_kind=CallerKind.CHANNEL)

    names = {
        tool.name
        for tool in filter_by_profile(
            registry.to_tool_definitions(channel_ctx),
            resolve_profile(channel_ctx),
            channel_ctx,
        )
    }

    assert "feishu_scopes_status" in names
    assert "feishu_doc_create" in names
    assert "feishu_doc_read_raw" in names
    assert "feishu_doc_list_blocks" in names
    assert "feishu_drive_meta" in names
    assert "feishu_drive_search" in names
    assert "feishu_drive_upload_artifact" in names
    assert "feishu_wiki_get_node" in names
    assert "feishu_wiki_list_nodes" in names
    assert "feishu_wiki_list_spaces" in names
    assert "feishu_perm_grant" not in names
    assert "feishu_perm_grant_member" not in names
    assert "write_file" not in names
    assert "execute_code" not in names
    assert "apply_patch" not in names


def test_feishu_capability_manifest_matches_channel_default_visibility() -> None:
    import opensquilla.tools.builtin.feishu_platform as feishu_platform

    for feature, capability in feishu_platform._FEATURE_CAPABILITIES.items():
        for tool_name in capability.tools:
            assert (
                profile_allows_tool(tool_name, ToolProfile.CHANNEL_DEFAULT)
                is capability.default_channel_visible
            ), f"{feature}:{tool_name}"


def test_channel_scopes_policy_expands_feishu_diagnostics() -> None:
    import opensquilla.tools.builtin  # noqa: F401

    registry = get_default_registry()
    config = {
        "channels": {
            "feishu": {
                "groups": {
                    "*": {
                        "tools": {
                            "profile": "minimal",
                            "also_allow": ["channel:scopes"],
                        }
                    }
                }
            }
        }
    }

    ctx = apply_tool_policy_from_config(
        ToolContext(is_owner=False, caller_kind=CallerKind.CHANNEL, channel_kind="feishu"),
        available_tools=registry.list_names(),
        config=config,
    )

    assert "feishu_scopes_status" in (ctx.allowed_tools or set())


def test_channel_chat_policy_does_not_grant_privileged_feishu_platform_tools() -> None:
    import opensquilla.tools.builtin  # noqa: F401

    registry = get_default_registry()
    config = {
        "channels": {
            "feishu": {
                "groups": {
                    "*": {
                        "tools": {
                            "profile": "minimal",
                            "also_allow": ["channel:chat"],
                        }
                    }
                }
            }
        }
    }

    ctx = apply_tool_policy_from_config(
        ToolContext(is_owner=False, caller_kind=CallerKind.CHANNEL, channel_kind="feishu"),
        available_tools=registry.list_names(),
        config=config,
    )

    assert "feishu_chat_reply" not in (ctx.allowed_tools or set())
    assert "feishu_chat_send" not in (ctx.allowed_tools or set())
    assert "feishu_chat_read" not in (ctx.allowed_tools or set())
    assert "feishu_chat_edit" not in (ctx.allowed_tools or set())


def test_channel_doc_wiki_drive_policy_grants_platform_safe_tools_only() -> None:
    import opensquilla.tools.builtin  # noqa: F401

    registry = get_default_registry()
    config = {
        "channels": {
            "feishu": {
                "groups": {
                    "*": {
                        "tools": {
                            "profile": "minimal",
                            "also_allow": ["channel:doc", "channel:wiki", "channel:drive"],
                        }
                    }
                }
            }
        }
    }

    ctx = apply_tool_policy_from_config(
        ToolContext(is_owner=False, caller_kind=CallerKind.CHANNEL, channel_kind="feishu"),
        available_tools=registry.list_names(),
        config=config,
    )
    allowed = ctx.allowed_tools or set()

    assert "feishu_doc_create" in allowed
    assert "feishu_doc_read_raw" in allowed
    assert "feishu_drive_upload_artifact" in allowed
    assert "feishu_drive_search" in allowed
    assert "feishu_wiki_list_spaces" in allowed
    assert "read_file" not in allowed
    assert "write_file" not in allowed
    assert "execute_code" not in allowed
    assert "publish_artifact" not in allowed


def test_channel_perm_policy_is_sender_scoped() -> None:
    import opensquilla.tools.builtin  # noqa: F401

    registry = get_default_registry()
    config = {
        "channels": {
            "feishu": {
                "groups": {
                    "*": {
                        "tools": {
                            "profile": "minimal",
                            "allow": ["feishu_perm_grant_member"],
                            "also_allow": ["channel:perm"],
                        }
                    },
                    "oc_group": {
                        "tools": {
                            "toolsBySender": {
                                "id:ou_allowed": {
                                    "also_allow": ["channel:perm"],
                                }
                            }
                        }
                    },
                }
            }
        }
    }

    default_ctx = apply_tool_policy_from_config(
        ToolContext(
            is_owner=False,
            caller_kind=CallerKind.CHANNEL,
            channel_kind="feishu",
            channel_id="oc_group",
            sender_id="ou_other",
        ),
        available_tools=registry.list_names(),
        config=config,
    )
    sender_ctx = apply_tool_policy_from_config(
        ToolContext(
            is_owner=False,
            caller_kind=CallerKind.CHANNEL,
            channel_kind="feishu",
            channel_id="oc_group",
            sender_id="ou_allowed",
        ),
        available_tools=registry.list_names(),
        config=config,
    )

    assert "feishu_perm_grant_member" not in (default_ctx.allowed_tools or set())
    assert "feishu_perm_grant_member" in (sender_ctx.allowed_tools or set())


@pytest.mark.asyncio
async def test_feishu_perm_grant_member_dry_run_does_not_call_api() -> None:
    import opensquilla.tools.builtin.feishu_platform as feishu_platform

    async def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError(f"unexpected request: {request.method} {request.url}")

    channel = _channel()
    channel._client = httpx.AsyncClient(
        base_url="https://open.feishu.cn/open-apis",
        transport=httpx.MockTransport(handler),
    )
    feishu_platform.register_feishu_channel("feishu-main", channel)

    try:
        result = json.loads(
            await feishu_platform.feishu_perm_grant_member(
                token="doc_token",
                doc_type="docx",
                member_type="openid",
                member_id="ou_user",
                perm="view",
                channel="feishu-main",
            )
        )
    finally:
        await channel.stop()
        feishu_platform.clear_feishu_channels()

    assert result["status"] == "dry_run"
    assert result["operation"] == "grant_member"
    assert result["plan"]["path"] == "/drive/v1/permissions/doc_token/members"
    assert result["plan"]["body"] == {
        "member_type": "openid",
        "member_id": "ou_user",
        "perm": "view",
    }


@pytest.mark.asyncio
async def test_feishu_perm_grant_member_mutates_after_dry_run_opt_in() -> None:
    import opensquilla.tools.builtin.feishu_platform as feishu_platform

    seen: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        body = await request.aread()
        if request.url.path == "/open-apis/drive/v1/permissions/doc_token/members":
            assert request.url.params["type"] == "docx"
            assert request.url.params["need_notification"] == "false"
            assert json.loads(body) == {
                "member_type": "openid",
                "member_id": "ou_user",
                "perm": "edit",
            }
            return httpx.Response(
                200,
                json={
                    "code": 0,
                    "data": {
                        "member": {
                            "member_type": "openid",
                            "member_id": "ou_user",
                            "perm": "edit",
                        }
                    },
                },
            )
        raise AssertionError(f"unexpected request: {request.method} {request.url}")

    channel = _channel()
    channel._client = httpx.AsyncClient(
        base_url="https://open.feishu.cn/open-apis",
        transport=httpx.MockTransport(handler),
    )
    feishu_platform.register_feishu_channel("feishu-main", channel)

    try:
        result = json.loads(
            await feishu_platform.feishu_perm_grant_member(
                token="doc_token",
                doc_type="docx",
                member_type="openid",
                member_id="ou_user",
                perm="edit",
                dry_run=False,
                channel="feishu-main",
            )
        )
    finally:
        await channel.stop()
        feishu_platform.clear_feishu_channels()

    assert [request.url.path for request in seen] == [
        "/open-apis/drive/v1/permissions/doc_token/members"
    ]
    assert result["status"] == "granted"
    assert result["member"]["member_id"] == "ou_user"


@pytest.mark.asyncio
async def test_channel_manager_registers_feishu_platform_tools(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import opensquilla.channels.manager as manager_mod
    import opensquilla.tools.builtin.feishu_platform as feishu_platform

    channel = _channel()
    entry = SimpleNamespace(
        enabled=True,
        name="feishu-main",
        type="feishu",
        agent_id="main",
        debounce_window_s=0.0,
    )
    monkeypatch.setattr(manager_mod, "build_managed_channel", lambda _entry: channel)
    feishu_platform.clear_feishu_channels()

    try:
        manager_mod.ChannelManager.from_config(
            [entry],
            turn_runner=None,
            session_manager=None,
        )
        result = json.loads(await feishu_platform.feishu_scopes_status(channel="feishu-main"))
    finally:
        await channel.stop()
        feishu_platform.clear_feishu_channels()

    assert result["status"] == "ok"
    assert result["channel"] == "feishu-main"
    assert "wiki:space:retrieve" in result["features"]["wiki_read"]["required_scopes"]
    assert "drive:drive" in result["features"]["drive_upload"]["required_scopes"]
    assert result["features"]["doc_create"]["tools"] == ["feishu_doc_create"]
    assert result["features"]["doc_create"]["category"] == "doc"
    assert result["features"]["doc_create"]["mutates"] is True
    assert result["features"]["wiki_read"]["category"] == "wiki"
    assert result["features"]["wiki_read"]["mutates"] is False
    assert result["features"]["perm_member"]["category"] == "perm"
    assert result["features"]["perm_member"]["mutates"] is True
    assert result["features"]["perm_member"]["dry_run_supported"] is True
    assert result["features"]["perm_member"]["default_channel_visible"] is False


@pytest.mark.asyncio
async def test_channel_manager_unregisters_feishu_platform_tools_on_stop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import opensquilla.channels.manager as manager_mod
    import opensquilla.tools.builtin.feishu_platform as feishu_platform

    channel = _channel()
    entry = SimpleNamespace(
        enabled=True,
        name="feishu-main",
        type="feishu",
        agent_id="main",
        debounce_window_s=0.0,
    )
    monkeypatch.setattr(manager_mod, "build_managed_channel", lambda _entry: channel)
    feishu_platform.clear_feishu_channels()
    manager = manager_mod.ChannelManager.from_config(
        [entry],
        turn_runner=None,
        session_manager=None,
    )

    try:
        await manager.stop_channel("feishu-main")
        with pytest.raises(Exception, match="unknown Feishu channel"):
            await feishu_platform.feishu_scopes_status(channel="feishu-main")
    finally:
        await channel.stop()
        feishu_platform.clear_feishu_channels()
