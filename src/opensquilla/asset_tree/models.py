"""Asset tree node models — 类型、状态和节点定义。

AssetType 枚举了树中所有可能的节点层级:
  ROOT_DOMAIN → SUB_DOMAIN → IP → PORT → SERVICE → ENDPOINT

AssetState 追踪每个节点的探测进度，驱动波次选择:
  UNSEEN → DISCOVERED → TRIAGED → EXPLOITED / ABANDONED

AssetNode 是树的原子单元，通过 parent_id / children_ids 构建层级。
metadata 字典按节点类型承载不同的附加信息（ASN、版本号、HTTP 状态等）。
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, Field


# ── 枚举 ──────────────────────────────────────────────


class AssetType(str, enum.Enum):
    """资产树节点类型 — 决定节点在层级中的位置和可接受的子节点类型。"""

    ROOT_DOMAIN = "root_domain"  # 顶层根域名
    SUB_DOMAIN = "sub_domain"  # 子域名
    IP = "ip"  # IPv4 / IPv6 地址
    PORT = "port"  # 开放端口
    SERVICE = "service"  # 端口上的服务指纹
    ENDPOINT = "endpoint"  # 服务下的具体路径 / 表 / 方法
    GENERIC = "generic"  # 兜底


# 合法的父子关系: parent → set(child)
_VALID_PARENT_CHILD: dict[AssetType, set[AssetType]] = {
    AssetType.ROOT_DOMAIN: {AssetType.SUB_DOMAIN},
    AssetType.SUB_DOMAIN: {AssetType.IP},
    AssetType.IP: {AssetType.PORT},
    AssetType.PORT: {AssetType.SERVICE},
    AssetType.SERVICE: {AssetType.ENDPOINT},
    AssetType.GENERIC: set(AssetType),  # generic 可以接受任何子类型
}


class AssetState(str, enum.Enum):
    """节点探测状态 — 驱动波次选择和 brief 生成。

    状态流转::

        UNSEEN  ──(W0.5/W1 扫描)──→  DISCOVERED
        DISCOVERED ──(W2 triage)──→  TRIAGED
        TRIAGED  ──(W4 exploit)──→  EXPLOITED
        UNSEEN / DISCOVERED / TRIAGED ──→  ABANDONED
    """

    UNSEEN = "unseen"  # 从 DNS/扫描中发现，尚未深入
    DISCOVERED = "discovered"  # 基础信息已获取（端口开放、服务指纹）
    TRIAGED = "triaged"  # 已完成 vulnerability triage
    EXPLOITED = "exploited"  # 已有 exploit 成功
    ABANDONED = "abandoned"  # 放弃（不可达、无价值等）


# ── 节点模型 ──────────────────────────────────────────


def _new_id() -> str:
    """生成 12 字符的短 hex id。"""
    return uuid.uuid4().hex[:12]


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class AssetNode(BaseModel):
    """资产树的单个节点。

    Attributes:
        id: 唯一标识（12 位 hex）。
        asset_type: 节点类型。
        value: 节点值 — 按类型不同含义不同:
            - ROOT_DOMAIN / SUB_DOMAIN: 域名字符串
            - IP: IPv4 或 IPv6 地址
            - PORT: 端口号（字符串）
            - SERVICE: 服务指纹，如 "HTTP/NGINX 1.24.0"
            - ENDPOINT: 路径/表名/方法名
        state: 探测状态。
        parent_id: 父节点 ID（根节点为 None）。
        children_ids: 子节点 ID 列表（保持插入顺序）。
        source_wave: 发现此节点的波次 handoff_id。
        first_seen / last_seen: 时间戳。
        metadata: 按类型承载不同附加信息的字典。
            - SUB_DOMAIN: ``{"resolver": "dns", "records": ["A: 1.2.3.4"]}``
            - IP: ``{"asn": "AS12345", "geo": "US", "isp": "Cloudflare"}``
            - PORT: ``{"state": "open", "protocol": "tcp"}``
            - SERVICE: ``{"product": "nginx", "version": "1.24.0", "cpe": "..."}``
            - ENDPOINT: ``{"method": "GET", "status": 200, "content_type": "text/html"}``
        assigned_wave: 当前正在被哪个波次处理。
        evidence_refs: 关联的 evidence handoff_id 列表。
    """

    id: str = Field(default_factory=_new_id)
    asset_type: AssetType
    value: str
    state: AssetState = AssetState.UNSEEN
    parent_id: Optional[str] = None
    children_ids: list[str] = Field(default_factory=list)

    # 发现上下文
    source_wave: Optional[str] = None
    first_seen: Optional[datetime] = Field(default_factory=_utcnow)
    last_seen: Optional[datetime] = Field(default_factory=_utcnow)

    # 元数据
    metadata: dict[str, Any] = Field(default_factory=dict)

    # 波次绑定
    assigned_wave: Optional[str] = None
    evidence_refs: list[str] = Field(default_factory=list)

    def is_leaf(self) -> bool:
        """是否为叶节点（无子节点）。"""
        return len(self.children_ids) == 0

    def to_ref(self) -> "AssetNodeRef":
        """转为轻量引用。"""
        return AssetNodeRef(
            node_id=self.id,
            asset_type=self.asset_type,
            value=self.value,
            state=self.state,
        )


# ── 轻量引用 ──────────────────────────────────────────


class AssetNodeRef(BaseModel):
    """轻量节点引用 — 用于传递而非序列化整棵树。"""

    node_id: str
    asset_type: AssetType
    value: str
    state: AssetState


# ── 路径模型 ──────────────────────────────────────────


class AssetPath(BaseModel):
    """从根到当前节点的路径描述 — 用于 scope 传递和 brief 生成。"""

    parts: list[AssetNodeRef] = Field(default_factory=list)

    def to_scope_string(self) -> str:
        """生成如 ``ROOT_DOMAIN=example.com → IP=1.2.3.4 → PORT=443`` 的 scope 描述。"""
        return " → ".join(f"{p.asset_type.value}={p.value}" for p in self.parts)

    def to_brief_context(self) -> str:
        """生成给 specialist 的多行上下文摘要。"""
        lines: list[str] = []
        for p in self.parts:
            lines.append(f"  [{p.asset_type.value}] {p.value}  state={p.state.value}")
        return "\n".join(lines)

    def depth(self) -> int:
        return len(self.parts)


# ── 父子关系校验 ──────────────────────────────────────


def validate_parent_child(parent_type: AssetType, child_type: AssetType) -> None:
    """校验父子关系是否合法，不合法则抛出 ValueError。"""
    allowed = _VALID_PARENT_CHILD.get(parent_type)
    if allowed is None:
        raise ValueError(f"Unknown parent type: {parent_type}")
    if child_type not in allowed:
        raise ValueError(
            f"Invalid parent→child: {parent_type.value} → {child_type.value}. "
            f"Allowed children of {parent_type.value}: {[t.value for t in sorted(allowed, key=lambda t: t.value)]}"
        )
