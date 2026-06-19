"""Asset tree node models — 类型、状态和节点定义。

AssetType 枚举了树中所有可能的节点层级::

  Network surface
    ROOT_DOMAIN → SUB_DOMAIN → IP → PORT → SERVICE → URL

  Web surface (URL 之下的可下钻资产)
    URL
      ├─ ENDPOINT            (method + path)
      │    └─ PARAMETER      (path / query / header / cookie)
      │         └─ INJECTION_VECTOR  (param × vuln 类型的二元漏洞点)
      ├─ AUTH_SURFACE        (login / SSO / API key / OAuth / JWT / reset)
      ├─ STATIC_ASSET        (robots.txt / swagger.json / .git/HEAD / 备份 / JS)
      ├─ API_SCHEMA          (OpenAPI / GraphQL SDL / Postman / gRPC)
      ├─ COOKIE              (HttpOnly / Secure / SameSite / 过期)
      └─ HEADER              (安全头 / 信息泄露头)

  Off-host surface
    COMPONENT               (product + version + cpe，独立 CVE 视角)
    STORAGE → STORAGE_OBJECT (s3 / azure / gcs bucket 与对象)
    SECRET                  (泄漏的凭证 / token / 内部域名)

  Catch-all
    GENERIC                 (兜底，可挂在任何父节点下)

AssetState 追踪每个节点的探测进度，驱动波次选择:
  UNSEEN → DISCOVERED → TRIAGED → EXPLOITED / ABANDONED

AssetNode 是树的原子单元，通过 parent_id / children_ids 构建层级。
metadata 字典按节点类型承载不同的附加信息（ASN、版本号、HTTP 状态等）。
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field


# ── 枚举 ──────────────────────────────────────────────


class AssetType(str, enum.Enum):
    """资产树节点类型 — 决定节点在层级中的位置和可接受的子节点类型。

    完整的层级关系见模块顶部的链路图。新增类型必须同步更新::

      - ``_VALID_PARENT_CHILD``（运行时父子校验）
      - ``db/schema.py`` 中 ``ck_asset_nodes_asset_type`` 的白名单
        与 ``DDL_STATEMENTS`` 模板
    """

    # ── Network surface ──────────────────────────────────────────
    ROOT_DOMAIN = "root_domain"  # 顶层根域名
    SUB_DOMAIN = "sub_domain"  # 子域名
    IP = "ip"  # IPv4 / IPv6 地址
    PORT = "port"  # 开放端口
    SERVICE = "service"  # 端口上的服务指纹

    # ── Web surface（URL 之下）────────────────────────────────────
    URL = "url"  # 服务下的可调用 URL（vhost / scheme / 认证上下文）
    ENDPOINT = "endpoint"  # URL 下的可调用接口（method + path）
    PARAMETER = "parameter"  # 接口下的具体参数（path/query/header/cookie）
    INJECTION_VECTOR = "injection_vector"  # 参数 × 注入类型的二元漏洞点
    AUTH_SURFACE = "auth_surface"  # 鉴权面：login / SSO / API key / OAuth / JWT / reset
    STATIC_ASSET = "static_asset"  # 静态资源：robots.txt / swagger.json / .git/HEAD / 备份 / JS
    API_SCHEMA = "api_schema"  # 结构化接口描述：OpenAPI / GraphQL SDL / Postman / gRPC
    COOKIE = "cookie"  # Cookie（HttpOnly / Secure / SameSite / 过期）
    HEADER = "header"  # HTTP 头（含安全头缺失 / 信息泄露头）

    # ── Off-host surface ─────────────────────────────────────────
    COMPONENT = "component"  # 组件指纹：product + version + cpe（独立 CVE 视角）
    STORAGE = "storage"  # 云存储：s3 / azure / gcs bucket
    STORAGE_OBJECT = "storage_object"  # 存储桶内的对象（敏感文件、备份等）
    SECRET = "secret"  # 泄漏的凭证 / 内部信息（key/token/内部域名）

    # ── Catch-all ────────────────────────────────────────────────
    GENERIC = "generic"  # 兜底


# 合法的父子关系: parent → set(child)
#
# 设计要点:
#   - ``URL`` 是 web 站点的统一挂载点；``ENDPOINT / AUTH_SURFACE /
#     STATIC_ASSET / API_SCHEMA / COOKIE / HEADER`` 都直接挂在 URL 之下，
#     表达"同一 base URL 下不同维度的资产"。
#   - ``COMPONENT`` 同时挂在 ``SERVICE``（指纹如 nginx 1.24.0）和 ``URL``
#     （从 JS bundle/响应头识别的前端组件）之下，因为组件是 CVE 视角
#     的独立可测资产，跨层级复用合理。
#   - ``STORAGE`` / ``STORAGE_OBJECT`` 挂在 ``SUB_DOMAIN`` 之下，表达
#     "该子域对应公司名/产品名关联到的云存储"。
#   - ``SECRET`` 可挂在任何父节点之下（JS 文件、env、config、git 历史
#     都可能命中），通过 ``GENERIC`` 的特殊化 ``_ALLOWED_PARENT_TYPES``
#     集合精确控制，避免误挂。
#   - ``GENERIC`` 仍保留"父位可接受任何子类型"语义不变。
_VALID_PARENT_CHILD: dict[AssetType, set[AssetType]] = {
    # Network surface
    AssetType.ROOT_DOMAIN: {AssetType.SUB_DOMAIN, AssetType.ROOT_DOMAIN},  # ROOT_DOMAIN children: SUB_DOMAIN (normal) or ROOT_DOMAIN (extra_seed sibling)
    AssetType.SUB_DOMAIN: {AssetType.IP, AssetType.STORAGE, AssetType.SECRET},
    AssetType.IP: {AssetType.PORT, AssetType.SECRET},
    AssetType.PORT: {AssetType.SERVICE},
    AssetType.SERVICE: {
        AssetType.URL,
        AssetType.COMPONENT,
        AssetType.SECRET,
    },
    # Web surface — 全部以 URL 为父位
    AssetType.URL: {
        AssetType.ENDPOINT,
        AssetType.AUTH_SURFACE,
        AssetType.STATIC_ASSET,
        AssetType.API_SCHEMA,
        AssetType.COMPONENT,
        AssetType.COOKIE,
        AssetType.HEADER,
        AssetType.SECRET,
    },
    AssetType.ENDPOINT: {AssetType.PARAMETER},
    AssetType.PARAMETER: {AssetType.INJECTION_VECTOR},
    # Off-host surface
    AssetType.STORAGE: {AssetType.STORAGE_OBJECT},
    # Catch-all
    AssetType.GENERIC: set(AssetType),  # generic 可以接受任何子类型
}

# ``SECRET`` 允许的父类型白名单（精确控制，避免误挂）
_SECRET_ALLOWED_PARENTS: frozenset[AssetType] = frozenset({
    AssetType.SUB_DOMAIN,
    AssetType.IP,
    AssetType.SERVICE,
    AssetType.URL,
    AssetType.STATIC_ASSET,
    AssetType.API_SCHEMA,
    AssetType.STORAGE,
    AssetType.STORAGE_OBJECT,
})


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

    # v5 (2026-06-18): 节点到根的距离 (0 = 根)。这是一个 property,
    # **不**作为 Pydantic 字段存储 — 调用方拿不到父链时返回 -1。
    # 真正的权威存于 db schema 的 ``path_depth`` 列, 该列在
    # ``_add_node_locked`` 写入时设置; in-memory 节点通过
    # ``compute_depth_from_chain`` 在树组装时回填。
    @property
    def depth(self) -> int:
        """自身 depth (L0 = 根)。无法解析 (脱离树) 时返回 -1。"""
        if self.parent_id is None:
            return 0
        # 默认无外部上下文时, 返回 -1; 调用方 (AssetTree.add_node
        # 完成后会显式 set_depth) 负责注入。
        return getattr(self, "_depth", -1)

    def set_depth(self, depth: int) -> None:
        """由 ``AssetTree._add_node_locked`` 调用, 写入 in-memory 深度。"""
        self._depth = int(depth)

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


# ── 深度约束 ─────────────────────────────────────────────
#
# 业务硬约束 (v5, 2026-06-18): AssetTree 的合法路径深度上限为 8 层
# (从 ROOT_DOMAIN 算起, 包含 L0 根节点)。这条约束由 ``_VALID_PARENT_CHILD``
# 的最长链 ``ROOT → SUB → IP → PORT → SERVICE → URL → ENDPOINT →
# PARAMETER → INJECTION_VECTOR`` 推导得出, 是"业务模型"与"编排器波次系统"
# 共用的硬约束。
#
# 深度编号约定 (与 AssetPath.depth() 一致, L = path_depth):
#   L0  ROOT_DOMAIN
#   L1  SUB_DOMAIN
#   L2  IP / STORAGE
#   L3  PORT / SERVICE / STORAGE_OBJECT
#   L4  URL / COMPONENT
#   L5  ENDPOINT / AUTH_SURFACE / STATIC_ASSET / API_SCHEMA / COOKIE / HEADER
#   L6  (跳过 — 当前主链未占用, 预留)
#   L7  PARAMETER       (业务最深资产层, find 终止契约目标)
#   L8  INJECTION_VECTOR (漏洞向量层, find 不写)
#
# 跨层挂载 ``SECRET`` / 兜底 ``GENERIC`` 不计入主链深度 (它们允许挂在
# 8 类父节点白名单下, 自身是叶节点)。
#
# ``MAX_TREE_DEPTH = 8`` 是 v5 新增常量, 含义 = **路径深度上限**
# (节点 path_depth ∈ [0, 8], 9 节点层)。实际最长链 (path_depth 0..7):
# ROOT(L0) → SUB(L1) → IP(L2) → PORT(L3) → SERVICE(L4) → URL(L5) →
# ENDPOINT(L6) → PARAMETER(L7), 共 8 节点层 = 8 层资产深度。
# INJECTION_VECTOR (L8, path_depth=8) 由 hack-deep 在 attack phase
# 写入, 受 MAX_TREE_DEPTH=8 上限保护。任何 ``add_node`` 触发
# ``validate_depth()`` 失败都会 raise ``DepthExceededError``。
MAX_TREE_DEPTH: int = 8


# v5.2 (2026-06-18) ``FIND_TERMINATION_DEPTH`` — hack-deep-find 终止深度。
#
# 业务硬上限仍为 ``MAX_TREE_DEPTH = 8`` (path_depth ∈ [0, 8], 9 节点层),
# 保留作为模型合法性的天花板, 允许 INJECTION_VECTOR (path_depth=8) 这类漏洞
# 节点在 attack phase 阶段由 hack-deep 写入树中。
#
# 但 hack-deep-find 的 find-complete-v1 emit 契约锚定在 L7 PARAMETER
# (path_depth=7) — 即整棵资产树最深的"业务资产层"。从 L0 (ROOT_DOMAIN)
# 到 L7 (PARAMETER) 一共 8 节点层 / 7 跳边, 这就是用户口中的"8 层深度"
# 资产树, 是 find 唯一负责构建的范围。
#
# INJECTION_VECTOR (path_depth=8) 节点**允许出现在树中** (作为后续
# attack-phase 写入的预留位置, 仍受 MAX_TREE_DEPTH=8 约束), 但 find 不
# 负责产生它, 也不要求 is_skeleton_complete() 为 True 时它必须存在。
# ``is_skeleton_complete()`` 现以 ``max_depth_reached() >=
# FIND_TERMINATION_DEPTH`` 为终止条件。
#
# 关联职责划分 (v5.2):
#   L0..L7  = 资产 (find 全权负责: discovery + verification + tree persist)
#   L8      = 漏洞向量 (hack-deep 在 attack phase 写入, find 不触碰)
#
# depth 编号速查 (与 AssetPath.depth() / 实际代码验证 一致):
#   L0  ROOT_DOMAIN          (path_depth=0)
#   L1  SUB_DOMAIN           (path_depth=1)
#   L2  IP / STORAGE         (path_depth=2)
#   L3  PORT / SERVICE / SO  (path_depth=3)
#   L4  URL / COMPONENT      (path_depth=4)
#   L5  ENDPOINT / AUTH...   (path_depth=5)
#   L6  (此项保留, 当前主链未占用)
#   L7  PARAMETER            (path_depth=7, 业务最深资产层, find 终止)
#   L8  INJECTION_VECTOR     (path_depth=8, 漏洞向量层, find 不写)
#
# 因此"8 层深度"资产树 = path_depth 上限 7 = 8 节点层 (L0..L7)。
FIND_TERMINATION_DEPTH: int = 7


class IncompleteSkeletonError(RuntimeError):
    """v5.2 (2026-06-18) find 终止骨架未完整时阻断 find-complete-v1 emit。

    ``asset_tree_complete`` 工具在 ``is_skeleton_complete() == False`` 时
    raise 此异常, 强制编排器先跑 F-resume 补全缺失 wave。LLM 收到此异常
    必须调用 ``asset_tree_plan_pending(tree_id)`` 拿 pending plan, 然后
    跑缺失的 F1.5 / F1.5c / F3.5 wave, 直到 complete=True。

    v5.2 重大变更: find 终止深度从 L8 INJECTION_VECTOR 改为 L7 PARAMETER
    (path_depth=7), 因为 L8 是漏洞向量节点, 不属于资产探测范畴。L8
    节点仍可由 hack-deep 在 attack phase 写入 (受 MAX_TREE_DEPTH=8
    业务硬上限保护), 但 find 不要求也不负责。详细职责划分见本模块
    顶部的 ``FIND_TERMINATION_DEPTH`` 注释。

    不允许: 改 force=True 强行跳过 (除非真的紧急, e.g. 用户手动中断);
    不允许: 发假的 find-complete-v1 evidence 声称 complete。
    """

    def __init__(
        self,
        *,
        tree_id: str,
        max_depth_reached: int,
        max_depth_required: int = FIND_TERMINATION_DEPTH,
        unseen_total: int,
        completion_pct: float,
        missing_waves: list[str] | None = None,
    ) -> None:
        self.tree_id = tree_id
        self.max_depth_reached = max_depth_reached
        self.max_depth_required = max_depth_required
        self.unseen_total = unseen_total
        self.completion_pct = completion_pct
        self.missing_waves = missing_waves or []
        waves_str = ", ".join(self.missing_waves) if self.missing_waves else "<unknown>"
        super().__init__(
            f"[tree_id={tree_id}] find-skeleton INCOMPLETE: "
            f"max_depth_reached={max_depth_reached} "
            f"(need {max_depth_required}), "
            f"unseen_total={unseen_total} (need 0), "
            f"completion_pct={completion_pct:.2%}. "
            f"Missing waves (run F-resume): {waves_str}. "
            f"DO NOT emit find-complete-v1 until this is resolved."
        )


class DepthExceededError(ValueError):
    """调用方尝试添加会超过 ``MAX_TREE_DEPTH`` 路径深度的节点。

    典型触发场景: 试图在 INJECTION_VECTOR (L8) 下再挂子节点 (新节点
    path_depth=9, 越界), 或者试图在 ``SECRET`` 下再挂子节点 (虽然
    ``_VALID_PARENT_CHILD`` 也不允许 SECRET 有子节点, 但深度校验是
    防御性纵深)。
    """

    def __init__(
        self,
        *,
        would_be_depth: int,
        parent_depth: int | None,
        parent_type: AssetType | None,
        child_type: AssetType,
        max_depth: int = MAX_TREE_DEPTH,
    ) -> None:
        self.would_be_depth = would_be_depth
        self.parent_depth = parent_depth
        self.parent_type = parent_type
        self.child_type = child_type
        self.max_depth = max_depth
        super().__init__(
            f"Depth would be {would_be_depth} (> {max_depth}, hard cap); "
            f"refused to add {child_type.value} under "
            f"{parent_type.value if parent_type else '<None>'} "
            f"(parent_depth={parent_depth}). "
            f"Allowed deepest chain ends at INJECTION_VECTOR (L8, depth=8). "
            f"SECRET and GENERIC are cross-layer / catch-all and may "
            f"hang off whitelisted parents regardless of depth, but "
            f"are leaves themselves (no further descendants)."
        )


def validate_depth(
    *,
    parent_depth: int | None,
    parent_type: AssetType | None,
    child_type: AssetType,
) -> int:
    """校验父→子边的深度不会越界, 返回新节点的深度 (parent_depth + 1)。

    规则:
      * 根节点 (parent_depth is None) 总是深度 0, 无需校验。
      * 业务类型: 必须满足 ``parent_depth + 1 <= MAX_TREE_DEPTH`` (即新节点 depth <= 8)。
      * ``SECRET`` / ``GENERIC`` 也走同一深度规则 (它们自身是叶,
        因此不可能成为 "parent" — 但 ``validate_depth`` 仍然作为
        防御性纵深)。
    Raises:
        DepthExceededError: 越界时。
    """
    if parent_depth is None:
        return 0
    would_be = parent_depth + 1
    # 业务最深的合法节点是 L8 (INJECTION_VECTOR, path_depth=8)。
    # 越界 (would_be > MAX_TREE_DEPTH=8, 即 9) 拒。
    if would_be > MAX_TREE_DEPTH:
        raise DepthExceededError(
            would_be_depth=would_be,
            parent_depth=parent_depth,
            parent_type=parent_type,
            child_type=child_type,
        )
    return would_be


# ── 父子关系校验 ─────────────────────────────────────────────


def validate_parent_child(parent_type: AssetType, child_type: AssetType) -> None:
    """校验父子关系是否合法，不合法则抛出 ValueError。

    ``SECRET`` 节点单独走白名单校验（见 ``_SECRET_ALLOWED_PARENTS``），
    其它节点走 ``_VALID_PARENT_CHILD``。
    """
    if child_type == AssetType.SECRET:
        if parent_type not in _SECRET_ALLOWED_PARENTS:
            raise ValueError(
                f"Invalid parent→child: {parent_type.value} → {child_type.value}. "
                f"Allowed parents of secret: "
                f"{sorted(t.value for t in _SECRET_ALLOWED_PARENTS)}"
            )
        return
    allowed = _VALID_PARENT_CHILD.get(parent_type)
    if allowed is None:
        raise ValueError(f"Unknown parent type: {parent_type}")
    if child_type not in allowed:
        raise ValueError(
            f"Invalid parent→child: {parent_type.value} → {child_type.value}. "
            f"Allowed children of {parent_type.value}: {[t.value for t in sorted(allowed, key=lambda t: t.value)]}"
        )


# ── 攻击路径模型 (v6, 2026-06-19) ─────────────────────────────────────
#
# AttackPath = 资产树上一条从 L0 (ROOT_DOMAIN) 到 L7 (PARAMETER) 的完整
# 边链。create-attack-path agent 用它把"树上的边"打包成"一次攻击输入";
# hack-deep 按 path_id 接单, 跑完后回写 vulnerability / vuln_node_vulns
# 实现反哺。
#
# AttackEdge 是组成 AttackPath 的原子 — 一对父子节点, 携带类型/值/状态
# 三个字段, 给 specialist 当 scope 上下文拼 BriefContext 用。
#
# 路径 ID 的来源: 对 edge_chain 做 SHA1 取前 12 hex (与 AssetNode.id
# 风格一致, 12 hex 字符), 相同拓扑 + 状态组合的两次枚举产生同一 id,
# 写入 vuln_attack_paths 时靠 path_hash UNIQUE 约束做幂等。

import hashlib

AttackPathStatus = Literal[
    "pending",
    "in_progress",
    "completed",
    "failed",
    "abandoned",
]


class AttackEdge(BaseModel):
    """AttackPath 中的一条边 — L_n 节点 → L_{n+1} 节点。"""

    edge_index: int = Field(..., ge=0, le=7, description="边在路径中的位置, 0..7")
    from_node_id: str
    to_node_id: str
    from_type: AssetType
    to_type: AssetType
    from_value: str
    to_value: str
    edge_state: AssetState = Field(
        default=AssetState.UNSEEN,
        description="to_node 的当前状态",
    )

    def to_scope_part(self) -> str:
        return f"{self.from_type.value}={self.from_value} -> {self.to_type.value}={self.to_value}"


class AttackPath(BaseModel):
    """一棵资产树上一条 L0..L7 的完整路径, 作为一次攻击输入。"""

    path_id: str = Field(..., min_length=12, max_length=12)
    tree_id: str
    edges: list[AttackEdge] = Field(..., min_length=1)
    leaf_node_id: str
    leaf_type: AssetType
    leaf_value: str
    scope_string: str = Field(..., description="人读 scope 串, 给 LLM/human 看")
    metadata: dict[str, Any] = Field(default_factory=dict)
    status: AttackPathStatus = "pending"
    created_at: datetime = Field(default_factory=_utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    vuln_count: int = 0
    error: Optional[str] = None

    @staticmethod
    def compute_path_id(edges: list[AttackEdge]) -> str:
        """由边链生成稳定的 12 hex id (与 AssetNode.id 风格一致)。"""
        buf = "|".join(
            f"{e.from_node_id}->{e.to_node_id}:{e.from_type.value}:{e.to_type.value}:{e.from_value}:{e.to_value}"
            for e in edges
        )
        return hashlib.sha1(buf.encode("utf-8")).hexdigest()[:12]

    def mark_started(self) -> None:
        if self.started_at is None:
            self.started_at = _utcnow()
        self.status = "in_progress"

    def mark_completed(self, vuln_count: int) -> None:
        self.completed_at = _utcnow()
        self.status = "completed"
        self.vuln_count = vuln_count

    def mark_failed(self, error: str) -> None:
        self.completed_at = _utcnow()
        self.status = "failed"
        self.error = error

    def mark_abandoned(self, reason: str) -> None:
        self.completed_at = _utcnow()
        self.status = "abandoned"
        self.error = reason

    def to_dict(self) -> dict[str, Any]:
        return {
            "path_id": self.path_id,
            "tree_id": self.tree_id,
            "edges": [e.model_dump(mode="json") for e in self.edges],
            "leaf_node_id": self.leaf_node_id,
            "leaf_type": self.leaf_type.value,
            "leaf_value": self.leaf_value,
            "scope_string": self.scope_string,
            "metadata": self.metadata,
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "vuln_count": self.vuln_count,
            "error": self.error,
        }
