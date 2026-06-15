已确认项目当前使用 SQLite/aiosqlite。现在提供完整 PostgreSQL 企业级方案：

---

## 完整方案

### 1. 添加依赖

```toml
# pyproject.toml - 添加到 dependencies
"asyncpg>=0.29",           # PostgreSQL 异步驱动
"sqlalchemy[asyncio]>=2.0", # ORM
```

### 2. 数据库配置

```python
# src/opensquilla/asset_tree/db/config.py
from pydantic_settings import BaseSettings
from functools import lru_cache

class DatabaseSettings(BaseSettings):
    """PostgreSQL connection settings."""
    
    ASSET_TREE_DB_URL: str = "postgresql+asyncpg://user:pass@localhost:5432/opensquilla"
    DB_POOL_SIZE: int = 20
    DB_MAX_OVERFLOW: int = 30
    DB_POOL_TIMEOUT: int = 30
    DB_POOL_RECYCLE: int = 1800
    
    model_config = {"env_prefix": ""}

@lru_cache
def get_db_settings() -> DatabaseSettings:
    return DatabaseSettings()
```

### 3. ORM 模型

```python
# src/opensquilla/asset_tree/db/models.py
from datetime import datetime
from typing import Optional, List
from uuid import UUID, uuid4

from sqlalchemy import (
    String, Text, Boolean, DateTime, ForeignKey, Index, UniqueConstraint
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID, INET, JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class TreeModel(Base):
    """资产树元数据表."""
    __tablename__ = "asset_trees"

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    root_domain: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, default="")
    created_by: Mapped[Optional[str]] = mapped_column(String(100))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)
    is_deleted: Mapped[bool] = mapped_column(Boolean, default=False)

    # 关系
    nodes: Mapped[List["NodeModel"]] = relationship(back_populates="tree", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_trees_root_domain", "root_domain"),
    )


class NodeModel(Base):
    """资产节点表 - 支持树形递归查询."""
    __tablename__ = "asset_nodes"

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    tree_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("asset_trees.id", ondelete="CASCADE"), nullable=False)
    parent_id: Mapped[Optional[UUID]] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("asset_nodes.id", ondelete="SET NULL"))
    
    # 节点标识
    node_id: Mapped[str] = mapped_column(String(100), nullable=False)
    node_type: Mapped[str] = mapped_column(String(50), nullable=False)
    
    # 核心属性
    title: Mapped[Optional[str]] = mapped_column(String(500), default="")
    state: Mapped[str] = mapped_column(String(50), default="unseen")
    url: Mapped[Optional[str]] = mapped_column(Text)
    asset_type: Mapped[Optional[str]] = mapped_column(String(50))
    ip_address: Mapped[Optional[str]] = mapped_column(INET)
    
    # 元数据
    meta: Mapped[dict] = mapped_column(JSONB, default=dict)
    
    # 时间戳
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)

    # 关系
    tree: Mapped["TreeModel"] = relationship(back_populates="nodes")
    parent: Mapped[Optional["NodeModel"]] = relationship(remote_side=[id], back_populates="children")
    children: Mapped[List["NodeModel"]] = relationship(back_populates="parent")

    __table_args__ = (
        UniqueConstraint("tree_id", "node_id", name="uq_tree_node_id"),
        UniqueConstraint("tree_id", "parent_id", "node_id", name="uq_tree_parent_node"),
        Index("idx_nodes_tree", "tree_id"),
        Index("idx_nodes_parent", "parent_id"),
        Index("idx_nodes_type", "tree_id", "node_type"),
        Index("idx_nodes_state", "tree_id", "state"),
        Index("idx_nodes_meta", "meta", postgresql_using="gin"),
        Index("idx_nodes_ip", "ip_address"),
    )


class AuditLogModel(Base):
    """审计日志表."""
    __tablename__ = "asset_audit_log"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tree_id: Mapped[Optional[UUID]] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("asset_trees.id"))
    node_id: Mapped[Optional[UUID]] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("asset_nodes.id"))
    action: Mapped[str] = mapped_column(String(50), nullable=False)
    old_value: Mapped[Optional[dict]] = mapped_column(JSONB)
    new_value: Mapped[Optional[dict]] = mapped_column(JSONB)
    changed_by: Mapped[Optional[str]] = mapped_column(String(100))
    changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)

    __table_args__ = (
        Index("idx_audit_tree", "tree_id"),
        Index("idx_audit_changed_at", "changed_at"),
    )
```

### 4. 数据库会话管理

```python
# src/opensquilla/asset_tree/db/session.py
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from .config import get_db_settings
from .models import Base


class Database:
    """PostgreSQL async session manager."""

    def __init__(self):
        settings = get_db_settings()
        self.engine = create_async_engine(
            settings.ASSET_TREE_DB_URL,
            pool_size=settings.DB_POOL_SIZE,
            max_overflow=settings.DB_MAX_OVERFLOW,
            pool_timeout=settings.DB_POOL_TIMEOUT,
            pool_recycle=settings.DB_POOL_RECYCLE,
            pool_pre_ping=True,
        )
        self.session_factory = async_sessionmaker(
            bind=self.engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )

    async def create_tables(self):
        """Create all tables (for development/testing)."""
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def drop_tables(self):
        """Drop all tables (for testing)."""
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)

    @asynccontextmanager
    async def session(self) -> AsyncGenerator[AsyncSession, None]:
        """Get an async session with automatic commit/rollback."""
        async with self.session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    async def close(self):
        """Close the engine."""
        await self.engine.dispose()


# Singleton
_db: Database | None = None


def get_db() -> Database:
    global _db
    if _db is None:
        _db = Database()
    return _db
```

### 5. Repository 实现

```python
# src/opensquilla/asset_tree/db/repository.py
from typing import Optional, List
from uuid import UUID

from sqlalchemy import select, update, delete, func, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from .models import TreeModel, NodeModel, AuditLogModel
from .session import get_db


class TreeRepository:
    """资产树数据访问层."""

    def __init__(self, session: AsyncSession):
        self.session = session

    # ── Tree CRUD ──────────────────────────────────────

    async def create_tree(
        self,
        name: str,
        root_domain: str,
        description: str = "",
        created_by: str | None = None,
    ) -> TreeModel:
        tree = TreeModel(
            name=name,
            root_domain=root_domain,
            description=description,
            created_by=created_by,
        )
        self.session.add(tree)
        await self.session.flush()
        return tree

    async def get_tree(self, tree_id: UUID, include_deleted: bool = False) -> Optional[TreeModel]:
        query = select(TreeModel).where(TreeModel.id == tree_id)
        if not include_deleted:
            query = query.where(TreeModel.is_deleted == False)
        result = await self.session.execute(query)
        return result.scalar_one_or_none()

    async def list_trees(self, limit: int = 100, offset: int = 0) -> List[TreeModel]:
        query = (
            select(TreeModel)
            .where(TreeModel.is_deleted == False)
            .order_by(TreeModel.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def delete_tree(self, tree_id: UUID, hard: bool = False) -> bool:
        if hard:
            await self.session.execute(delete(TreeModel).where(TreeModel.id == tree_id))
        else:
            await self.session.execute(
                update(TreeModel).where(TreeModel.id == tree_id).values(is_deleted=True)
            )
        return True

    # ── Node CRUD ──────────────────────────────────────

    async def create_node(
        self,
        tree_id: UUID,
        node_id: str,
        node_type: str,
        parent_id: UUID | None = None,
        title: str = "",
        state: str = "unseen",
        url: str | None = None,
        asset_type: str | None = None,
        ip_address: str | None = None,
        meta: dict | None = None,
    ) -> NodeModel:
        node = NodeModel(
            tree_id=tree_id,
            parent_id=parent_id,
            node_id=node_id,
            node_type=node_type,
            title=title,
            state=state,
            url=url,
            asset_type=asset_type,
            ip_address=ip_address,
            meta=meta or {},
        )
        self.session.add(node)
        await self.session.flush()
        return node

    async def get_node(self, node_id: UUID) -> Optional[NodeModel]:
        query = select(NodeModel).where(NodeModel.id == node_id)
        result = await self.session.execute(query)
        return result.scalar_one_or_none()

    async def get_node_by_tree_and_node_id(
        self, tree_id: UUID, node_id: str
    ) -> Optional[NodeModel]:
        query = select(NodeModel).where(
            NodeModel.tree_id == tree_id,
            NodeModel.node_id == node_id,
        )
        result = await self.session.execute(query)
        return result.scalar_one_or_none()

    async def list_nodes(
        self,
        tree_id: UUID,
        parent_id: UUID | None = None,
        node_type: str | None = None,
        state: str | None = None,
        limit: int = 1000,
    ) -> List[NodeModel]:
        query = select(NodeModel).where(NodeModel.tree_id == tree_id)
        
        if parent_id is not None:
            query = query.where(NodeModel.parent_id == parent_id)
        if node_type:
            query = query.where(NodeModel.node_type == node_type)
        if state:
            query = query.where(NodeModel.state == state)
            
        query = query.order_by(NodeModel.created_at).limit(limit)
        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def update_node(
        self,
        node_id: UUID,
        **kwargs,
    ) -> bool:
        kwargs["updated_at"] = func.now()
        await self.session.execute(
            update(NodeModel).where(NodeModel.id == node_id).values(**kwargs)
        )
        return True

    async def update_node_state(self, node_id: UUID, new_state: str, changed_by: str | None = None) -> bool:
        """更新节点状态并记录审计日志."""
        node = await self.get_node(node_id)
        if not node:
            return False
        
        old_state = node.state
        await self.update_node(node_id, state=new_state)
        
        # 审计日志
        audit = AuditLogModel(
            tree_id=node.tree_id,
            node_id=node_id,
            action="state_change",
            old_value={"state": old_state},
            new_value={"state": new_state},
            changed_by=changed_by,
        )
        self.session.add(audit)
        return True

    async def delete_node(self, node_id: UUID) -> bool:
        await self.session.execute(delete(NodeModel).where(NodeModel.id == node_id))
        return True

    # ── 递归查询 ──────────────────────────────────────

    async def get_full_tree(self, tree_id: UUID) -> List[dict]:
        """递归查询获取完整树结构."""
        query = text("""
            WITH RECURSIVE tree AS (
                SELECT id, tree_id, parent_id, node_id, node_type, 
                       title, state, url, asset_type, ip_address, meta,
                       created_at, updated_at,
                       ARRAY[id] as path_ids
                FROM asset_nodes 
                WHERE parent_id IS NULL AND tree_id = :tree_id
                UNION ALL
                SELECT n.id, n.tree_id, n.parent_id, n.node_id, n.node_type,
                       n.title, n.state, n.url, n.asset_type, n.ip_address, n.meta,
                       n.created_at, n.updated_at,
                       t.path_ids || n.id
                FROM asset_nodes n
                JOIN tree t ON n.parent_id = t.id
            )
            SELECT * FROM tree ORDER BY path_ids
        """)
        result = await self.session.execute(query, {"tree_id": str(tree_id)})
        return [dict(row._mapping) for row in result]

    async def get_node_path(self, node_id: UUID) -> List[dict]:
        """获取节点到根的路径."""
        query = text("""
            WITH RECURSIVE path AS (
                SELECT id, node_id, title, parent_id, node_type, state,
                       ARRAY[id] as path_ids
                FROM asset_nodes WHERE id = :node_id
                UNION ALL
                SELECT n.id, n.node_id, n.title, n.parent_id, n.node_type, n.state,
                       p.path_ids || n.id
                FROM asset_nodes n JOIN path p ON n.parent_id = p.id
            )
            SELECT * FROM path ORDER BY path_ids
        """)
        result = await self.session.execute(query, {"node_id": str(node_id)})
        return [dict(row._mapping) for row in result]

    # ── 统计查询 ──────────────────────────────────────

    async def get_tree_stats(self, tree_id: UUID) -> dict:
        """获取树统计信息."""
        query = text("""
            SELECT 
                node_type,
                state,
                COUNT(*) as count
            FROM asset_nodes
            WHERE tree_id = :tree_id
            GROUP BY node_type, state
        """)
        result = await self.session.execute(query, {"tree_id": str(tree_id)})
        
        stats = {"total": 0, "by_type": {}, "by_state": {}}
        for row in result:
            node_type, state, count = row
            stats["total"] += count
            stats["by_type"][node_type] = stats["by_type"].get(node_type, 0) + count
            stats["by_state"][state] = stats["by_state"].get(state, 0) + count
        
        return stats

    async def batch_update_state(
        self,
        tree_id: UUID,
        node_ids: List[str],
        new_state: str,
        changed_by: str | None = None,
    ) -> int:
        """批量更新节点状态."""
        query = (
            update(NodeModel)
            .where(
                NodeModel.tree_id == tree_id,
                NodeModel.node_id.in_(node_ids),
            )
            .values(state=new_state, updated_at=func.now())
        )
        result = await self.session.execute(query)
        return result.rowcount
```

### 6. 迁移脚本

```python
# src/opensquilla/asset_tree/db/migrations/001_initial.py
"""Initial schema migration."""

from yoyo import step

steps = [
    step("""
        CREATE EXTENSION IF NOT EXISTS "pgcrypto";
    """),
    step("""
        CREATE TABLE asset_trees (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            name VARCHAR(255) NOT NULL,
            root_domain VARCHAR(255) NOT NULL,
            description TEXT DEFAULT '',
            created_by VARCHAR(100),
            created_at TIMESTAMPTZ DEFAULT NOW(),
            updated_at TIMESTAMPTZ DEFAULT NOW(),
            is_deleted BOOLEAN DEFAULT FALSE
        );
        
        CREATE INDEX idx_trees_root_domain ON asset_trees(root_domain);
    """),
    step("""
        CREATE TABLE asset_nodes (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tree_id UUID NOT NULL REFERENCES asset_trees(id) ON DELETE CASCADE,
            parent_id UUID REFERENCES asset_nodes(id) ON DELETE SET NULL,
            node_id VARCHAR(100) NOT NULL,
            node_type VARCHAR(50) NOT NULL,
            title VARCHAR(500) DEFAULT '',
            state VARCHAR(50) DEFAULT 'unseen',
            url TEXT,
            asset_type VARCHAR(50),
            ip_address INET,
            meta JSONB DEFAULT '{}',
            created_at TIMESTAMPTZ DEFAULT NOW(),
            updated_at TIMESTAMPTZ DEFAULT NOW(),
            UNIQUE(tree_id, node_id),
            UNIQUE(tree_id, parent_id, node_id)
        );
        
        CREATE INDEX idx_nodes_tree ON asset_nodes(tree_id);
        CREATE INDEX idx_nodes_parent ON asset_nodes(parent_id);
        CREATE INDEX idx_nodes_type ON asset_nodes(tree_id, node_type);
        CREATE INDEX idx_nodes_state ON asset_nodes(tree_id, state);
        CREATE INDEX idx_nodes_meta ON asset_nodes USING GIN (meta);
        CREATE INDEX idx_nodes_ip ON asset_nodes(ip_address);
    """),
    step("""
        CREATE TABLE asset_audit_log (
            id BIGSERIAL PRIMARY KEY,
            tree_id UUID REFERENCES asset_trees(id),
            node_id UUID REFERENCES asset_nodes(id),
            action VARCHAR(50) NOT NULL,
            old_value JSONB,
            new_value JSONB,
            changed_by VARCHAR(100),
            changed_at TIMESTAMPTZ DEFAULT NOW()
        );
        
        CREATE INDEX idx_audit_tree ON asset_audit_log(tree_id);
        CREATE INDEX idx_audit_changed_at ON asset_audit_log(changed_at);
    """),
]
```

### 7. 使用示例

```python
# src/opensquilla/asset_tree/web/store_pg.py
from typing import Optional, List
from uuid import UUID

from ..db.session import get_db
from ..db.repository import TreeRepository
from ..models import AssetType, AssetState


class PgTreeStore:
    """PostgreSQL-backed tree store - 企业级实现."""

    def __init__(self):
        self.db = get_db()

    async def create_tree(
        self,
        root_domain: str,
        tree_id: Optional[str] = None,
        description: str = "",
    ) -> dict:
        async with self.db.session() as session:
            repo = TreeRepository(session)
            tree = await repo.create_tree(
                name=root_domain,
                root_domain=root_domain,
                description=description,
            )
            return {
                "id": str(tree.id),
                "root_domain": tree.root_domain,
                "description": tree.description,
                "created_at": tree.created_at.isoformat(),
            }

    async def add_node(
        self,
        tree_id: UUID,
        parent_id: Optional[UUID],
        node_id: str,
        node_type: str,
        title: str = "",
        state: str = "unseen",
        url: Optional[str] = None,
        meta: dict | None = None,
    ) -> dict:
        async with self.db.session() as session:
            repo = TreeRepository(session)
            node = await repo.create_node(
                tree_id=tree_id,
                node_id=node_id,
                node_type=node_type,
                parent_id=parent_id,
                title=title,
                state=state,
                url=url,
                meta=meta,
            )
            return {
                "id": str(node.id),
                "node_id": node.node_id,
                "node_type": node.node_type,
                "state": node.state,
            }

    async def explore_asset(
        self,
        tree_id: UUID,
        parent_id: Optional[UUID],
        domain: str,
        url: str,
        force: bool = False,
    ) -> dict:
        """探测资产并持久化."""
        async with self.db.session() as session:
            repo = TreeRepository(session)
            
            # 创建或获取节点
            node = await repo.get_node_by_tree_and_node_id(tree_id, domain)
            if node and not force:
                return {"id": str(node.id), "state": node.state, "cached": True}
            
            # 创建新节点
            if not node:
                node = await repo.create_node(
                    tree_id=tree_id,
                    node_id=domain,
                    node_type="sub_domain",
                    parent_id=parent_id,
                    title=domain,
                    state="discovered",
                    url=url,
                )
            else:
                await repo.update_node(node.id, state="discovered", url=url)
            
            return {"id": str(node.id), "state": "discovered", "cached": False}

    async def get_stats(self, tree_id: UUID) -> dict:
        async with self.db.session() as session:
            repo = TreeRepository(session)
            return await repo.get_tree_stats(tree_id)
```

---

需要我创建这些文件并配置迁移吗？
