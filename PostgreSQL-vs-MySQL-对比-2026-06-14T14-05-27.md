## PostgreSQL vs MySQL 对比

| 特性 | PostgreSQL | MySQL |
|------|-----------|-------|
| **JSON 支持** | ✅ JSONB 二进制存储 + GIN 索引 | ⚠️ JSON 类型，索引有限 |
| **递归查询 CTE** | ✅ 原生支持 | ✅ 8.0+ 支持 |
| **INET 类型** | ✅ 原生 IP 类型 | ❌ 需 VARCHAR |
| **数组类型** | ✅ 原生数组 | ❌ 需 JSON 模拟 |
| **全文搜索** | ✅ tsvector | ✅ FULLTEXT INDEX |
| **并发性能** | ✅ MVCC 无锁读 | ⚠️ 行锁，写多时竞争 |
| **窗口函数** | ✅ 完整支持 | ✅ 8.0+ 支持 |
| **物化视图** | ✅ 原生支持 | ❌ 需手动模拟 |
| **扩展生态** | ✅ PostGIS, pg_trgm 等 | ⚠️ 插件较少 |

---

## MySQL 适配方案

### 主要差异修改

```python
# src/opensquilla/asset_tree/db/models_mysql.py
from datetime import datetime
from typing import Optional, List
from uuid import UUID, uuid4

from sqlalchemy import (
    String, Text, Boolean, DateTime, ForeignKey, Index, UniqueConstraint, JSON
)
from sqlalchemy.dialects.mysql import VARCHAR, INTEGER
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class TreeModel(Base):
    """资产树元数据表 (MySQL)."""
    __tablename__ = "asset_trees"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    root_domain: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, default="")
    created_by: Mapped[Optional[str]] = mapped_column(String(100))
    created_at: Mapped[datetime] = mapped_column(DateTime(fsp=6), default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(fsp=6), default=datetime.utcnow, onupdate=datetime.utcnow)
    is_deleted: Mapped[bool] = mapped_column(Boolean, default=False)

    nodes: Mapped[List["NodeModel"]] = relationship(back_populates="tree", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_trees_root_domain", "root_domain"),
    )


class NodeModel(Base):
    """资产节点表 (MySQL) - 使用闭包表或邻接表模拟树形查询."""
    __tablename__ = "asset_nodes"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    tree_id: Mapped[UUID] = mapped_column(ForeignKey("asset_trees.id", ondelete="CASCADE"), nullable=False)
    parent_id: Mapped[Optional[UUID]] = mapped_column(ForeignKey("asset_nodes.id", ondelete="SET NULL"))
    
    # 节点路径 (MySQL 特有: 物化路径便于快速查询)
    path: Mapped[Optional[str]] = mapped_column(String(1000), default="/")
    
    # 节点标识
    node_id: Mapped[str] = mapped_column(String(100), nullable=False)
    node_type: Mapped[str] = mapped_column(String(50), nullable=False)
    
    # 核心属性
    title: Mapped[Optional[str]] = mapped_column(String(500), default="")
    state: Mapped[str] = mapped_column(String(50), default="unseen")
    url: Mapped[Optional[str]] = mapped_column(Text)
    asset_type: Mapped[Optional[str]] = mapped_column(String(50))
    ip_address: Mapped[Optional[str]] = mapped_column(String(45))  # IPv6 最长 45 字符
    
    # 元数据 (MySQL JSON)
    meta: Mapped[dict] = mapped_column(JSON, default=dict)
    
    # 时间戳
    created_at: Mapped[datetime] = mapped_column(DateTime(fsp=6), default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(fsp=6), default=datetime.utcnow, onupdate=datetime.utcnow)

    tree: Mapped["TreeModel"] = relationship(back_populates="nodes")
    parent: Mapped[Optional["NodeModel"]] = relationship(remote_side=[id], back_populates="children")
    children: Mapped[List["NodeModel"]] = relationship(back_populates="parent")

    __table_args__ = (
        UniqueConstraint("tree_id", "node_id", name="uq_tree_node_id"),
        Index("idx_nodes_tree", "tree_id"),
        Index("idx_nodes_parent", "parent_id"),
        Index("idx_nodes_path", "path"),
        Index("idx_nodes_type", "tree_id", "node_type"),
        Index("idx_nodes_state", "tree_id", "state"),
    )
```

### MySQL 专用查询

```python
# src/opensquilla/asset_tree/db/repository_mysql.py
from sqlalchemy import text
from .repository import TreeRepository


class MySQLTreeRepository(TreeRepository):
    """MySQL 特定实现."""

    async def get_full_tree(self, tree_id: str) -> list[dict]:
        """MySQL 递归查询."""
        query = text("""
            WITH RECURSIVE tree AS (
                SELECT id, tree_id, parent_id, node_id, node_type, 
                       title, state, url, asset_type, ip_address, meta,
                       path, created_at, updated_at
                FROM asset_nodes 
                WHERE parent_id IS NULL AND tree_id = :tree_id
                UNION ALL
                SELECT n.id, n.tree_id, n.parent_id, n.node_id, n.node_type,
                       n.title, n.state, n.url, n.asset_type, n.ip_address, n.meta,
                       n.path, n.created_at, n.updated_at
                FROM asset_nodes n
                JOIN tree t ON n.parent_id = t.id
            )
            SELECT * FROM tree ORDER BY path
        """)
        result = await self.session.execute(query, {"tree_id": tree_id})
        return [dict(row._mapping) for row in result]

    async def get_descendants_by_path(self, tree_id: str, path_prefix: str) -> list[dict]:
        """MySQL: 使用 LIKE 查询路径前缀 (性能依赖索引)."""
        query = text("""
            SELECT * FROM asset_nodes
            WHERE tree_id = :tree_id 
              AND path LIKE :path_prefix
            ORDER BY path
        """)
        result = await self.session.execute(
            query, {"tree_id": tree_id, "path_prefix": f"{path_prefix}%"}
        )
        return [dict(row._mapping) for row in result]

    async def update_node_path(self, node_id: str, new_path: str) -> bool:
        """更新节点路径 (级联更新子节点)."""
        query = text("""
            UPDATE asset_nodes 
            SET path = CONCAT(:new_path, SUBSTRING(path, LENGTH(:old_path) + 1))
            WHERE path LIKE :old_path_prefix
        """)
        # 需要先获取旧路径
        node = await self.get_node(node_id)
        if not node:
            return False
        
        old_path = node.path or "/"
        await self.session.execute(
            query,
            {
                "new_path": new_path,
                "old_path": old_path,
                "old_path_prefix": f"{old_path}%",
            },
        )
        return True
```

---

## 配置差异

```python
# src/opensquilla/asset_tree/db/config.py
from pydantic_settings import BaseSettings

class DatabaseSettings(BaseSettings):
    # PostgreSQL
    # DB_URL: str = "postgresql+asyncpg://user:pass@localhost:5432/opensquilla"
    
    # MySQL
    DB_URL: str = "mysql+aiomysql://user:pass@localhost:3306/opensquilla"
    
    DB_POOL_SIZE: int = 20
    DB_MAX_OVERFLOW: int = 30
```

---

## 迁移脚本 (MySQL)

```sql
-- 001_initial_mysql.sql
CREATE TABLE IF NOT EXISTS asset_trees (
    id CHAR(36) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    root_domain VARCHAR(255) NOT NULL,
    description TEXT,
    created_by VARCHAR(100),
    created_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    is_deleted TINYINT(1) DEFAULT 0,
    INDEX idx_trees_root_domain (root_domain)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS asset_nodes (
    id CHAR(36) PRIMARY KEY,
    tree_id CHAR(36) NOT NULL,
    parent_id CHAR(36),
    path VARCHAR(1000) DEFAULT '/',
    node_id VARCHAR(100) NOT NULL,
    node_type VARCHAR(50) NOT NULL,
    title VARCHAR(500) DEFAULT '',
    state VARCHAR(50) DEFAULT 'unseen',
    url TEXT,
    asset_type VARCHAR(50),
    ip_address VARCHAR(45),
    meta JSON,
    created_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_tree_node_id (tree_id, node_id),
    INDEX idx_nodes_tree (tree_id),
    INDEX idx_nodes_parent (parent_id),
    INDEX idx_nodes_path (path(100)),
    INDEX idx_nodes_type (tree_id, node_type),
    INDEX idx_nodes_state (tree_id, state),
    FOREIGN KEY (tree_id) REFERENCES asset_trees(id) ON DELETE CASCADE,
    FOREIGN KEY (parent_id) REFERENCES asset_nodes(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

---

## 总结建议

| 场景 | 推荐 |
|------|------|
| 新项目、JSON 查询多 | **PostgreSQL** |
| 已有 MySQL 基础设施 | **MySQL** |
| 需要复杂树查询 | **PostgreSQL** |
| 简单 CRUD 为主 | **MySQL** |
| 需要全文搜索 | 两者皆可 |
| 高并发写入 | **PostgreSQL** (MVCC) |

需要我实现 MySQL 版本的完整代码吗？
