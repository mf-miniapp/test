"""v6 (2026-06-19) attack-paths CLI 单测。

覆盖:
  - 注册到主 typer app
  - attack-paths run --help 可调用
  - attack-paths list --help 可调用
  - tree 不存在时返回 exit code 2
  - dry-run 模式 (用 InlineDispatcher 走通)
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from typer.testing import CliRunner

from opensquilla.asset_tree.db import backend as _be_mod
from opensquilla.cli.main import app
from opensquilla.cli.attack_paths_cmd import attack_paths_app
from tests._stubs.in_memory_backend import InMemoryStubBackend


runner = CliRunner()


@pytest.fixture()
def backend(monkeypatch):
    be = InMemoryStubBackend()
    _be_mod.set_default_backend(be)
    return be


class TestCLIRegistration:
    def test_attack_paths_subcommand_registered(self):
        # 找 attack-paths group
        group_names = [g.name for g in app.registered_groups]
        assert "attack-paths" in group_names

    def test_run_help(self):
        result = runner.invoke(attack_paths_app, ["run", "--help"])
        assert result.exit_code == 0
        assert "Run v6 attack-path orchestrator" in result.stdout

    def test_list_help(self):
        result = runner.invoke(attack_paths_app, ["list", "--help"])
        assert result.exit_code == 0
        assert "List attack paths" in result.stdout


class TestCLIRun:
    def test_run_nonexistent_tree(self, backend, monkeypatch):
        # patch TreeStore.get_tree to raise KeyError
        from opensquilla.asset_tree.web import store as _store
        real_get_tree = _store.TreeStore.get_tree

        async def _raise(self, tree_id):
            raise KeyError(f"Tree '{tree_id}' not found")
        monkeypatch.setattr(_store.TreeStore, "get_tree", _raise)

        result = runner.invoke(attack_paths_app, [
            "run", "tree-missing", "--dry-run",
        ])
        assert result.exit_code == 2
        assert "not found" in result.stdout

    def test_run_dry_run_with_data(self, backend, monkeypatch):
        # 建树 + 写 backend
        from opensquilla.asset_tree.tree import AssetTree
        from opensquilla.asset_tree.models import AssetType

        async def setup():
            tree = AssetTree("example.com", tree_id="tree-test")
            sub = tree.add_node(AssetType.SUB_DOMAIN, "a.example.com",
                                parent_id=tree.root_id, allow_unverified=True)
            ip = tree.add_node(AssetType.IP, "1.1.1.1", parent_id=sub,
                               allow_unverified=True)
            port = tree.add_node(AssetType.PORT, "443", parent_id=ip,
                                 allow_unverified=True)
            svc = tree.add_node(AssetType.SERVICE, "HTTPS", parent_id=port,
                                 allow_unverified=True)
            url = tree.add_node(AssetType.URL, "https://a.example.com",
                                parent_id=svc, allow_unverified=True)
            ep = tree.add_node(AssetType.ENDPOINT, "/api", parent_id=url,
                                allow_unverified=True)
            leaf = tree.add_node(AssetType.PARAMETER, "q", parent_id=ep,
                                 allow_unverified=True)
            # 写 backend (用 add_node + upsert_tree)
            await backend.upsert_tree(
                tree_id="tree-test", root_domain="example.com",
                root_node_id=tree.root_id,
            )
            # 把所有 node 写入
            from opensquilla.asset_tree.web import store as _store
            real = _store.TreeStore.get_tree

            async def fake_get_tree(self, tree_id):
                if tree_id != "tree-test":
                    raise KeyError(f"Tree '{tree_id}' not found")
                return tree
            monkeypatch.setattr(_store.TreeStore, "get_tree", fake_get_tree)
            return tree
        asyncio.run(setup())

        result = runner.invoke(attack_paths_app, [
            "run", "tree-test", "--dry-run",
        ])
        # dry_run = True → 不调 dispatcher, 只生成 paths
        assert result.exit_code == 0
        assert "path_count" in result.stdout or "completed" in result.stdout
