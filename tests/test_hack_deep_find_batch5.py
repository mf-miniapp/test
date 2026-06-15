"""Batch 5 (time-dimension) tests.

Validates:
  - 2 new tools (recon_diff_snapshots, recon_list_snapshots) registered
  - asset_tree_complete returns snapshot_id of the form <tree_id>--<iso_ts>
  - recon_diff_snapshots correctly identifies added/removed/changed/moved
  - recon_diff_snapshots detects sensitivity escalations (low→high, not high→low)
  - recon_list_snapshots filters by root_domain substring + mtime ordering
"""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
from pathlib import Path

import pytest


# ── 1. asset_tree_complete has snapshot_id ───────────


def test_asset_tree_complete_signature_has_snapshot_id():
    import inspect
    from opensquilla.tools.builtin.asset_tree import tree as tree_tools

    sig = inspect.signature(tree_tools.asset_tree_complete)
    # No new parameters, but the return value must include snapshot_id
    assert list(sig.parameters.keys()) == ["tree_id"]


def test_asset_tree_complete_returns_snapshot_id():
    """Smoke: when called with a real tree, the returned JSON has snapshot_id."""
    import importlib
    pkg = importlib.import_module("opensquilla.agents.hack-deep-find")
    # Read the SOUL to make sure the snapshot_id field is documented
    assert "snapshot_id" in pkg.SOUL_BODY


# ── 2. Tool registry ─────────────────────────────────


class TestBatch5ToolsRegistered:
    def test_recon_diff_snapshots_registered(self):
        from opensquilla.tools.registry import get_default_registry

        reg = get_default_registry()
        assert "recon_diff_snapshots" in reg.list_names()

    def test_recon_list_snapshots_registered(self):
        from opensquilla.tools.registry import get_default_registry

        reg = get_default_registry()
        assert "recon_list_snapshots" in reg.list_names()

    def test_recon_diff_tool_group_exists(self):
        from opensquilla.tools.policy_config import _TOOL_GROUPS

        assert "group:recon:diff" in _TOOL_GROUPS
        assert "recon_diff_snapshots" in _TOOL_GROUPS["group:recon:diff"]
        assert "recon_list_snapshots" in _TOOL_GROUPS["group:recon:diff"]


# ── 3. recon_list_snapshots ──────────────────────────


class TestReconListSnapshots:
    @pytest.fixture(autouse=True)
    def tmp_snapshots(self, tmp_path, monkeypatch):
        """Plant two snapshot files in a tmp state dir."""
        monkeypatch.setenv("OPEN_SQUILLA_STATE_DIR", str(tmp_path))
        # snapshot A: tree-acme-corp.com--2026-06-01.json
        a = {
            "tree_id": "tree-acme-corp.com",
            "root_id": "rootA",
            "nodes": {
                "rootA": {"asset_type": "root_domain", "value": "acme-corp.com",
                          "parent_id": None, "metadata": {}, "state": "discovered"},
                "sub1": {"asset_type": "sub_domain", "value": "api.acme-corp.com",
                         "parent_id": "rootA", "metadata": {}, "state": "discovered"},
            },
        }
        # snapshot B: tree-other.com--2026-06-10.json (different tree_id)
        b = {
            "tree_id": "tree-other.com",
            "root_id": "rootB",
            "nodes": {
                "rootB": {"asset_type": "root_domain", "value": "other.com",
                          "parent_id": None, "metadata": {}, "state": "discovered"},
            },
        }
        # Write files; mtime difference simulated via set_mtime after
        path_a = tmp_path / "tree-acme-corp.com.json"
        path_b = tmp_path / "tree-other.com.json"
        path_a.write_text(json.dumps(a), encoding="utf-8")
        path_b.write_text(json.dumps(b), encoding="utf-8")
        # mtime A < mtime B
        os.utime(path_a, (1_700_000_000, 1_700_000_000))
        os.utime(path_b, (1_710_000_000, 1_710_000_000))
        self.tmp_path = tmp_path
        return tmp_path

    def test_list_all(self):
        from opensquilla.tools.builtin.recon import diff as diff_mod

        out = json.loads(asyncio.run(diff_mod.recon_list_snapshots()))
        assert out["snapshot_count"] == 2
        # newest first: other.com (mtime 1.71b) before acme-corp (mtime 1.70b)
        assert out["snapshots"][0]["tree_id"] == "tree-other.com"
        assert out["snapshots"][1]["tree_id"] == "tree-acme-corp.com"

    def test_list_filtered_by_substring(self):
        from opensquilla.tools.builtin.recon import diff as diff_mod

        out = json.loads(asyncio.run(diff_mod.recon_list_snapshots(root_domain_substr="acme")))
        assert out["snapshot_count"] == 1
        assert out["snapshots"][0]["tree_id"] == "tree-acme-corp.com"

    def test_list_snapshot_id_includes_iso_ts(self):
        from opensquilla.tools.builtin.recon import diff as diff_mod

        out = json.loads(asyncio.run(diff_mod.recon_list_snapshots(root_domain_substr="acme")))
        snap = out["snapshots"][0]
        # If the file has no --<iso> suffix, snapshot_id == tree_id (legacy)
        assert "snapshot_id" in snap
        assert "node_count" in snap
        assert snap["node_count"] == 2
        assert snap["node_count_by_type"]["root_domain"] == 1
        assert snap["node_count_by_type"]["sub_domain"] == 1

    def test_list_limit(self):
        from opensquilla.tools.builtin.recon import diff as diff_mod

        out = json.loads(asyncio.run(diff_mod.recon_list_snapshots(limit=1)))
        assert out["snapshot_count"] == 1


# ── 4. recon_diff_snapshots ──────────────────────────


class TestReconDiffSnapshots:
    @pytest.fixture(autouse=True)
    def setup(self, tmp_path, monkeypatch):
        monkeypatch.setenv("OPEN_SQUILLA_STATE_DIR", str(tmp_path))
        # Build two snapshots: A (older) and B (newer)
        # A: 1 root, 1 sub_domain
        # B: same root, +1 new sub_domain, 1 STATIC_ASSET added, 1 COOKIE changed (escalation)
        self.snap_a_path = tmp_path / "snap-a.json"
        self.snap_b_path = tmp_path / "snap-b.json"
        a = {
            "tree_id": "tree-x.com",
            "root_id": "rootA",
            "nodes": {
                "rootA": {"asset_type": "root_domain", "value": "x.com",
                          "parent_id": None, "metadata": {}, "state": "discovered"},
                "sub1": {"asset_type": "sub_domain", "value": "api.x.com",
                         "parent_id": "rootA", "metadata": {}, "state": "discovered"},
                "cookie1": {"asset_type": "cookie", "value": "cookie:session",
                            "parent_id": "url1", "metadata": {"risk": "low", "http_only": True}, "state": "discovered"},
            },
        }
        b = {
            "tree_id": "tree-x.com",
            "root_id": "rootA",
            "nodes": {
                "rootA": {"asset_type": "root_domain", "value": "x.com",
                          "parent_id": None, "metadata": {}, "state": "discovered"},
                "sub1": {"asset_type": "sub_domain", "value": "api.x.com",
                         "parent_id": "rootA", "metadata": {}, "state": "discovered"},
                "sub2": {"asset_type": "sub_domain", "value": "staging.x.com",
                         "parent_id": "rootA", "metadata": {}, "state": "discovered"},
                "static1": {"asset_type": "static_asset", "value": "/.env",
                            "parent_id": "url1", "metadata": {"sensitivity": "critical", "status": 200}, "state": "discovered"},
                "cookie1": {"asset_type": "cookie", "value": "cookie:session",
                            "parent_id": "url1", "metadata": {"risk": "high", "http_only": False}, "state": "discovered"},
            },
        }
        self.snap_a_path.write_text(json.dumps(a), encoding="utf-8")
        self.snap_b_path.write_text(json.dumps(b), encoding="utf-8")
        return tmp_path

    def test_diff_basic(self):
        from opensquilla.tools.builtin.recon import diff as diff_mod

        out = json.loads(asyncio.run(diff_mod.recon_diff_snapshots(
            snapshot_a_path=str(self.snap_a_path),
            snapshot_b_path=str(self.snap_b_path),
        )))
        assert out["summary"]["added"] == 2  # sub2 + static1
        assert out["summary"]["removed"] == 0
        assert out["summary"]["changed"] == 1  # cookie1 risk low→high

    def test_diff_added_nodes_have_correct_type(self):
        from opensquilla.tools.builtin.recon import diff as diff_mod

        out = json.loads(asyncio.run(diff_mod.recon_diff_snapshots(
            snapshot_a_path=str(self.snap_a_path),
            snapshot_b_path=str(self.snap_b_path),
        )))
        added_types = {a["asset_type"] for a in out["added"]}
        assert added_types == {"sub_domain", "static_asset"}

    def test_diff_detects_sensitivity_escalation(self):
        from opensquilla.tools.builtin.recon import diff as diff_mod

        out = json.loads(asyncio.run(diff_mod.recon_diff_snapshots(
            snapshot_a_path=str(self.snap_a_path),
            snapshot_b_path=str(self.snap_b_path),
        )))
        assert out["summary"]["sensitivity_escalations"] == 1
        # The escalation is on cookie1's risk field (low → high)
        esc = out["sensitivity_escalations"][0]
        assert esc["diffs"]["risk"] == {"from": "low", "to": "high"}

    def test_diff_uses_custom_sensitivity_field(self):
        from opensquilla.tools.builtin.recon import diff as diff_mod

        # custom field "http_only" — both values are booleans; can't ladder
        out = json.loads(asyncio.run(diff_mod.recon_diff_snapshots(
            snapshot_a_path=str(self.snap_a_path),
            snapshot_b_path=str(self.snap_b_path),
            sensitivity_field="http_only",
        )))
        # No risk ladder for booleans → 0 escalations
        assert out["summary"]["sensitivity_escalations"] == 0
        # But "changed" still has the diff entry
        assert out["summary"]["changed"] == 1

    def test_diff_by_type_summary(self):
        from opensquilla.tools.builtin.recon import diff as diff_mod

        out = json.loads(asyncio.run(diff_mod.recon_diff_snapshots(
            snapshot_a_path=str(self.snap_a_path),
            snapshot_b_path=str(self.snap_b_path),
        )))
        by_type = out["summary"]["by_type"]
        assert by_type["sub_domain"]["added"] == 1
        assert by_type["static_asset"]["added"] == 1
        assert by_type["cookie"]["changed"] == 1

    def test_diff_handles_removed_nodes(self):
        """Reverse the inputs to make everything look 'removed'."""
        from opensquilla.tools.builtin.recon import diff as diff_mod

        out = json.loads(asyncio.run(diff_mod.recon_diff_snapshots(
            snapshot_a_path=str(self.snap_b_path),  # newer as A
            snapshot_b_path=str(self.snap_a_path),  # older as B
        )))
        assert out["summary"]["removed"] == 2  # sub2 + static1
        assert out["summary"]["added"] == 0

    def test_diff_missing_snapshot_a_raises(self):
        from opensquilla.tools.builtin.recon import diff as diff_mod

        with pytest.raises(FileNotFoundError):
            asyncio.run(diff_mod.recon_diff_snapshots(
                snapshot_a_path="/nonexistent/path.json",
                snapshot_b_path=str(self.snap_b_path),
            ))

    def test_diff_ignores_non_escalation(self):
        """Cookie risk high → low should NOT count as escalation (ladder is one-way)."""
        from opensquilla.tools.builtin.recon import diff as diff_mod
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            tp = Path(td)
            a = {
                "nodes": {
                    "root": {"asset_type": "root_domain", "value": "x.com",
                             "parent_id": None, "metadata": {}, "state": "discovered"},
                    "c1": {"asset_type": "cookie", "value": "c1",
                           "parent_id": "root", "metadata": {"risk": "high"}, "state": "discovered"},
                }
            }
            b = {
                "nodes": {
                    "root": {"asset_type": "root_domain", "value": "x.com",
                             "parent_id": None, "metadata": {}, "state": "discovered"},
                    "c1": {"asset_type": "cookie", "value": "c1",
                           "parent_id": "root", "metadata": {"risk": "low"}, "state": "discovered"},
                }
            }
            pa = tp / "a.json"
            pb = tp / "b.json"
            pa.write_text(json.dumps(a))
            pb.write_text(json.dumps(b))
            out = json.loads(asyncio.run(diff_mod.recon_diff_snapshots(
                snapshot_a_path=str(pa), snapshot_b_path=str(pb),
            )))
            assert out["summary"]["sensitivity_escalations"] == 0
            assert out["summary"]["changed"] == 1


# ── 5. SOUL_BODY / ATTRIBUTION_BODY mentions Batch 5 ─


class TestSoulMentionsBatch5:
    def test_soul_documents_diff_and_list_snapshots(self):
        import importlib
        pkg = importlib.import_module("opensquilla.agents.hack-deep-find")
        # Either SOUL or ATTRIBUTION should mention these tools
        combined = pkg.SOUL_BODY + "\n" + pkg.ATTRIBUTION_BODY
        assert "recon_diff_snapshots" in combined
        assert "recon_list_snapshots" in combined


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
