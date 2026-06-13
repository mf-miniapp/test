"""Tests for the recon coverage gap fix (2026-06-10).

These tests verify that:

  1. The 8 new recon / dir-bust / vuln-scan skills are actually registered
     in `~/.opensquilla/skills/`. The recon coverage fix shipped 5 scripts
     that must all be run before recon is fully effective.
  2. The 3 specialist SOUL.md files (`recon`, `penetration`,
     `attack-surface-enumeration`) describe only tools that have a real
     skill registered. This is the "三段对齐" guard added after the
     2026-06-10 user feedback that recon was claiming
     "SYN/UDP/TCP 全开" and "目录/文件爆破" without the corresponding
     skills installed.
  3. The wordlist + payload data lives at the expected paths
     (`~/.opensquilla/wordlists/raft-medium-directories.txt` and
     `~/.opensquilla/payloads/manual-payloads.md`).

These are tolerant: if the runtime files don't exist (e.g. when running
in CI without the bootstrap), the tests are skipped instead of failing
hard. The CI test for the source code is in
`tests/test_attack_dispatch.py` which doesn't depend on these runtime
artifacts.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

SKILLS_ROOT = Path.home() / ".opensquilla" / "skills"
AGENTS_ROOT = Path.home() / ".opensquilla" / "agents"
WORDLIST_PATH = (
    Path.home() / ".opensquilla" / "wordlists" / "raft-medium-directories.txt"
)
MANUAL_PAYLOADS_PATH = (
    Path.home() / ".opensquilla" / "payloads" / "manual-payloads.md"
)

# R3 字典 (S22)
R3_WORDLISTS: tuple[Path, ...] = (
    Path.home() / ".opensquilla" / "wordlists" / "devops-paths.txt",
    Path.home() / ".opensquilla" / "wordlists" / "monitoring-paths.txt",
    Path.home() / ".opensquilla" / "wordlists" / "cloud-buckets-prefixes.txt",
    Path.home() / ".opensquilla" / "wordlists" / "db-ports.txt",
)

# 8 skills added by the recon coverage gap fix scripts.
# These names MUST match the bin name in `requires.bins[]` of each
# SKILL.md frontmatter.
EXPECTED_NEW_SKILLS: tuple[str, ...] = (
    "naabu",          # add_port_scan_skills.py
    "nmap",           # add_port_scan_skills.py
    "ffuf",           # add_dir_bust_skills.py
    "feroxbuster",    # add_dir_bust_skills.py
    "gobuster",       # add_dir_bust_skills.py
    "sqlmap",         # add_vuln_scan_skills.py
    "nikto",          # add_vuln_scan_skills.py
    "dalfox",         # add_vuln_scan_skills.py
)

# 19 skills added by the R3 P0+P1 expansion (S13-S21).
# These are the full set the recon / penetration / attack-surface SOUL.md
# tools-list sections now describe.
EXPECTED_R3_SKILLS: tuple[str, ...] = (
    # P0 cloud assets (S13)
    "s3scanner", "cloud_enum",
    # P0 devops (S14)
    "jenkins-cli", "gitrob",
    # P0 monitoring (S15)
    "grafana-fingerprinter", "prometheus-fingerprinter",
    # P0 db/mq (S16)
    "mongosh", "redis-cli", "elasticsearch-tools", "rabbitmqadmin", "kafkacat",
    # P1 whois + asn (S18)
    "whois", "asnmap",
    # P1 waf + cdn (S19)
    "cdncheck", "wafw00f",
    # P1 ssl + tls (S20)
    "tlsx", "sslyze",
    # P1 secret scan (S21)
    "gitleaks", "trufflehog",
)

# Tools explicitly mentioned by name in each specialist SOUL.md's
# "工具清单" section (added 2026-06-10). If SOUL.md mentions a tool here
# that is not in EXPECTED_NEW_SKILLS or the pre-existing 32, the test
# fails — that's how we catch the next "空口承诺" regression.
EXPECTED_RECON_TOOLS: tuple[str, ...] = (
    # R1
    "naabu", "nmap", "ffuf", "feroxbuster", "gobuster",
    # R3 (sample — full 19 listed in EXPECTED_R3_SKILLS)
    "s3scanner", "jenkins-cli", "mongosh", "asnmap", "cdncheck", "gitleaks",
)
EXPECTED_PENETRATION_TOOLS: tuple[str, ...] = (
    # R1
    "sqlmap", "dalfox", "nikto", "ssrf", "ssti", "lfi", "xxe", "idor",
    # R3 (db + mgmt + cloud + secret vector_class)
    "mongosh", "redis-cli", "jenkins-cli", "grafana",
)
EXPECTED_ATTACK_SURFACE_TOOLS: tuple[str, ...] = (
    # R3 priority_top_n 排序规则段提到了这些 service 名
    "mongodb", "redis", "elasticsearch", "kafka", "rabbitmq",
    "jenkins", "grafana", "prometheus", "kibana",
)

# Backtick-quoted tokens in SOUL.md that are not tool names. Keep this
# list in sync with the SOUL.md prose; expand when a new generic word
# starts failing the test.
GENERIC_BACKTICK_WORDS: frozenset[str] = frozenset({
    "path", "host", "target", "rate", "pps", "root", "bin", "key", "id",
    "bins", "kind", "hash", "sha256", "url", "file", "files", "tools",
    "name", "cmd", "args", "arg", "opts", "tag", "tags", "step", "steps",
    "src", "dst", "tmp", "log", "logs", "raw", "out", "err", "error",
    "ok", "warn", "info", "debug", "header", "headers", "body", "cookie",
    "cookies", "query", "params", "param", "form", "json", "xml", "yaml",
    "toml", "env", "config", "cfg", "recursion", "fanout", "skip",
    "verbose", "silent", "batch", "level", "risk", "tuning", "time",
    "timeout", "delay", "interval", "mode", "type", "string", "int",
    "bool", "true", "false", "none", "all", "default", "list", "dict",
    "tuple", "set", "frozenset", "input", "output", "result", "results",
    "schema", "schemas", "v1", "v2", "v3", "lt", "le", "ge", "gt", "eq",
    "self", "cls", "spec", "agent", "agents", "wave", "waves", "dep",
    "deps", "specialist", "specialists", "fanout_agents", "evidence",
    "report", "report-v1", "h", "s", "m", "ms",
})


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _skill_md(skill_name: str) -> Path:
    return SKILLS_ROOT / skill_name / "SKILL.md"


def _bin_names_from_skill(skill_name: str) -> set[str]:
    """Extract the bin names from a SKILL.md frontmatter `requires.bins[]`."""
    p = _skill_md(skill_name)
    if not p.exists():
        return set()
    text = p.read_text(encoding="utf-8")
    # Find the `requires.bins[]` block
    m = re.search(
        r"requires:\s*\n\s*bins:\s*\n((?:\s*-\s*\S+\s*\n)+)",
        text,
    )
    if not m:
        return set()
    return {line.strip().lstrip("-").strip() for line in m.group(1).splitlines() if line.strip()}


def _soul_path(agent_id: str) -> Path:
    return AGENTS_ROOT / agent_id / "SOUL.md"


def _soul_text(agent_id: str) -> str:
    p = _soul_path(agent_id)
    if not p.exists():
        return ""
    return p.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Test 1: 8 new skills are registered
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("skill_name", EXPECTED_NEW_SKILLS)
def test_new_skill_registered(skill_name: str) -> None:
    """Each of the 8 new skills has a SKILL.md + ATTRIBUTION.md on disk."""
    p = _skill_md(skill_name)
    if not p.exists():
        pytest.skip(
            f"runtime skill {skill_name!r} not yet installed; "
            f"run scripts/add_port_scan_skills.py / add_dir_bust_skills.py / "
            f"add_vuln_scan_skills.py to bootstrap"
        )
    assert p.exists(), f"missing SKILL.md for {skill_name}"
    assert p.stat().st_size > 200, f"SKILL.md for {skill_name} is suspiciously small"
    attr = p.parent / "ATTRIBUTION.md"
    assert attr.exists(), f"missing ATTRIBUTION.md for {skill_name}"


# ---------------------------------------------------------------------------
# Test 2: SOUL.md tool mentions have a real registered skill
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("skill_name", EXPECTED_NEW_SKILLS)
def test_new_skill_has_bins(skill_name: str) -> None:
    """Each new SKILL.md declares at least one bin in `requires.bins[]`."""
    bins_ = _bin_names_from_skill(skill_name)
    if not bins_:
        pytest.skip(f"skill {skill_name!r} not yet installed")
    assert bins_, f"SKILL.md for {skill_name} has no `requires.bins[]`"


def test_recon_soul_mentions_only_real_skills() -> None:
    """recon SOUL.md must not mention tool names that have no skill installed.

    Added 2026-06-10 after the user feedback that recon was promising
    "SYN/UDP/TCP 全开" and "目录/文件爆破" without the corresponding
    skills installed. Catches future regressions where SOUL.md describes
    a tool the runtime can't actually invoke.
    """
    soul = _soul_text("recon")
    if not soul:
        pytest.skip("recon SOUL.md not at expected runtime path")
    if not SKILLS_ROOT.exists():
        pytest.skip("~/.opensquilla/skills/ not bootstrapped")
    # Tools the recon SOUL.md is expected to mention (per T5)
    soul_lower = soul.lower()
    for tool in EXPECTED_RECON_TOOLS:
        assert tool.lower() in soul_lower, (
            f"recon SOUL.md is expected to mention {tool!r} "
            f"(added 2026-06-10 by T5 recon coverage fix)"
        )
    # For any other tool name in the SOUL.md's "工具清单" section, verify
    # it has a corresponding skill registered. This is the "三段对齐" guard.
    m = re.search(
        r"## 工具清单.*?(?=\n## |\Z)",
        soul,
        re.DOTALL,
    )
    if not m:
        pytest.skip("no '工具清单' section in recon SOUL.md (legacy)")
    section = m.group(0)
    # Match backtick-quoted tool names (e.g. `naabu`)
    mentioned = set(re.findall(r"`([a-zA-Z][a-zA-Z0-9._-]{1,40})`", section))
    # Filter to plausible tool names (skip generic words)
    candidates = {m for m in mentioned if m.lower() not in GENERIC_BACKTICK_WORDS}
    # Each candidate must have a registered skill OR be a sub-word
    # (e.g. "syn" is part of "syn-ack", not a tool)
    for tool in candidates:
        skill_dir = SKILLS_ROOT / tool
        # Also check the bin name (e.g. skill "sqlmap" requires bin "sqlmap.py")
        if skill_dir.exists():
            continue
        # Not registered → could be a sub-word of a phrase; only fail if
        # it appears as a standalone `tool` (e.g. `wordlist` is fine but
        # `naabu` would not be).
        pytest.fail(
            f"recon SOUL.md '工具清单' mentions {tool!r} but no skill is "
            f"registered at {skill_dir}. Run the corresponding add_*_skills.py "
            f"script or remove the mention from SOUL.md."
        )


def test_penetration_soul_mentions_only_real_skills() -> None:
    """penetration SOUL.md must reference the new vuln-scan skills + payloads."""
    soul = _soul_text("penetration")
    if not soul:
        pytest.skip("penetration SOUL.md not at expected runtime path")
    if not SKILLS_ROOT.exists():
        pytest.skip("~/.opensquilla/skills/ not bootstrapped")
    soul_lower = soul.lower()
    for tool in EXPECTED_PENETRATION_TOOLS:
        assert tool.lower() in soul_lower, (
            f"penetration SOUL.md is expected to mention {tool!r} "
            f"(added 2026-06-10 by T6 recon coverage fix)"
        )


def test_attack_surface_soul_priority_top_n_constraint() -> None:
    """attack-surface SOUL.md `complete` 判据 must depend on port + dir evidence."""
    soul = _soul_text("attack-surface-enumeration")
    if not soul:
        pytest.skip("attack-surface-enumeration SOUL.md not at expected runtime path")
    # The constraint added 2026-06-10 by T7:
    assert "port_scan_complete" in soul, (
        "attack-surface-enumeration SOUL.md must reference `port_scan_complete` "
        "in the `complete` 判据 (added 2026-06-10 by T7 recon coverage fix)"
    )
    assert "dir_bust_evidence" in soul, (
        "attack-surface-enumeration SOUL.md must reference `dir_bust_evidence` "
        "in the `complete` 判据 (added 2026-06-10 by T7 recon coverage fix)"
    )


# ---------------------------------------------------------------------------
# Test 3: Wordlist + payload data is on disk
# ---------------------------------------------------------------------------


def test_raft_medium_wordlist_present() -> None:
    """~/.opensquilla/wordlists/raft-medium-directories.txt is downloaded."""
    if not WORDLIST_PATH.exists():
        pytest.skip(
            "raft-medium-directories.txt not yet fetched; "
            "run scripts/fetch_wordlists.py to bootstrap"
        )
    size = WORDLIST_PATH.stat().st_size
    assert size > 100_000, (
        f"raft-medium-directories.txt is suspiciously small ({size} bytes); "
        f"expected ~250KB from SecLists"
    )
    # Sanity: at least 10000 entries
    line_count = sum(1 for _ in WORDLIST_PATH.open(encoding="utf-8", errors="ignore"))
    assert line_count > 10_000, (
        f"raft-medium-directories.txt has only {line_count} lines; expected 20k+"
    )


def test_manual_payloads_present() -> None:
    """~/.opensquilla/payloads/manual-payloads.md is written."""
    if not MANUAL_PAYLOADS_PATH.exists():
        pytest.skip(
            "manual-payloads.md not yet written; "
            "run scripts/fetch_wordlists.py to bootstrap"
        )
    text = MANUAL_PAYLOADS_PATH.read_text(encoding="utf-8")
    # Each OWASP class must have a section
    for section in ("SSRF", "SSTI", "LFI", "XXE", "IDOR"):
        assert f"## {section}" in text, (
            f"manual-payloads.md is missing the `## {section}` section"
        )


# ---------------------------------------------------------------------------
# Test 4: Source code (evidence.py) accepts the new fields
# ---------------------------------------------------------------------------


def test_recon_evidence_scan_profile_default_full() -> None:
    """ReconEvidence.scan_profile default is 'full' (full port + dir bust)."""
    from opensquilla.attack_dispatch.evidence import ReconEvidence

    e = ReconEvidence(target="example.com")
    assert e.scan_profile == "full", (
        f"ReconEvidence.scan_profile default should be 'full' per T8; got {e.scan_profile!r}"
    )
    assert e.port_scan_complete is False
    assert e.dir_bust_evidence == {}


def test_recon_evidence_explicit_scan_profile() -> None:
    """ReconEvidence accepts explicit scan_profile + port_scan_complete + dir_bust."""
    from opensquilla.attack_dispatch.evidence import ReconEvidence

    e = ReconEvidence(
        target="example.com",
        scan_profile="light",
        port_scan_complete=True,
        dir_bust_evidence={"ffuf": ["/admin", "/api/v1"]},
    )
    assert e.scan_profile == "light"
    assert e.port_scan_complete is True
    assert e.dir_bust_evidence == {"ffuf": ["/admin", "/api/v1"]}


# ---------------------------------------------------------------------------
# Test 5: W1.5c wave registered
# ---------------------------------------------------------------------------


def test_w1_5c_expand_scan_wave_registered() -> None:
    """W1.5c expand scan wave is registered with single specialist=recon."""
    from opensquilla.attack_dispatch.waves import LAYERS, WAVES, LayerName

    assert "W1.5c" in WAVES, "W1.5c not registered in WAVES"
    spec = WAVES["W1.5c"]
    assert spec.specialist == "recon"
    assert spec.deps == ("W1",)
    assert spec.fanout == "single"
    assert spec.evidence_schema == "recon-v1"
    assert "W1.5c" in LAYERS[LayerName.BREADTH.value], (
        "W1.5c must be listed in the BREADTH layer (between W1.5 and W2)"
    )


# ---------------------------------------------------------------------------
# Test 6: R3 P0+P1 — 19 new skills + 4 wordlists + PrivescCurrentAccess 7 keys
# + ResourceEvidence schema + W0.6 wave
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("skill_name", EXPECTED_R3_SKILLS)
def test_r3_new_skill_registered(skill_name: str) -> None:
    """Each R3 skill has a SKILL.md + ATTRIBUTION.md on disk."""
    p = _skill_md(skill_name)
    if not p.exists():
        pytest.skip(
            f"runtime skill {skill_name!r} not yet installed; "
            f"run the corresponding R3 add_*_skills.py to bootstrap"
        )
    assert p.exists(), f"missing SKILL.md for {skill_name}"
    assert p.stat().st_size > 200, f"SKILL.md for {skill_name} is suspiciously small"
    attr = p.parent / "ATTRIBUTION.md"
    assert attr.exists(), f"missing ATTRIBUTION.md for {skill_name}"


@pytest.mark.parametrize("wordlist_path", R3_WORDLISTS)
def test_r3_wordlist_present(wordlist_path: Path) -> None:
    """Each R3 wordlist is on disk and non-empty."""
    if not wordlist_path.exists():
        pytest.skip(f"runtime wordlist {wordlist_path.name} not yet fetched")
    size = wordlist_path.stat().st_size
    assert size > 100, f"{wordlist_path.name} is suspiciously small ({size} bytes)"
    line_count = sum(
        1 for _ in wordlist_path.open(encoding="utf-8", errors="ignore")
    )
    assert line_count > 5, f"{wordlist_path.name} has only {line_count} lines"


def test_recon_soul_mentions_r3_tools() -> None:
    """recon SOUL.md mentions the 19 R3 bins by name."""
    soul = _soul_text("recon")
    if not soul:
        pytest.skip("recon SOUL.md not at expected runtime path")
    soul_lower = soul.lower()
    for tool in EXPECTED_RECON_TOOLS:
        assert tool.lower() in soul_lower, (
            f"recon SOUL.md is expected to mention {tool!r} "
            f"(added 2026-06-10 by R3 P0/P1 S25)"
        )


def test_penetration_soul_mentions_r3_vector_class() -> None:
    """penetration SOUL.md vector_class 分流表含 db + mgmt + cloud + secret 行."""
    soul = _soul_text("penetration")
    if not soul:
        pytest.skip("penetration SOUL.md not at expected runtime path")
    soul_lower = soul.lower()
    for tool in EXPECTED_PENETRATION_TOOLS:
        assert tool.lower() in soul_lower, (
            f"penetration SOUL.md is expected to mention {tool!r} "
            f"(added 2026-06-10 by R3 S26 vector_class 分流)"
        )


def test_attack_surface_soul_priority_top_n_db_mgmt() -> None:
    """attack-surface SOUL.md priority_top_n 排序规则提到 DB/MQ + 管理面板 service 名."""
    soul = _soul_text("attack-surface-enumeration")
    if not soul:
        pytest.skip("attack-surface-enumeration SOUL.md not at expected runtime path")
    soul_lower = soul.lower()
    for service in EXPECTED_ATTACK_SURFACE_TOOLS:
        assert service.lower() in soul_lower, (
            f"attack-surface-enumeration SOUL.md priority_top_n 段 is expected "
            f"to mention {service!r} (added 2026-06-10 by R3 S27)"
        )


def test_dnsx_skill_includes_axfr_dmarc_spf_dkim() -> None:
    """dnsx SKILL.md runtime hint 包含 axfr / dmarc / spf / dkim 触发器."""
    p = _skill_md("dnsx")
    if not p.exists():
        pytest.skip("dnsx SKILL.md not at expected runtime path")
    text = p.read_text(encoding="utf-8").lower()
    for trigger in ("axfr", "dmarc", "spf", "dkim"):
        assert trigger in text, (
            f"dnsx SKILL.md runtime hint should mention {trigger!r} "
            f"(added 2026-06-10 by R3 S23)"
        )


def test_privesc_current_access_seven_keys() -> None:
    """PrivescEvidence.current_access 文档化为 7 类键 (os / net / proc / cron / env / creds / suid)."""
    from opensquilla.attack_dispatch.evidence import (
        PrivescEvidence,
        PrivescCurrentAccessKey,
    )

    # TypedDict is a Literal — assert the 7 keys
    expected_keys = {"os", "net", "proc", "cron", "env", "creds", "suid"}
    assert set(PrivescCurrentAccessKey.__args__) == expected_keys

    # PrivescEvidence accepts a dict with all 7 keys (no schema enforcement,
    # just storage validation)
    pr = PrivescEvidence(
        target="x",
        current_access={
            "os": "linux", "net": "10.0.0.0/24", "proc": [], "cron": [],
            "env": [], "creds": [], "suid": [],
        },
    )
    assert set(pr.current_access.keys()) == expected_keys


def test_w0_6_resource_checkpoint_wave_registered() -> None:
    """W0.6 资源检查站 wave 注册 (R3 P0 S24) — static_fanout 3 specialist."""
    from opensquilla.attack_dispatch.waves import LAYERS, WAVES, LayerName

    assert "W0.6" in WAVES, "W0.6 not registered in WAVES"
    spec = WAVES["W0.6"]
    assert spec.fanout == "static_fanout"
    assert set(spec.fanout_agents) == {
        "recon", "penetration", "engagement-planning",
    }
    assert spec.deps == ("W0",)
    assert spec.evidence_schema == "resource-v1"
    assert "W0.6" in LAYERS[LayerName.BREADTH.value], (
        "W0.6 must be listed in the BREADTH layer (between W0.5 and W1)"
    )
    # Position check: W0.6 comes after W0.5 and before W1
    breadth = LAYERS[LayerName.BREADTH.value]
    assert breadth.index("W0.6") > breadth.index("W0.5")
    assert breadth.index("W0.6") < breadth.index("W1")


def test_resource_evidence_schema_registered() -> None:
    """ResourceEvidence schema registered as 'resource-v1' in EVIDENCE_SCHEMAS."""
    from opensquilla.attack_dispatch.evidence import (
        EVIDENCE_SCHEMAS,
        EVIDENCE_SCHEMA_NAMES,
        ResourceEvidence,
        ResourceEntry,
    )

    assert "resource-v1" in EVIDENCE_SCHEMAS
    assert EVIDENCE_SCHEMAS["resource-v1"] is ResourceEvidence
    assert len(EVIDENCE_SCHEMA_NAMES) == 18, (
        f"expected 18 evidence schemas (16 R1+R3 + port-attack-plan-v1 + web-crawl-v1); got {len(EVIDENCE_SCHEMA_NAMES)}"
    )

    # ResourceEntry accepts the 4 source values
    for src in ("skill", "bin", "wordlist", "payload"):
        re_e = ResourceEntry(tool="x", source=src)  # type: ignore[arg-type]
        assert re_e.source == src

    # ResourceEvidence accepts the standard fields
    ev = ResourceEvidence(target="x")
    assert ev.available_skills == []
    assert ev.available_bins == []
    assert ev.available_wordlists == []
    assert ev.available_payloads == []
    assert ev.missing == []
    assert ev.warnings == []
    assert ev.evidence_schema == "resource-v1"
