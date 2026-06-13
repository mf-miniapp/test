#!/usr/bin/env python3
"""Add 2 port-scan skills to the MANAGED skills layer.

Target : ~/.opensquilla/skills/<name>/SKILL.md  +  ATTRIBUTION.md
Schema : same as scripts/add_web_attack_skills.py
          (name / description / always / triggers / provenance /
           metadata.opensquilla{risk, capabilities, requires.bins[],
           install[{kind:brew/uv/apt/go}]})

Idempotent: re-running refreshes SKILL.md + ATTRIBUTION.md in place
without raising. Safe to call as part of a `hack-deep` clone bootstrap.

Skills added (2026-06-10, recon coverage gap fix):
  naabu, nmap

Why these two and not masscan:
  - naabu: ProjectDiscovery ecosystem (consistent with subfinder/httpx/dnsx);
    raw SYN scanner, ~1-10x faster than nmap on full port range;
    needs CAP_NET_RAW (root) — fallback `-sT` (TCP connect) for non-root.
  - nmap: the de-facto standard for service version + OS fingerprint +
    NSE scripting; complements naabu's pure port discovery with deep
    service enumeration. Available in every package manager.

Out of scope (per user 2026-06-10):
  - masscan (functionally redundant with naabu + nmap; naabu is enough)
  - rustscan (subset of naabu capabilities)
  - zmap (research-grade, not in recon default stack)
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path

DST_ROOT = Path.home() / ".opensquilla" / "skills"
ATTRIBUTION_DATE = "2026-06-10"
UPSTREAM_NAABU = "https://github.com/projectdiscovery/naabu"
UPSTREAM_NMAP = "https://nmap.org"

NET = "network"
SHELL = "shell"
FS_R = "filesystem-read"


@dataclass(frozen=True)
class SkillMeta:
    name: str
    risk: str
    triggers: tuple[str, ...]
    bins: tuple[str, ...]
    capabilities: tuple[str, ...]
    install_brew: tuple[tuple[str, str], ...] = ()
    install_go: tuple[str, ...] = ()
    install_pip: tuple[str, ...] = ()
    install_apt: tuple[tuple[str, str], ...] = ()
    description: str = ""
    upstream_url: str = ""


# Order matches the delivery todo T1.
PORT_SCAN_SKILLS: tuple[SkillMeta, ...] = (
    SkillMeta(
        name="naabu",
        risk="medium",
        triggers=(
            "naabu",
            "端口扫描",
            "port scan",
            "SYN scan",
            "TCP connect",
            "全端口扫描",
            "full port scan",
        ),
        bins=("naabu",),
        capabilities=(SHELL, NET, FS_R),
        install_go=("github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",),
        install_brew=(("naabu", "naabu"),),
        description=(
            "Fast SYN/TCP port scanner from ProjectDiscovery. Default usage is "
            "`naabu -p- -rate 1000 -host <target>` for full 1-65535 sweep; pair with "
            "nmap `-sV` for service fingerprint. Requires CAP_NET_RAW (root) for SYN "
            "scan; fall back to `-sT` (TCP connect) when running unprivileged."
        ),
        upstream_url=UPSTREAM_NAABU,
    ),
    SkillMeta(
        name="nmap",
        risk="medium",
        triggers=(
            "nmap",
            "服务指纹",
            "service version",
            "OS detection",
            "NSE script",
            "端口 + 服务",
        ),
        bins=("nmap",),
        capabilities=(SHELL, NET, FS_R),
        install_brew=(("nmap", "nmap"),),
        install_apt=(("nmap", "nmap"),),
        description=(
            "De-facto standard port + service + OS scanner. Default usage is "
            "`nmap -sV -sC -O -p <ports> <host>` to enumerate services, run safe NSE "
            "scripts, and fingerprint OS. Pair with naabu's port list for full coverage: "
            "`naabu -p- -silent -host <target> | nmap -sV -sC -O -p- -iL -`. Slower than "
            "naabu but provides service version / banner / OS evidence that naabu cannot."
        ),
        upstream_url=UPSTREAM_NMAP,
    ),
)


# ---------------------------------------------------------------------------
# Frontmatter helpers (mirror add_web_attack_skills.py)
# ---------------------------------------------------------------------------


def yaml_escape(s: str) -> str:
    if re.search(r"[:#\n\"']", s):
        return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return s


def render_frontmatter(meta: SkillMeta) -> str:
    lines: list[str] = ["---"]
    lines.append(f"name: {meta.name}")
    lines.append(f"description: {yaml_escape(meta.description)}")
    lines.append("always: false")
    lines.append("triggers:")
    for t in meta.triggers:
        lines.append(f"  - {yaml_escape(t)}")
    lines.append("provenance:")
    lines.append("  origin: recon-coverage-gap-fix-2026-06-10")
    lines.append("  license: per-tool")
    if meta.upstream_url:
        lines.append(f"  upstream_url: {meta.upstream_url}")
    lines.append("  maintained_by: zlpc")
    lines.append("metadata:")
    lines.append("  opensquilla:")
    lines.append(f"    risk: {meta.risk}")
    if meta.capabilities:
        lines.append("    capabilities:")
        for c in meta.capabilities:
            lines.append(f"      - {c}")
    if meta.bins:
        lines.append("    requires:")
        lines.append("      bins:")
        for b in meta.bins:
            lines.append(f"        - {b}")
    if meta.install_brew or meta.install_go or meta.install_pip or meta.install_apt:
        lines.append("    install:")
        for formula, bin_name in meta.install_brew:
            lines.append("      - kind: brew")
            lines.append(f"        id: {formula}")
            lines.append(f"        formula: {formula}")
            lines.append("        bins:")
            lines.append(f"          - {bin_name}")
        for go_path in meta.install_go:
            bin_name = go_path.rsplit("/", 1)[-1]
            lines.append("      - kind: go")
            lines.append(f"        path: {go_path}")
            lines.append("        bins:")
            lines.append(f"          - {bin_name}")
        for mod in meta.install_pip:
            lines.append("      - kind: uv")
            lines.append(f"        module: {mod}")
            lines.append("        bins:")
            lines.append(f"          - {mod}")
        for pkg, bin_name in meta.install_apt:
            lines.append("      - kind: apt")
            lines.append(f"        package: {pkg}")
            lines.append("        bins:")
            lines.append(f"          - {bin_name}")
    lines.append("---")
    return "\n".join(lines) + "\n"


def render_body(meta: SkillMeta) -> str:
    """Render a short markdown body describing the skill purpose.

    Kept terse — the SKILL.md exists to be loaded by the orchestrator LLM,
    not as documentation. Detailed usage lives in each tool's upstream README.
    """
    trigger_str = ", ".join(repr(t) for t in meta.triggers)
    return (
        f"\n# {meta.name}\n\n"
        f"{meta.description}\n\n"
        f"**Triggers**: {trigger_str}\n\n"
        f"**Bins**: {', '.join(meta.bins) or '(none)'}\n\n"
        f"**Risk**: {meta.risk}\n\n"
        f"**Capabilities**: {', '.join(meta.capabilities) or '(none)'}\n\n"
        f"Added by `scripts/add_port_scan_skills.py` on {ATTRIBUTION_DATE} "
        f"as part of the recon coverage gap fix. See "
        f"`docs/delivery/recon-coverage-gap-fix.delivery-solution.md` for context.\n"
    )


def render_attribution(meta: SkillMeta) -> str:
    upstream = meta.upstream_url or "(see upstream project)"
    return (
        f"# Attribution — {meta.name}\n\n"
        f"Added on {ATTRIBUTION_DATE} as part of the recon coverage gap fix "
        f"(B-plan: port scan + dir bust + vuln scan).\n\n"
        f"- **Triggers**: {', '.join(repr(t) for t in meta.triggers)}\n"
        f"- **Bins**: {', '.join(meta.bins) or '(none)'}\n"
        f"- **Upstream reference**: {upstream}\n"
        f"- **Risk**: {meta.risk}\n"
        f"- **Maintainer**: zlpc\n\n"
        f"This skill is a thin OpenSquilla-side wrapper: the body describes "
        f"the trigger context and the bins the agent should call. The actual "
        f"implementation lives in the upstream CLI tool.\n"
    )


def write_skill(meta: SkillMeta) -> Path:
    dst = DST_ROOT / meta.name
    dst.mkdir(parents=True, exist_ok=True)
    (dst / "SKILL.md").write_text(
        render_frontmatter(meta) + render_body(meta), encoding="utf-8"
    )
    (dst / "ATTRIBUTION.md").write_text(render_attribution(meta), encoding="utf-8")
    return dst


def main() -> int:
    DST_ROOT.mkdir(parents=True, exist_ok=True)
    written: list[str] = []
    for meta in PORT_SCAN_SKILLS:
        dst = write_skill(meta)
        written.append(f"{meta.name} -> {dst}")
    print(f"OK  wrote {len(written)}  port-scan skills -> {DST_ROOT}")
    for line in written:
        print(f"     + {line}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
