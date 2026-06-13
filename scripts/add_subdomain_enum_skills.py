#!/usr/bin/env python3
"""Add 9 subdomain-enumeration skills to the MANAGED skills layer.

Target : ~/.opensquilla/skills/<name>/SKILL.md  +  ATTRIBUTION.md
Schema : same as scripts/migrate_cyberstrikeai_skills.py
          (name / description / always / triggers / provenance /
           metadata.opensquilla{risk, capabilities, requires.bins[],
           install[{kind:brew/uv,...}]})

Idempotent: re-running refreshes SKILL.md + ATTRIBUTION.md in place
without raising. Safe to call as part of a `hack-deep` clone bootstrap.

Skills added (2026-06-07, hack-deep multi-target expansion):
  subfinder, assetfinder, chaos, shuffledns, dnsx, httpx,
  subjack, cero, github-subdomains
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path

DST_ROOT = Path.home() / ".opensquilla" / "skills"
ATTRIBUTION_DATE = "2026-06-07"
UPSTREAM = "https://github.com/projectdiscovery"


@dataclass(frozen=True)
class SkillMeta:
    name: str
    risk: str
    triggers: tuple[str, ...]
    bins: tuple[str, ...]
    capabilities: tuple[str, ...]
    install_brew: tuple[tuple[str, str], ...] = ()
    install_go: tuple[str, ...] = ()  # go install path (e.g. github.com/...)
    install_pip: tuple[str, ...] = ()
    description: str = ""


NET = "network"
SHELL = "shell"
FS_R = "filesystem-read"
HTTP_O = "network.http"


# Order matches the delivery todo T15.
SUBDOMAIN_SKILLS: tuple[SkillMeta, ...] = (
    SkillMeta(
        name="subfinder",
        risk="low",
        triggers=("子域枚举", "subdomain enumeration", "subfinder", "被动枚举", "passive enum"),
        bins=("subfinder",),
        capabilities=(SHELL, NET, HTTP_O, FS_R),
        install_go=("github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",),
        description="Passive subdomain enumeration via 30+ online sources (Shodan, Censys, CT logs, DNSdumpster, etc.). Use as the first-pass discovery tool for any recon wave.",
    ),
    SkillMeta(
        name="assetfinder",
        risk="low",
        triggers=("assetfinder", "子域查找", "资产查找", "asset discovery"),
        bins=("assetfinder",),
        capabilities=(SHELL, NET, HTTP_O, FS_R),
        install_go=("github.com/tomnomnom/assetfinder@latest",),
        description="Lightweight passive subdomain / asset finder from tomnomnom. Complements subfinder when the target has a smaller surface.",
    ),
    SkillMeta(
        name="chaos",
        risk="low",
        triggers=("chaos", "chaos-client", "projectdiscovery chaos", "CDN 数据集"),
        bins=("chaos",),
        capabilities=(SHELL, NET, HTTP_O, FS_R),
        install_go=("github.com/projectdiscovery/chaos-client/cmd/chaos@latest",),
        description="ProjectDiscovery's curated dataset of internet-wide DNS assets. Useful for breadth-first asset inventory in hack-deep W0.5 / W1.5.",
    ),
    SkillMeta(
        name="shuffledns",
        risk="medium",
        triggers=("shuffledns", "字典爆破", "active enumeration", "subdomain bruteforce"),
        bins=("shuffledns", "massdns"),
        capabilities=(SHELL, NET, FS_R),
        install_go=("github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest",),
        description="MassDNS-powered active subdomain enumeration with permutation and resolution. Pairs with subfinder for full coverage.",
    ),
    SkillMeta(
        name="dnsx",
        risk="low",
        triggers=("dnsx", "DNS 探测", "DNS probe", "DNS resolution check"),
        bins=("dnsx",),
        capabilities=(SHELL, NET, FS_R),
        install_go=("github.com/projectdiscovery/dnsx/cmd/dnsx@latest",),
        description="Fast and multi-purpose DNS toolkit. Used for resolving candidate subdomains and probing DNS records en masse.",
    ),
    SkillMeta(
        name="httpx",
        risk="low",
        triggers=("httpx", "HTTP 探测", "HTTP probe", "alive host check", "tech stack probe"),
        bins=("httpx",),
        capabilities=(SHELL, NET, HTTP_O, FS_R),
        install_go=("github.com/projectdiscovery/httpx/cmd/httpx@latest",),
        description="Fast HTTP prober with tech-stack / status / title / TLS detection. Pairs with dnsx output to identify live web hosts in W1 recon.",
    ),
    SkillMeta(
        name="subjack",
        risk="medium",
        triggers=("subjack", "subdomain takeover", "子域接管", "CNAME takeover"),
        bins=("subjack",),
        capabilities=(SHELL, NET, FS_R),
        install_go=("github.com/haccer/subjack@latest",),
        description="Subdomain takeover vulnerability scanner. Checks dangling CNAMEs against known fingerprinted services.",
    ),
    SkillMeta(
        name="cero",
        risk="medium",
        triggers=("cero", "subdomain takeover", "子域接管", "Go takeover scanner"),
        bins=("cero",),
        capabilities=(SHELL, NET, HTTP_O, FS_R),
        install_go=("github.com/glebarez/cero@latest",),
        description="Modern Go-based subdomain takeover scanner. Faster and more accurate than subjack; checks additional services.",
    ),
    SkillMeta(
        name="github-subdomains",
        risk="low",
        triggers=("github-subdomains", "github recon", "代码搜索子域", "git dorking"),
        bins=("github-subdomains", "git"),
        capabilities=(SHELL, NET, HTTP_O, FS_R),
        install_go=("github.com/gwen001/github-subdomains@latest",),
        description="Enumerate subdomains by scraping GitHub code search results. Catches leaked internal subdomains not indexed by other passive tools.",
    ),
)


# ---------------------------------------------------------------------------
# Frontmatter helpers (mirror migrate_cyberstrikeai_skills.py)
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
    lines.append("  origin: hack-deep-2026-06-07")
    lines.append("  license: per-tool")
    lines.append(f"  upstream_url: {UPSTREAM}")
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
    if meta.install_brew or meta.install_go or meta.install_pip:
        lines.append("    install:")
        for formula, bin_name in meta.install_brew:
            lines.append("      - kind: brew")
            lines.append(f"        id: {formula}")
            lines.append(f"        formula: {formula}")
            lines.append("        bins:")
            lines.append(f"          - {bin_name}")
        for go_path in meta.install_go:
            # bin name is the last path segment
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
    lines.append("---")
    return "\n".join(lines) + "\n"


def render_body(meta: SkillMeta) -> str:
    """Render a short markdown body describing the skill purpose.

    Kept terse — the SKILL.md exists to be loaded by the orchestrator LLM,
    not as documentation. The detailed usage lives in each tool's upstream
    README.
    """
    trigger_str = ", ".join(repr(t) for t in meta.triggers)
    return (
        f"\n# {meta.name}\n\n"
        f"{meta.description}\n\n"
        f"**Triggers**: {trigger_str}\n\n"
        f"**Bins**: {', '.join(meta.bins) or '(none)'}\n\n"
        f"**Risk**: {meta.risk}\n\n"
        f"**Capabilities**: {', '.join(meta.capabilities) or '(none)'}\n\n"
        f"Added by `scripts/add_subdomain_enum_skills.py` on {ATTRIBUTION_DATE} "
        f"as part of the hack-deep multi-target expansion. See "
        f"`docs/hack-deep.md` for context.\n"
    )


def render_attribution(meta: SkillMeta) -> str:
    return (
        f"# Attribution — {meta.name}\n\n"
        f"Added on {ATTRIBUTION_DATE} as part of hack-deep's 9-skill "
        f"subdomain-enumeration bundle.\n\n"
        f"- **Triggers**: {', '.join(repr(t) for t in meta.triggers)}\n"
        f"- **Bins**: {', '.join(meta.bins) or '(none)'}\n"
        f"- **Upstream reference**: {UPSTREAM}\n"
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
    for meta in SUBDOMAIN_SKILLS:
        dst = write_skill(meta)
        written.append(f"{meta.name} -> {dst}")
    print(f"OK  wrote {len(written)}  subdomain-enum skills -> {DST_ROOT}")
    for line in written:
        print(f"     + {line}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
