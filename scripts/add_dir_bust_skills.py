#!/usr/bin/env python3
"""Add 3 directory/file brute-force skills to the MANAGED skills layer.

Target : ~/.opensquilla/skills/<name>/SKILL.md  +  ATTRIBUTION.md
Schema : same as scripts/add_port_scan_skills.py / add_web_attack_skills.py
          (name / description / always / triggers / provenance /
           metadata.opensquilla{risk, capabilities, requires.bins[],
           install[{kind:brew/uv/apt/go}]})

Idempotent: re-running refreshes SKILL.md + ATTRIBUTION.md in place
without raising. Safe to call as part of a `hack-deep` clone bootstrap.

Skills added (2026-06-10, recon coverage gap fix):
  ffuf, feroxbuster, gobuster

Why these three (and not dirb/dirsearch/wfuzz):
  - ffuf: the de-facto Go-based fuzz reference; supports GET/POST/header/
    body fuzzing with response-diff filtering; recommended primary.
  - feroxbuster: recursive scan engine with intelligent rate-limiting
    and link extraction; complements ffuf on deep recursive targets.
  - gobuster: lightweight, DNS + dir + vhost modes; covers DNS brute
    (mode=dns) and vhost enumeration (mode=vhost) — both missing from ffuf.
  - All three are Go, installable from upstream repos.

Out of scope (per user 2026-06-10):
  - dirb / dirsearch (Python + wordlist, slower; redundant with ffuf)
  - wfuzz (Python, less maintained since 2022; replaced by ffuf)
  - massdns / shuffledns (already in add_subdomain_enum_skills.py)
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path

DST_ROOT = Path.home() / ".opensquilla" / "skills"
ATTRIBUTION_DATE = "2026-06-10"

NET = "network"
SHELL = "shell"
FS_R = "filesystem-read"
HTTP_O = "network.http"


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


# Order matches the delivery todo T2.
DIR_BUST_SKILLS: tuple[SkillMeta, ...] = (
    SkillMeta(
        name="ffuf",
        risk="medium",
        triggers=(
            "ffuf",
            "目录爆破",
            "directory brute",
            "目录扫描",
            "directory fuzz",
            "path discovery",
        ),
        bins=("ffuf",),
        capabilities=(SHELL, NET, HTTP_O, FS_R),
        install_go=("github.com/ffuf/ffuf/v2@latest",),
        install_brew=(("ffuf", "ffuf"),),
        description=(
            "Fast web fuzzer written in Go. Default usage is "
            "`ffuf -w ~/.opensquilla/wordlists/raft-medium-directories.txt -u "
            "https://target/FUZZ -mc 200,301,302,403 -recursion` for recursive "
            "directory discovery. Supports GET/POST/Header/Body fuzz, recursive "
            "scan, response-diff filtering, and rate control. Pair with katana "
            "crawled endpoints as seed URLs."
        ),
        upstream_url="https://github.com/ffuf/ffuf",
    ),
    SkillMeta(
        name="feroxbuster",
        risk="medium",
        triggers=(
            "feroxbuster",
            "递归扫描",
            "recursive scan",
            "目录递归",
            "deep dir bust",
        ),
        bins=("feroxbuster",),
        capabilities=(SHELL, NET, HTTP_O, FS_R),
        install_go=("github.com/epi052/feroxbuster/v2@latest",),
        install_brew=(("feroxbuster", "feroxbuster"),),
        description=(
            "Recursive content discovery tool written in Rust. Default usage is "
            "`feroxbuster -u https://target -w ~/.opensquilla/wordlists/"
            "raft-medium-directories.txt --depth 3` for deep recursive scan. "
            "Intelligent rate-limiting, link extraction, automatic recursion "
            "into discovered directories. Use as a complement to ffuf when "
            "the target has many nested paths."
        ),
        upstream_url="https://github.com/epi052/feroxbuster",
    ),
    SkillMeta(
        name="gobuster",
        risk="medium",
        triggers=(
            "gobuster",
            "DNS 爆破",
            "DNS brute",
            "vhost 枚举",
            "vhost enum",
            "轻量目录扫描",
        ),
        bins=("gobuster",),
        capabilities=(SHELL, NET, HTTP_O, FS_R),
        install_go=("github.com/OJ/gobuster/v3@latest",),
        install_brew=(("gobuster", "gobuster"),),
        description=(
            "Lightweight directory/DNS/vhost brute-forcer. Default usage is "
            "`gobuster dir -u https://target -w ~/.opensquilla/wordlists/"
            "raft-medium-directories.txt` for directory scan; switch to "
            "`gobuster dns -d target.com -w subdomains.txt` for DNS brute; "
            "`gobuster vhost -u https://target -w vhosts.txt` for vhost "
            "enumeration. Less feature-rich than ffuf/feroxbuster but very "
            "fast and stable; covers DNS + vhost modes that ffuf lacks."
        ),
        upstream_url="https://github.com/OJ/gobuster",
    ),
)


# ---------------------------------------------------------------------------
# Frontmatter helpers (mirror add_port_scan_skills.py)
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
    """Render a short markdown body describing the skill purpose."""
    trigger_str = ", ".join(repr(t) for t in meta.triggers)
    return (
        f"\n# {meta.name}\n\n"
        f"{meta.description}\n\n"
        f"**Triggers**: {trigger_str}\n\n"
        f"**Bins**: {', '.join(meta.bins) or '(none)'}\n\n"
        f"**Risk**: {meta.risk}\n\n"
        f"**Capabilities**: {', '.join(meta.capabilities) or '(none)'}\n\n"
        f"Added by `scripts/add_dir_bust_skills.py` on {ATTRIBUTION_DATE} "
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
    for meta in DIR_BUST_SKILLS:
        dst = write_skill(meta)
        written.append(f"{meta.name} -> {dst}")
    print(f"OK  wrote {len(written)}  dir-bust skills -> {DST_ROOT}")
    for line in written:
        print(f"     + {line}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
