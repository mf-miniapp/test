#!/usr/bin/env python3
"""Add 3 vulnerability scanning skills to the MANAGED skills layer.

Target : ~/.opensquilla/skills/<name>/SKILL.md  +  ATTRIBUTION.md
Schema : same as scripts/add_port_scan_skills.py / add_dir_bust_skills.py
          (name / description / always / triggers / provenance /
           metadata.opensquilla{risk, capabilities, requires.bins[],
           install[{kind:brew/uv/apt/go}]})

Idempotent: re-running refreshes SKILL.md + ATTRIBUTION.md in place
without raising. Safe to call as part of a `hack-deep` clone bootstrap.

Skills added (2026-06-10, recon coverage gap fix):
  sqlmap, nikto, dalfox

Why these three (and NOT nuclei, per user 2026-06-10 directive):
  - sqlmap: de-facto standard automated SQL injection detection + exploitation.
    Supports MySQL/Postgres/Oracle/MSSQL/SQLite/etc., time-based/blind/UNION/
    stacked/error-based. Reads request from tamas.manual/curl/saved log.
  - nikto: classic web server vulnerability scanner (~7000 checks against
    1250+ dangerous files/CGIs, version-specific issues, 270+ server
    misconfigurations). Will trigger IDS, default off; enable via
    ReconEvidence.scan_profile=="full" + explicit ROE flag.
  - dalfox: Go-based XSS scanner + parameter analyzer. Companion to manual
    XSS testing; detects reflected/stored/DOM XSS via response-diff
    analysis. Complements xsstricky (payload generator) with
    automated scanning.

Out of scope (per user 2026-06-10):
  - nuclei (explicitly excluded — "排除 nuclei,改用 nikto + 手工 SQLi/SSRF/SSTI 模板")
  - wpscan (CMS-specific, already in add_web_attack_skills.py)
  - droopescan (CMS-specific, already in add_web_attack_skills.py)
  - xsstricky (payload-only, already in add_web_attack_skills.py)
  - xsstrike (Python, less maintained; replaced by dalfox)
  - commix (command injection, low priority; use nikto + manual)

Manual payload templates (SSRF/SSTI/LFI/XXE/IDOR) are NOT registered as
skills here — they are bundled as data files in scripts/fetch_wordlists.py
and stored in ~/.opensquilla/payloads/. The penetration agent reads them
at exploitation time per its vector_class routing.
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


# Order matches the delivery todo T3.
VULN_SCAN_SKILLS: tuple[SkillMeta, ...] = (
    SkillMeta(
        name="sqlmap",
        risk="high",
        triggers=(
            "sqlmap",
            "SQL 注入",
            "SQL injection",
            "SQLi",
            "UNION 注入",
            "盲注",
            "blind SQLi",
            "time-based SQLi",
        ),
        bins=("sqlmap", "sqlmap.py"),
        capabilities=(SHELL, NET, HTTP_O, FS_R),
        install_brew=(("sqlmap", "sqlmap"),),
        install_pip=("sqlmap",),
        install_apt=(("sqlmap", "sqlmap"),),
        description=(
            "Automatic SQL injection + database takeover tool. Default usage is "
            "`sqlmap -u 'https://target/?id=1' --batch --level=3 --risk=2 "
            "--technique=BEUST --random-agent` for multi-technique blind/error/"
            "UNION/stacked/time-based detection. Use `--dbms=mysql` / `--dbms="
            "postgres` to constrain. Reads request from saved curl/file via `-r`. "
            "DESTRUCTIVE OPTIONS: `--os-shell`, `--os-cmd`, `--file-write` — only "
            "with explicit ROE flag and user confirmation. Risk: HIGH — actively "
            "queries target; may be logged by WAF/IDS."
        ),
        upstream_url="https://github.com/sqlmapproject/sqlmap",
    ),
    SkillMeta(
        name="nikto",
        risk="high",
        triggers=(
            "nikto",
            "Web 服务器扫描",
            "web server scan",
            "CGI 漏洞",
            "危险文件",
            "server misconfig",
        ),
        bins=("nikto",),
        capabilities=(SHELL, NET, HTTP_O, FS_R),
        install_brew=(("nikto", "nikto"),),
        install_apt=(("nikto", "nikto"),),
        description=(
            "Classic web server vulnerability scanner (Perl). Default usage is "
            "`nikto -h https://target -Tuning x6 -maxtime 3600s` to scan with "
            "tuning profile x6 (DoS checks excluded) and 1-hour time cap. "
            "Checks ~7000 dangerous files/CGIs, ~1250 server version-specific "
            "issues, ~270 misconfigurations. VERY NOISY: will trigger every "
            "IDS/WAF on the planet. Default off; only invoke with `aggressive` "
            "ROE flag. Pair with nmap service detection to know what server "
            "versions to expect."
        ),
        upstream_url="https://github.com/sullo/nikto",
    ),
    SkillMeta(
        name="dalfox",
        risk="medium",
        triggers=(
            "dalfox",
            "XSS 扫描",
            "XSS scan",
            "反射型 XSS",
            "reflected XSS",
            "DOM XSS",
            "blind XSS",
        ),
        bins=("dalfox",),
        capabilities=(SHELL, NET, HTTP_O, FS_R),
        install_go=("github.com/hahwul/dalfox/v2@latest",),
        install_brew=(("dalfox", "dalfox"),),
        description=(
            "Go-based XSS scanner + parameter analyzer. Default usage is "
            "`dalfox url https://target/?q=FUZZ --follow-redirects --skip-bav` "
            "to scan a single URL, or pipe katana-crawled URLs via `dalfox pipe`. "
            "Detects reflected/stored/blind/DOM XSS with response-diff analysis. "
            "Complements xsstricky (payload generator) with automated scanning. "
            "Risk: medium — actively probes reflected vectors, less noisy than "
            "nikto but still logs in WAF."
        ),
        upstream_url="https://github.com/hahwul/dalfox",
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
        f"Added by `scripts/add_vuln_scan_skills.py` on {ATTRIBUTION_DATE} "
        f"as part of the recon coverage gap fix. See "
        f"`docs/delivery/recon-coverage-gap-fix.delivery-solution.md` for context.\n"
    )


def render_attribution(meta: SkillMeta) -> str:
    upstream = meta.upstream_url or "(see upstream project)"
    return (
        f"# Attribution — {meta.name}\n\n"
        f"Added on {ATTRIBUTION_DATE} as part of the recon coverage gap fix "
        f"(B-plan: port scan + dir bust + vuln scan). nuclei is explicitly "
        f"out of scope per user direction on 2026-06-10.\n\n"
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
    for meta in VULN_SCAN_SKILLS:
        dst = write_skill(meta)
        written.append(f"{meta.name} -> {dst}")
    print(f"OK  wrote {len(written)}  vuln-scan skills -> {DST_ROOT}")
    for line in written:
        print(f"     + {line}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
