#!/usr/bin/env python3
"""Add 22 modern web-attack skills to the MANAGED skills layer.

Target : ~/.opensquilla/skills/<name>/SKILL.md  +  ATTRIBUTION.md
Schema : same as scripts/migrate_cyberstrikeai_skills.py / add_subdomain_enum_skills.py

Idempotent. Added 2026-06-07 as part of hack-deep's modern-web-attack
surface expansion. Out of scope per user request:
  - Any nuclei-related entry (cve-mapping, takeover template, etc.)
  - Any ROE enforcement

Skills added:
  katana, jsluice, linkfinder, xnLinkFinder, subjs, arjun,
  paramspider, x8, kiterunner, graphql-introspector, clairvoyance,
  batchql, wsrepl, nomore403, bypass-403, smuggler, h2csmuggler,
  wpscan, droopescan, xsstricky, evilginx2, mobsf, objection
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path

DST_ROOT = Path.home() / ".opensquilla" / "skills"
ATTRIBUTION_DATE = "2026-06-07"

NET = "network"
SHELL = "shell"
FS_R = "filesystem-read"
FS_W = "filesystem-write"
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


# Order matches the delivery todo T16.
WEB_ATTACK_SKILLS: tuple[SkillMeta, ...] = (
    # --- Crawling & JS recon -----------------------------------------------
    SkillMeta(
        name="katana",
        risk="low",
        triggers=("katana", "Web 爬虫", "crawler", "JS 爬取", "endpoint discovery"),
        bins=("katana",),
        capabilities=(SHELL, NET, HTTP_O, FS_R),
        install_go=("github.com/projectdiscovery/katana/cmd/katana@latest",),
        description="Next-gen crawling and spidering framework. Drives JS-aware crawling for endpoint discovery; feeds linkfinder / subjs / arjun pipelines.",
    ),
    SkillMeta(
        name="jsluice",
        risk="low",
        triggers=("jsluice", "JS 分析", "JavaScript analysis", "secret extraction"),
        bins=("jsluice",),
        capabilities=(SHELL, NET, FS_R),
        install_go=("github.com/BishopFox/jsluice/cmd/jsluice@latest",),
        description="Extract URLs, paths, secrets and interesting data from JavaScript source. Complements katana / linkfinder output.",
    ),
    SkillMeta(
        name="linkfinder",
        risk="low",
        triggers=("linkfinder", "JS endpoint 提取", "endpoint extraction", "JS 链接"),
        bins=("linkfinder",),
        capabilities=(SHELL, NET, FS_R),
        install_pip=("linkfinder",),
        description="Python tool to extract endpoints from JS / HTML. Useful for finding forgotten / hidden paths in single-page apps.",
    ),
    SkillMeta(
        name="xnLinkFinder",
        risk="low",
        triggers=("xnLinkFinder", "链接发现", "endpoint mining"),
        bins=("xnLinkFinder",),
        capabilities=(SHELL, NET, FS_R),
        install_pip=("xnLinkFinder",),
        description="Multi-threaded endpoint / link discovery across JS, HTML and JSON. Companion to katana for SPA path mining.",
    ),
    SkillMeta(
        name="subjs",
        risk="low",
        triggers=("subjs", "JS 资产", "JS file extraction", "subresource discovery"),
        bins=("subjs",),
        capabilities=(SHELL, NET, HTTP_O, FS_R),
        install_go=("github.com/lc/subjs@latest",),
        description="Extract JavaScript file URLs from a list of websites. Pre-process step for jsluice / linkfinder.",
    ),
    # --- Parameter discovery ------------------------------------------------
    SkillMeta(
        name="arjun",
        risk="medium",
        triggers=("arjun", "参数发现", "parameter discovery", "hidden params"),
        bins=("arjun",),
        capabilities=(SHELL, NET, HTTP_O, FS_R),
        install_pip=("arjun",),
        description="HTTP parameter discovery suite. Finds hidden GET / POST / JSON / HEADER parameters on endpoints.",
    ),
    SkillMeta(
        name="paramspider",
        risk="low",
        triggers=("paramspider", "参数爬取", "parameter mining", "Wayback params"),
        bins=("paramspider",),
        capabilities=(SHELL, NET, HTTP_O, FS_R),
        install_pip=("paramspider",),
        description="Mine parameters from the Wayback Machine and web.archive.org archives for a given domain.",
    ),
    SkillMeta(
        name="x8",
        risk="medium",
        triggers=("x8", "隐藏参数", "hidden parameter", "parameter fuzzer"),
        bins=("x8",),
        capabilities=(SHELL, NET, HTTP_O, FS_R),
        install_go=("github.com/shadowsocks-hub/x8/cmd/x8@latest",),
        description="Hidden parameter discovery fuzzer. Brute-forces GET / POST parameters with response-diffing.",
    ),
    # --- API surface --------------------------------------------------------
    SkillMeta(
        name="kiterunner",
        risk="medium",
        triggers=("kiterunner", "API 路由爆破", "API route bruteforce", "API endpoint fuzz"),
        bins=("kr",),
        capabilities=(SHELL, NET, FS_R),
        install_go=("github.com/assetnote/kiterunner@latest",),
        description="Brute-force API routes from wordlists compiled from real-world API schemas. Find undocumented / forgotten API paths.",
    ),
    SkillMeta(
        name="graphql-introspector",
        risk="low",
        triggers=("graphql introspection", "GraphQL schema", "GraphQL 探测"),
        bins=("graphql-introspector",),
        capabilities=(SHELL, NET, HTTP_O, FS_R),
        install_pip=("graphql-introspector",),
        description="Run GraphQL introspection queries and dump the full schema. Use as a first step against any GraphQL endpoint.",
    ),
    SkillMeta(
        name="clairvoyance",
        risk="medium",
        triggers=("clairvoyance", "GraphQL 爆破", "GraphQL wordlist", "GraphQL fuzzing"),
        bins=("clairvoyance",),
        capabilities=(SHELL, NET, FS_R),
        install_go=("github.com/nicholasgasior/clairvoyance@latest",),
        description="Brute-force GraphQL field / type names when introspection is disabled. Companion to graphql-introspector.",
    ),
    SkillMeta(
        name="batchql",
        risk="medium",
        triggers=("batchql", "GraphQL batch", "GraphQL 批量"),
        bins=("batchql",),
        capabilities=(SHELL, NET, HTTP_O, FS_R),
        install_pip=("batchql",),
        description="GraphQL security auditing toolkit: batching attacks, query depth analysis, field-suggestion mining.",
    ),
    # --- WebSocket & smuggling ---------------------------------------------
    SkillMeta(
        name="wsrepl",
        risk="medium",
        triggers=("wsrepl", "WebSocket 探测", "WebSocket testing", "WS repl"),
        bins=("wsrepl",),
        capabilities=(SHELL, NET, HTTP_O, FS_R),
        install_pip=("wsrepl",),
        description="Interactive WebSocket REPL for testing message handling, auth and message-injection attacks.",
    ),
    SkillMeta(
        name="nomore403",
        risk="medium",
        triggers=("nomore403", "403 bypass", "绕过 403", "forbidden bypass"),
        bins=("nomore403",),
        capabilities=(SHELL, NET, HTTP_O, FS_R),
        install_go=("github.com/m4ll0k/nomore403@latest",),
        description="Bypass 403 / 401 forbidden paths via header / verb / encoding tricks. Useful for depth-chain discovery.",
    ),
    SkillMeta(
        name="bypass-403",
        risk="medium",
        triggers=("bypass-403", "403 bypass", "绕过 403", "forbidden bypass"),
        bins=("bypass-403",),
        capabilities=(SHELL, NET, HTTP_O, FS_R),
        install_go=("github.com/lobuhi/byp4xx@latest",),
        description="Alternative 403 bypass tool. Tries verb / path / case / encoding mutations.",
    ),
    SkillMeta(
        name="smuggler",
        risk="high",
        triggers=("smuggler", "HTTP request smuggling", "请求走私", "CL-TE", "TE-CL"),
        bins=("smuggler",),
        capabilities=(SHELL, NET, HTTP_O, FS_R),
        install_pip=("smuggler",),
        description="HTTP request smuggling detector / exploiter. Targets CL.TE / TE.CL desync on reverse proxies.",
    ),
    SkillMeta(
        name="h2csmuggler",
        risk="high",
        triggers=("h2csmuggler", "h2c smuggling", "HTTP/2 cleartext", "h2c 走私"),
        bins=("h2csmuggler",),
        capabilities=(SHELL, NET, HTTP_O, FS_R),
        install_go=("github.com/BishopFox/h2csmuggler@latest",),
        description="Smuggle h2c (HTTP/2 cleartext) traffic past reverse proxies that don't speak h2. Internal endpoint bypass primitive.",
    ),
    # --- CMS / fingerprinting ----------------------------------------------
    SkillMeta(
        name="wpscan",
        risk="medium",
        triggers=("wpscan", "WordPress", "WordPress 扫描", "WP vuln"),
        bins=("wpscan",),
        capabilities=(SHELL, NET, HTTP_O, FS_R),
        install_pip=("wpscan",),
        description="WordPress vulnerability scanner. Enumerates plugins, themes, users and known CVEs.",
    ),
    SkillMeta(
        name="droopescan",
        risk="low",
        triggers=("droopescan", "Drupal", "SilverStripe", "CMS 扫描"),
        bins=("droopescan",),
        capabilities=(SHELL, NET, HTTP_O, FS_R),
        install_pip=("droopescan",),
        description="Plugin-based CMS scanner targeting Drupal, SilverStripe, WordPress, Joomla. Useful for CMS family detection.",
    ),
    # --- XSS / phishing / mobile -------------------------------------------
    SkillMeta(
        name="xsstricky",
        risk="medium",
        triggers=("xsstricky", "XSS 绕过", "XSS payload", "XSS bypass"),
        bins=("xsstricky",),
        capabilities=(SHELL, NET, HTTP_O, FS_R),
        install_pip=("xsstricky",),
        description="Generate XSS payloads that bypass common WAF / CSP filters. Useful for depth-chain XSS confirmation.",
    ),
    SkillMeta(
        name="evilginx2",
        risk="high",
        triggers=("evilginx2", "钓鱼框架", "phishing", "AiTM", "reverse proxy phishing"),
        bins=("evilginx2",),
        capabilities=(SHELL, NET, HTTP_O, FS_R),
        install_go=("github.com/kgretzky/evilginx2@latest",),
        description="Man-in-the-middle reverse-proxy phishing framework. Use to test phishing resilience / 2FA bypasses.",
    ),
    SkillMeta(
        name="mobsf",
        risk="medium",
        triggers=("mobsf", "Mobile Security Framework", "Android 安全", "iOS 安全", "APK 分析"),
        bins=("mobsf",),
        capabilities=(SHELL, NET, HTTP_O, FS_R),
        install_pip=("mobsf",),
        description="Mobile Security Framework for Android / iOS static and dynamic analysis. Companion to objection.",
    ),
    SkillMeta(
        name="objection",
        risk="medium",
        triggers=("objection", "Mobile runtime", "Frida runtime", "APK 运行时"),
        bins=("objection",),
        capabilities=(SHELL, NET, FS_R),
        install_pip=("objection",),
        description="Frida-powered mobile runtime exploration. Bypass SSL pinning, dump memory, hook methods. Pairs with mobsf.",
    ),
)


# ---------------------------------------------------------------------------
# Frontmatter helpers
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
    trigger_str = ", ".join(repr(t) for t in meta.triggers)
    return (
        f"\n# {meta.name}\n\n"
        f"{meta.description}\n\n"
        f"**Triggers**: {trigger_str}\n\n"
        f"**Bins**: {', '.join(meta.bins) or '(none)'}\n\n"
        f"**Risk**: {meta.risk}\n\n"
        f"**Capabilities**: {', '.join(meta.capabilities) or '(none)'}\n\n"
        f"Added by `scripts/add_web_attack_skills.py` on {ATTRIBUTION_DATE} as "
        f"part of hack-deep's modern-web-attack surface expansion. See "
        f"`docs/hack-deep.md` for context.\n"
    )


def render_attribution(meta: SkillMeta) -> str:
    return (
        f"# Attribution — {meta.name}\n\n"
        f"Added on {ATTRIBUTION_DATE} as part of hack-deep's 22-skill "
        f"modern-web-attack bundle.\n\n"
        f"- **Triggers**: {', '.join(repr(t) for t in meta.triggers)}\n"
        f"- **Bins**: {', '.join(meta.bins) or '(none)'}\n"
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
    for meta in WEB_ATTACK_SKILLS:
        dst = write_skill(meta)
        written.append(f"{meta.name} -> {dst}")
    print(f"OK  wrote {len(written)}  web-attack skills -> {DST_ROOT}")
    for line in written:
        print(f"     + {line}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
