#!/usr/bin/env python3
"""Add 2 secret-scanning skills (R3 P1).

gitleaks: Go-based regex + entropy secret scanner for git repos. Default
         scope cap: 1000 commits / 50MB.
trufflehog: Go-based high-entropy + verified-credential scanner. Detects
         more secrets than gitleaks via entropy, and verifies against live
         services when an API key is suspected.
"""
from __future__ import annotations
import re, sys
from dataclasses import dataclass
from pathlib import Path

DST_ROOT = Path.home() / ".opensquilla" / "skills"
ATTRIBUTION_DATE = "2026-06-10"
NET = "network"; SHELL = "shell"; FS_R = "filesystem-read"; HTTP_O = "network.http"


@dataclass(frozen=True)
class SkillMeta:
    name: str; risk: str; triggers: tuple; bins: tuple
    capabilities: tuple = ()
    install_brew: tuple = (); install_go: tuple = (); install_pip: tuple = (); install_apt: tuple = ()
    description: str = ""; upstream_url: str = ""


SECRET_SCAN_SKILLS: tuple = (
    SkillMeta(
        name="gitleaks", risk="medium",
        triggers=("gitleaks","git 密钥扫描","仓库密钥","API key 泄露","commit 历史密钥"),
        bins=("gitleaks",), capabilities=(SHELL, NET, FS_R),
        install_go=("github.com/gitleaks/gitleaks/v8@latest",),
        install_brew=(("gitleaks","gitleaks"),),
        description=(
            "Go-based git repo secret scanner with regex + entropy detection. "
            "Default usage: `gitleaks detect --source . --max-target-megabytes=50 "
            "--log-opts='--max-count=1000' --report-path ~/.opensquilla/evidence/gitleaks/` "
            "(scope cap: 1000 commits / 50MB to prevent timeout). Reports "
            "AWS keys, GitHub PATs, Slack tokens, private keys, etc. with file:line. "
            "Risk: medium — read-only on the local clone, no exfiltration."
        ),
        upstream_url="https://github.com/gitleaks/gitleaks",
    ),
    SkillMeta(
        name="trufflehog", risk="medium",
        triggers=("trufflehog","truffle","高熵密钥扫描","verified credential","凭证验证"),
        bins=("trufflehog",), capabilities=(SHELL, NET, HTTP_O, FS_R),
        install_go=("github.com/trufflesecurity/trufflehog/v3@latest",),
        install_brew=(("trufflehog","trufflehog"),),
        description=(
            "Go-based high-entropy secret scanner with optional live "
            "verification of suspected credentials. Default usage: "
            "`trufflehog git file://./repo --max-depth=1000 --concurrency=4 "
            "--json` to scan git history with 1000-commit cap. Complements "
            "gitleaks with entropy + (optional) live-verification. Risk: "
            "medium — read-only on local clone; `--verify` makes outbound "
            "HTTP to credential issuers (gated by ROE.aggressive)."
        ),
        upstream_url="https://github.com/trufflesecurity/trufflehog",
    ),
)


def yaml_escape(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"' if re.search(r"[:#\n\"']", s) else s


def render_frontmatter(m: SkillMeta) -> str:
    L = ["---", f"name: {m.name}", f"description: {yaml_escape(m.description)}", "always: false", "triggers:"]
    for t in m.triggers: L.append(f"  - {yaml_escape(t)}")
    L.append("provenance:"); L.append("  origin: recon-coverage-gap-fix-r3-2026-06-10"); L.append("  license: per-tool")
    if m.upstream_url: L.append(f"  upstream_url: {m.upstream_url}")
    L.append("  maintained_by: zlpc")
    L.append("metadata:"); L.append("  opensquilla:"); L.append(f"    risk: {m.risk}")
    if m.capabilities:
        L.append("    capabilities:")
        for c in m.capabilities: L.append(f"      - {c}")
    if m.bins:
        L.append("    requires:"); L.append("      bins:")
        for b in m.bins: L.append(f"        - {b}")
    if m.install_brew or m.install_go or m.install_pip or m.install_apt:
        L.append("    install:")
        for f, b in m.install_brew:
            L += ["      - kind: brew", f"        id: {f}", f"        formula: {f}", "        bins:", f"          - {b}"]
        for p in m.install_go:
            bn = p.rsplit("/", 1)[-1]
            L += ["      - kind: go", f"        path: {p}", "        bins:", f"          - {bn}"]
        for mod in m.install_pip:
            L += ["      - kind: uv", f"        module: {mod}", "        bins:", f"          - {mod}"]
        for pkg, bn in m.install_apt:
            L += ["      - kind: apt", f"        package: {pkg}", "        bins:", f"          - {bn}"]
    L.append("---"); return "\n".join(L) + "\n"


def render_body(m: SkillMeta) -> str:
    return (f"\n# {m.name}\n\n{m.description}\n\n"
            f"**Triggers**: {', '.join(repr(t) for t in m.triggers)}\n\n"
            f"**Bins**: {', '.join(m.bins) or '(none)'}\n\n"
            f"**Risk**: {m.risk}\n\n"
            f"**Capabilities**: {', '.join(m.capabilities) or '(none)'}\n\n"
            f"Added by `scripts/add_secret_scan_skills.py` on {ATTRIBUTION_DATE} (R3 P1 S21). "
            f"Default scope cap: 1000 commits / 50MB to prevent timeout on large repos.\n")


def render_attribution(m: SkillMeta) -> str:
    return (f"# Attribution — {m.name}\n\nAdded {ATTRIBUTION_DATE} (R3 P1).\n\n"
            f"- **Triggers**: {', '.join(repr(t) for t in m.triggers)}\n"
            f"- **Bins**: {', '.join(m.bins)}\n- **Upstream**: {m.upstream_url}\n"
            f"- **Risk**: {m.risk}\n- **Maintainer**: zlpc\n")


def write_skill(m: SkillMeta) -> Path:
    d = DST_ROOT / m.name; d.mkdir(parents=True, exist_ok=True)
    (d / "SKILL.md").write_text(render_frontmatter(m) + render_body(m), encoding="utf-8")
    (d / "ATTRIBUTION.md").write_text(render_attribution(m), encoding="utf-8"); return d


def main() -> int:
    DST_ROOT.mkdir(parents=True, exist_ok=True); n = 0
    for m in SECRET_SCAN_SKILLS: d = write_skill(m); print(f"     + {m.name} -> {d}"); n += 1
    print(f"OK  wrote {n}  secret-scan skills -> {DST_ROOT}"); return 0


if __name__ == "__main__":
    sys.exit(main())