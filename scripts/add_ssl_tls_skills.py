#!/usr/bin/env python3
"""Add 2 SSL/TLS deep-fingerprint skills (R3 P1).

tlsx: ProjectDiscovery Go tool — TLS handshake + JA3/JA4 fingerprint +
       cert chain walk + ALPN inspection.
sslyze: Python tool — comprehensive TLS scanner; cipher enum, cert
       expiration, vulnerability checks (Heartbleed, ROBOT, POODLE).
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


SSL_TLS_SKILLS: tuple = (
    SkillMeta(
        name="tlsx", risk="low",
        triggers=("tlsx","TLS 指纹","JA3","JA4","TLS 握手","TLS 深度"),
        bins=("tlsx",), capabilities=(SHELL, NET, FS_R),
        install_go=("github.com/projectdiscovery/tlsx/cmd/tlsx@latest",),
        install_brew=(("tlsx","tlsx"),),
        description=(
            "ProjectDiscovery fast TLS prober with JA3/JA4 fingerprint + "
            "cert chain walk. Default usage: `tlsx -u target.com -san -cn -tls-version` "
            "to dump TLS versions + cipher suites + JA3/JA4 hash + SAN list. "
            "JA3/JA4 enables client fingerprinting on the network. "
            "Risk: low — TLS handshake only."
        ),
        upstream_url="https://github.com/projectdiscovery/tlsx",
    ),
    SkillMeta(
        name="sslyze", risk="low",
        triggers=("sslyze","SSL 深度扫描","Heartbleed","ROBOT","POODLE","TLS 漏洞"),
        bins=("sslyze",), capabilities=(SHELL, NET, FS_R),
        install_pip=("sslyze",),
        install_brew=(("sslyze","sslyze"),),
        description=(
            "Comprehensive Python TLS scanner. Default usage: "
            "`sslyze --regular target.com:443` runs cipher enum + cert "
            "validation + vulnerability checks (Heartbleed / ROBOT / "
            "POODLE / SWEET32 / LOGJAM). Outputs JSON for evidence chain. "
            "Risk: low — TLS handshake only, no exploitation."
        ),
        upstream_url="https://github.com/nabla-c0d3/sslyze",
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
            f"Added by `scripts/add_ssl_tls_skills.py` on {ATTRIBUTION_DATE} (R3 P1 S20).\n")


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
    for m in SSL_TLS_SKILLS: d = write_skill(m); print(f"     + {m.name} -> {d}"); n += 1
    print(f"OK  wrote {n}  ssl-tls skills -> {DST_ROOT}"); return 0


if __name__ == "__main__":
    sys.exit(main())