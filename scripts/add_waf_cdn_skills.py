#!/usr/bin/env python3
"""Add 2 WAF detection + CDN origin-finder skills (R3 P1)."""
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


WAF_CDN_SKILLS: tuple = (
    SkillMeta(
        name="cdncheck", risk="low",
        triggers=("cdncheck","CDN 检测","WAF 回源","Cloudflare","Akamai","Fastly","CloudFront"),
        bins=("cdncheck",), capabilities=(SHELL, NET, HTTP_O, FS_R),
        install_go=("github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest",),
        install_brew=(("cdncheck","cdncheck"),),
        description=(
            "ProjectDiscovery CDN / WAF detector. Default usage: "
            "`cdncheck -d target.com` returns CDN provider (Cloudflare / "
            "Akamai / Fastly / CloudFront / etc.) + IP range classification. "
            "Use the `WAF-CDN 已知列表` output to drive W4 origin-IP probing. "
            "Risk: low — passive DNS / header analysis."
        ),
        upstream_url="https://github.com/projectdiscovery/cdncheck",
    ),
    SkillMeta(
        name="wafw00f", risk="low",
        triggers=("wafw00f","WAF 识别","WAF fingerprint","Web 应用防火墙"),
        bins=("wafw00f",), capabilities=(SHELL, NET, HTTP_O, FS_R),
        install_brew=(("wafw00f","wafw00f"),),
        install_pip=("wafw00f",),
        description=(
            "Web Application Firewall fingerprinter. Default usage: "
            "`wafw00f https://target` returns the detected WAF vendor + "
            "matched rule (Cloudflare / AWS WAF / ModSecurity / Imperva / "
            "etc.) and a confidence score. Risk: low — sends 1-3 normal "
            "HTTP requests to detect WAF; can be bypassed by rotating IPs."
        ),
        upstream_url="https://github.com/EnableSecurity/wafw00f",
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
            f"Added by `scripts/add_waf_cdn_skills.py` on {ATTRIBUTION_DATE} (R3 P1 S19).\n")


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
    for m in WAF_CDN_SKILLS: d = write_skill(m); print(f"     + {m.name} -> {d}"); n += 1
    print(f"OK  wrote {n}  waf-cdn skills -> {DST_ROOT}"); return 0


if __name__ == "__main__":
    sys.exit(main())