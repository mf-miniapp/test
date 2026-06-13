#!/usr/bin/env python3
"""Add 2 monitoring dashboard fingerprint skills (R3 P0)."""
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

MONITORING_SKILLS: tuple = (
    SkillMeta(
        name="grafana-fingerprinter", risk="medium",
        triggers=("grafana-fp","grafana","Grafana 暴露","Grafana 默认凭据","dashboard"),
        bins=("grafana-fingerprinter",),
        capabilities=(SHELL, NET, HTTP_O, FS_R),
        install_go=("github.com/dwisiswant0/grafana-fingerprinter@latest",),
        install_brew=(("grafana-fingerprinter","grafana-fingerprinter"),),
        description=(
            "Lightweight Grafana fingerprint + default-cred tester. Default usage: "
            "`echo 'https://target:3000' | grafana-fingerprinter` to detect "
            "Grafana version + vulnerable endpoints; then read "
            "`~/.opensquilla/wordlists/monitoring-paths.txt` for plugin / dashboard paths. "
            "Risk: medium — GET probes only; default-cred brute is gated by "
            "ROE.aggressive."
        ),
        upstream_url="https://github.com/dwisiswant0/grafana-fingerprinter",
    ),
    SkillMeta(
        name="prometheus-fingerprinter", risk="medium",
        triggers=("prometheus-fp","prometheus","/metrics","Prometheus 暴露","node-exporter"),
        bins=("prometheus-fingerprinter",),
        capabilities=(SHELL, NET, HTTP_O, FS_R),
        install_brew=(("prometheus-fingerprinter","prometheus-fingerprinter"),),
        install_go=("github.com/nicholasgasior/prometheus-fingerprinter@latest",),
        description=(
            "Prometheus + node-exporter fingerprinter. Default usage: "
            "`curl -s https://target:9090/metrics | head` to confirm Prometheus; "
            "nmap NSE `prometheus-info` script auto-discovers + reports version. "
            "Risk: medium — GET probes only."
        ),
        upstream_url="https://github.com/nicholasgasior/prometheus-fingerprinter",
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
            f"Added by `scripts/add_monitoring_skills.py` on {ATTRIBUTION_DATE} (R3 P0 S15).\n")


def render_attribution(m: SkillMeta) -> str:
    return (f"# Attribution — {m.name}\n\nAdded {ATTRIBUTION_DATE} (R3 P0).\n\n"
            f"- **Triggers**: {', '.join(repr(t) for t in m.triggers)}\n"
            f"- **Bins**: {', '.join(m.bins)}\n"
            f"- **Upstream**: {m.upstream_url}\n- **Risk**: {m.risk}\n- **Maintainer**: zlpc\n")


def write_skill(m: SkillMeta) -> Path:
    d = DST_ROOT / m.name; d.mkdir(parents=True, exist_ok=True)
    (d / "SKILL.md").write_text(render_frontmatter(m) + render_body(m), encoding="utf-8")
    (d / "ATTRIBUTION.md").write_text(render_attribution(m), encoding="utf-8"); return d


def main() -> int:
    DST_ROOT.mkdir(parents=True, exist_ok=True)
    n = 0
    for m in MONITORING_SKILLS:
        d = write_skill(m); print(f"     + {m.name} -> {d}"); n += 1
    print(f"OK  wrote {n}  monitoring skills -> {DST_ROOT}"); return 0


if __name__ == "__main__":
    sys.exit(main())