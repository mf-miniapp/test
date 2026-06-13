#!/usr/bin/env python3
"""Add 2 cloud asset enumeration skills to the MANAGED skills layer.

Target : ~/.opensquilla/skills/<name>/SKILL.md  +  ATTRIBUTION.md
Schema : same as scripts/add_port_scan_skills.py (R1 baseline)

Idempotent: re-running refreshes SKILL.md + ATTRIBUTION.md in place.

Skills added (2026-06-10, recon coverage gap fix R3 P0):
  s3scanner, cloud_enum

Why these two:
  - s3scanner: multi-threaded AWS S3 bucket scanner. Reads wordlist
    (cloud-buckets-prefixes.txt) → for each prefix, tries the canonical
    bucket naming patterns and reports ACL/region/listable status.
  - cloud_enum: comprehensive multi-cloud enum by initstring —
    S3 / Azure Blob / GCP Storage / Heroku / DigitalOcean Spaces.
    Complements s3scanner by covering Azure/GCP.

Out of scope (per user 2026-06-10):
  - nuclei cloud templates (excluded)
  - ScoutSuite / Prowler (heavier, AWS-only)
  - kube-hunter (covered in a separate S-tier if requested)
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


# Order matches the delivery todo R3 T1.
CLOUD_ASSETS_SKILLS: tuple[SkillMeta, ...] = (
    SkillMeta(
        name="s3scanner",
        risk="medium",
        triggers=(
            "s3scanner",
            "S3 bucket",
            "AWS S3",
            "S3 枚举",
            "云存储枚举",
            "S3 ACL",
        ),
        bins=("s3scanner",),
        capabilities=(SHELL, NET, HTTP_O, FS_R),
        install_go=("github.com/sa7mon/s3scanner/v3@latest",),
        install_brew=(("s3scanner", "s3scanner"),),
        description=(
            "Multi-threaded AWS S3 bucket scanner. Default usage is "
            "`s3scanner -bucket-file ~/.opensquilla/wordlists/cloud-buckets-prefixes.txt` "
            "to scan a list of bucket-name prefixes against the AWS S3 API. "
            "Reports ACL (private/public/public-read/etc), region, listable, "
            "and object-count. Pair with `cloud_enum` for full multi-cloud coverage "
            "(Azure Blob / GCP Storage / Heroku). Risk: medium — only does "
            "unauthenticated GET / HEAD against bucket endpoints, no writes."
        ),
        upstream_url="https://github.com/sa7mon/s3scanner",
    ),
    SkillMeta(
        name="cloud_enum",
        risk="medium",
        triggers=(
            "cloud_enum",
            "Azure Blob",
            "GCP Storage",
            "Heroku",
            "DigitalOcean Spaces",
            "多云枚举",
            "multi-cloud",
        ),
        bins=("cloud_enum.py", "cloud_enum"),
        capabilities=(SHELL, NET, HTTP_O, FS_R),
        install_brew=(("cloud_enum", "cloud_enum"),),
        install_pip=("cloud_enum",),
        description=(
            "Multi-cloud asset enumeration by initstring — supports S3, "
            "Azure Blob (`blob.core.windows.net`), GCP Storage "
            "(`storage.googleapis.com`), Heroku (`herokuapp.com`), and "
            "DigitalOcean Spaces (`digitaloceanspaces.com`). Default usage "
            "is `cloud_enum.py -k companyname -m Azure Blob,GCP Storage,Heroku`. "
            "Complements s3scanner for the Azure / GCP / Heroku halves. "
            "Risk: medium — same as s3scanner, unauthenticated GET probes."
        ),
        upstream_url="https://github.com/initstring/cloud_enum",
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
        f"Added by `scripts/add_cloud_assets_skills.py` on {ATTRIBUTION_DATE} "
        f"as part of the R3 P0 cloud assets expansion. See "
        f"`docs/delivery/recon-coverage-gap-fix.delivery-solution.md` S13 for context.\n"
    )


def render_attribution(meta: SkillMeta) -> str:
    upstream = meta.upstream_url or "(see upstream project)"
    return (
        f"# Attribution — {meta.name}\n\n"
        f"Added on {ATTRIBUTION_DATE} as part of the R3 P0 cloud assets bundle "
        f"(s3scanner + cloud_enum).\n\n"
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
    for meta in CLOUD_ASSETS_SKILLS:
        dst = write_skill(meta)
        written.append(f"{meta.name} -> {dst}")
    print(f"OK  wrote {len(written)}  cloud-assets skills -> {DST_ROOT}")
    for line in written:
        print(f"     + {line}")
    return 0


if __name__ == "__main__":
    sys.exit(main())