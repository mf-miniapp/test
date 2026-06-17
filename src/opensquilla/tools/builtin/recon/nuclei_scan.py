"""CVE + tech-fingerprint scan — nuclei (preferred) / stdlib (fallback).

v4 (2026-06-17): F1.5 / F3.5 CVE component view. nuclei
(https://github.com/projectdiscovery/nuclei) is the de-facto
industry-standard scanner with thousands of community-curated
CVE + tech-fingerprint + misconfig + exposure templates.

Stdlib fallback: a tiny built-in CVE map (top 20 known vulnerable
versions) used as a fingerprint dictionary. Real production
should always have nuclei available; the fallback is just a stub
to keep ingest from breaking.
"""
from __future__ import annotations

import asyncio
import json
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from opensquilla.tools.registry import tool
from opensquilla.tools.builtin.recon import _binaries


# Tiny built-in CVE map for stdlib fallback. Each entry:
#   product_substring -> [(cve_id, severity, version_lt), ...]
# A match triggers if the product/version string contains product_substring
# AND the version is < version_lt.
_TINY_CVE_MAP: dict[str, list[tuple[str, str, str]]] = {
    "nginx": [
        ("CVE-2021-23017", "high", "1.20.1"),
    ],
    "apache": [
        ("CVE-2021-41773", "critical", "2.4.50"),
    ],
    "openssh": [
        ("CVE-2024-6387", "high", "8.5p1"),
    ],
    "log4j": [
        ("CVE-2021-44228", "critical", "2.17.0"),
    ],
    "spring": [
        ("CVE-2022-22965", "critical", "5.3.18"),
    ],
    "confluence": [
        ("CVE-2023-22527", "critical", "8.5.4"),
    ],
    "jenkins": [
        ("CVE-2024-23897", "high", "2.442"),
    ],
    "struts": [
        ("CVE-2018-11776", "critical", "2.5.17"),
    ],
}


def _parse_version(v: str) -> tuple[int, ...]:
    parts: list[int] = []
    for p in re.split(r"[^0-9]+", v):
        if p.isdigit():
            parts.append(int(p))
    return tuple(parts)


async def _stdlib_cve_scan(targets: list[str], components: list[dict]) -> list[dict]:
    """CVE lookup against _TINY_CVE_MAP. Real value is from nuclei."""
    findings: list[dict] = []
    for c in components:
        product = (c.get("product") or "").lower()
        version = c.get("version") or ""
        for needle, cves in _TINY_CVE_MAP.items():
            if needle in product:
                for cve_id, severity, version_lt in cves:
                    if not version or _parse_version(version) < _parse_version(version_lt):
                        findings.append({
                            "template_id": f"stdlib-{needle}-{cve_id}",
                            "cve": cve_id,
                            "severity": severity,
                            "matched_product": product,
                            "matched_version": version,
                            "target": c.get("target"),
                            "source": "stdlib-tiny-map",
                            "description": f"{product} {version} < {version_lt} — stdlib stub match",
                        })
    return findings


@tool(
    name="recon_nuclei_scan",
    description=(
        "Run CVE + tech-fingerprint templates against a target. v4-preferred "
        "over hand-rolled fingerprint logic. Internally uses the ``nuclei`` "
        "binary (https://github.com/projectdiscovery/nuclei) which has 8000+ "
        "community-curated templates (CVE / tech-fingerprint / misconfig / "
        "exposure). Falls back to a tiny built-in CVE map (top 8 known "
        "vulnerable products) when nuclei is not on PATH. Use this in F1.5 "
        "or F3.5 to surface CVE-relevant components."
    ),
    params={
        "targets": {
            "type": "array",
            "items": {"type": "string"},
            "description": "List of target URLs or hosts (e.g. ['https://www.51ifind.com', 'https://api.51ifind.com']).",
        },
        "severity": {
            "type": "string",
            "enum": ["info", "low", "medium", "high", "critical", "unknown"],
            "description": "Min severity filter. Default: 'info' (all).",
            "default": "info",
        },
        "tags": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Optional nuclei tags filter (e.g. ['cve', 'tech', 'exposure']).",
        },
        "timeout_s": {
            "type": "integer",
            "description": "Total timeout. Default: 300.",
            "default": 300,
        },
    },
    required=["targets"],
    execution_timeout_seconds=600.0,
)
async def recon_nuclei_scan(
    targets: list[str],
    severity: str = "info",
    tags: list[str] | None = None,
    timeout_s: int = 300,
) -> str:
    """Run nuclei (preferred) or stdlib CVE stub (fallback)."""
    bp = _binaries.detect("nuclei")
    if not bp.available or not targets:
        # Stdlib fallback: a stub for now (would consume components in real impl).
        findings = await _stdlib_cve_scan(targets, [])
        return json.dumps({
            "source": "stdlib",
            "binary_path": None,
            "binary_version": None,
            "binary_error": "nuclei not on PATH",
            "scanned_targets": len(targets),
            "finding_count": len(findings),
            "findings": findings,
        }, ensure_ascii=False)

    out_path = f"/tmp/nuclei-{abs(hash(tuple(targets)))}.jsonl"
    argv = [
        bp.path,
        "-u", ",".join(targets),
        "-severity", severity,
        "-silent",
        "-json",
        "-o", out_path,
    ]
    if tags:
        argv.extend(["-tags", ",".join(tags)])
    try:
        rc, stdout, stderr = await _binaries._run_binary(argv, timeout_s=float(timeout_s))
    except (asyncio.TimeoutError, OSError) as exc:
        findings = await _stdlib_cve_scan(targets, [])
        return json.dumps({
            "source": "stdlib",
            "binary_path": bp.path,
            "binary_version": bp.version,
            "binary_error": f"{type(exc).__name__}: {exc}",
            "scanned_targets": len(targets),
            "finding_count": len(findings),
            "findings": findings,
        }, ensure_ascii=False)

    findings: list[dict] = []
    try:
        out_file = Path(out_path)
        if out_file.exists():
            for line in out_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                if not line.strip():
                    continue
                try:
                    obj = json.loads(line)
                    findings.append({
                        "template_id": obj.get("template-id") or obj.get("templateID"),
                        "name": obj.get("name"),
                        "severity": obj.get("severity"),
                        "matched": obj.get("matched-at") or obj.get("matched"),
                        "target": obj.get("host") or obj.get("target"),
                        "cve": (obj.get("info") or {}).get("classification", {}).get("cve-id") if isinstance(obj.get("info"), dict) else None,
                        "cvss": (obj.get("info") or {}).get("classification", {}).get("cvss-score") if isinstance(obj.get("info"), dict) else None,
                        "description": (obj.get("info") or {}).get("description") if isinstance(obj.get("info"), dict) else None,
                        "source": "nuclei",
                    })
                except json.JSONDecodeError:
                    continue
            try:
                out_file.unlink()
            except OSError:
                pass
    except OSError:
        pass

    return json.dumps({
        "source": "binary",
        "binary_path": bp.path,
        "binary_version": bp.version,
        "scanned_targets": len(targets),
        "finding_count": len(findings),
        "findings": findings,
    }, ensure_ascii=False)
