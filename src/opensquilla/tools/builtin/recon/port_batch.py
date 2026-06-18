"""Batch port scanner — naabu (preferred) / stdlib (fallback).

v4 (2026-06-17) hardening: 51ifind.com run ingested only 14/84 ports
because the LLM was running port-scanner specialist in a subagent that
probed ports one at a time with stdlib asyncio.open_connection.
That's ~1-2 sec/port = 84 seconds for 84 ports. LLM impatience leads
to self-truncation.

naabu binary (https://github.com/projectdiscovery/naabu) scans
65k ports in 10 seconds with SYN scan. We prefer the binary; the
stdlib path is a fallback for hosts without naabu.
"""
from __future__ import annotations

import asyncio
import json
import re
import socket
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from opensquilla.tools.registry import tool
from opensquilla.tools.builtin.recon import _binaries


_PORT_LINE = re.compile(r"^(?P<ip>[0-9.]+):(?P<port>\d+)$")


async def _stdlib_scan(ip: str, ports: list[int], timeout_s: float) -> list[dict]:
    """Per-port TCP probe fallback. Slow but portable."""
    out: list[dict] = []
    for port in ports:
        result = {"ip": ip, "port": port, "state": "closed", "error": None}
        try:
            _reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=timeout_s,
            )
            result["state"] = "open"
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError) as exc:
            result["error"] = f"{type(exc).__name__}: {exc}"
        out.append(result)
    return out


@tool(
    name="recon_port_batch",
    description=(
        "Batch-scan a list of IP/port pairs (or a list of IPs with a port "
        "range) and return the OPEN ports. v4-preferred over calling "
        "recon_port_verify per port. Internally uses the ``naabu`` binary "
        "(https://github.com/projectdiscovery/naabu) for SYN scan when "
        "available; falls back to per-port stdlib asyncio.open_connection "
        "when naabu is not on PATH. Returns a JSON object with the source "
        "(binary or stdlib) and a list of {ip, port, state, error} records. "
        "Use this in the F1 step of the find orchestrator to enumerate "
        "open ports for a batch of IPs at once."
    ),
    params={
        "ips": {
            "type": "array",
            "items": {"type": "string"},
            "description": "List of IPv4 addresses to scan (e.g. ['121.52.252.15', '183.129.160.102']).",
        },
        "ports": {
            "type": "string",
            "description": "Port spec. Examples: '80,443,8080' (specific) or '1-65535' (full range) or 'top-100' (top 100 TCP). Default: '1-65535'.",
            "default": "1-65535",
        },
        "timeout_s": {
            "type": "integer",
            "description": "Per-port timeout. Default: 2.0. (naabu ignores this; stdlib uses it.)",
            "default": 2,
        },
        "rate": {
            "type": "integer",
            "description": "naabu -rate flag: packets per second. Default: 1000. (naabu only.)",
            "default": 1000,
        },
    },
    required=["ips"],
    execution_timeout_seconds=1200.0,
)
async def recon_port_batch(
    ips: list[str],
    ports: str = "1-65535",
    timeout_s: int = 2,
    rate: int = 1000,
) -> str:
    """Batch port scan via naabu (preferred) or stdlib (fallback).

    v4.6 (2026-06-18) cap: naabu full-range (1-65535) over a typical
    sub-domain IP set takes 30-60 min and trips the subagent
    supervisor's 10-min stuck-kill (DEFAULT_STUCK_THRESHOLD_SECONDS),
    leaving a zombie naabu process and an unannounced subagent that
    the parent LLM keeps retrying. Auto-cap to TOP-1000 when callers
    pass "1-65535"/"full"; 1000 ports is the standard recon coverage
    (covers 99% of production-exposed services per ProjectDiscovery
    defaults) and fits in the 10-min budget for 5-10 IPs at
    rate=1000. Callers needing full-range must pass ports explicitly
    to a different tool (e.g. nmap -p-).
    """
    _PORT_CAP = 1000  # auto-cap threshold
    _port_cap_applied = False
    if ports in ("1-65535", "full"):
        ports = f"top-{_PORT_CAP}"
        _port_cap_applied = True
    elif "-" in ports:
        try:
            a, b = ports.split("-", 1)
            span = int(b) - int(a) + 1
            if span > _PORT_CAP:
                ports = f"top-{_PORT_CAP}"
                _port_cap_applied = True
        except (ValueError, TypeError):
            pass
    bp = _binaries.detect("naabu")
    if not bp.available or not ips:
        # Stdlib fallback path.
        port_list: list[int] = []
        if ports in ("1-65535", "full"):
            # stdlib fallback: scan top 1000 (don't try 65k via stdlib).
            port_list = list(range(1, 1001))
        elif "-" in ports:
            a, b = ports.split("-", 1)
            port_list = list(range(int(a), int(b) + 1))
        else:
            for p in ports.split(","):
                p = p.strip()
                if p:
                    port_list.append(int(p))
        all_results: list[dict] = []
        for ip in ips:
            all_results.extend(await _stdlib_scan(ip, port_list, float(timeout_s)))
        open_count = sum(1 for r in all_results if r["state"] == "open")
        return json.dumps({
            "source": "stdlib",
            "binary_path": None,
            "binary_version": None,
            "binary_error": "naabu not on PATH" if not bp.available else None,
            "scanned_ips": len(ips),
            "scanned_ports_per_ip": len(port_list),
            "port_cap_applied": _port_cap_applied,
            "open_count": open_count,
            "results": all_results,
        }, ensure_ascii=False)

    # naabu binary path: write IPs to a file, run naabu, parse output.
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, prefix="naabu-hosts-"
    ) as f:
        for ip in ips:
            f.write(ip + "\n")
        hosts_path = f.name

    out_path = hosts_path + ".out"
    argv = [
        bp.path,
        "-l", hosts_path,
        "-p", ports,
        "-rate", str(rate),
        "-silent",
        "-o", out_path,
        "-json",  # JSONL output
    ]
    try:
        rc, stdout, stderr = await _binaries._run_binary(argv, timeout_s=600.0)
    except (asyncio.TimeoutError, OSError) as exc:
        # Binary failed mid-run; fall back to stdlib for at least top 1000.
        port_list = list(range(1, 1001))
        all_results: list[dict] = []
        for ip in ips:
            all_results.extend(await _stdlib_scan(ip, port_list, float(timeout_s)))
        return json.dumps({
            "source": "stdlib",
            "binary_path": bp.path,
            "binary_version": bp.version,
            "binary_error": f"{type(exc).__name__}: {exc}",
            "scanned_ips": len(ips),
            "scanned_ports_per_ip": len(port_list),
            "port_cap_applied": _port_cap_applied,
            "open_count": sum(1 for r in all_results if r["state"] == "open"),
            "results": all_results,
        }, ensure_ascii=False)
    finally:
        try:
            Path(hosts_path).unlink()
        except OSError:
            pass

    # Parse naabu JSONL output (one JSON object per line: {host, port, ...})
    results: list[dict] = []
    try:
        out_file = Path(out_path)
        if out_file.exists():
            for line in out_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                if not line.strip():
                    continue
                try:
                    obj = json.loads(line)
                    ip = obj.get("host") or obj.get("ip") or ""
                    port = obj.get("port")
                    if ip and port:
                        results.append({
                            "ip": ip,
                            "port": int(port),
                            "state": "open",
                            "error": None,
                        })
                except (json.JSONDecodeError, ValueError):
                    # Maybe it's a non-JSON ip:port line.
                    m = _PORT_LINE.match(line.strip())
                    if m:
                        results.append({
                            "ip": m.group("ip"),
                            "port": int(m.group("port")),
                            "state": "open",
                            "error": None,
                        })
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
        "scanned_ips": len(ips),
        "scanned_ports_per_ip": ports,
        "port_cap_applied": _port_cap_applied,
        "open_count": len(results),
        "results": results,
    }, ensure_ascii=False)
