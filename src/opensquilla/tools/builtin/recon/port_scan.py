"""TCP port recon tools — naabu (preferred) / masscan (large-scale) / stdlib (fallback).

Group: ``group:recon:portscan``.

v4.4 (2026-06-18) hardening: naabu binary
(https://github.com/projectdiscovery/naabu) does SYN scan at
1k-10k pps. masscan binary
(https://github.com/robertdavidgraham/masscan) does
Internet-scale scans (10M pps). Stdlib asyncio.open_connection
is the FALLBACK for hosts without either binary. The routing:
  - ip + ports (≤500)        -> naabu
  - ip + ports (>500 / full) -> masscan if available, else naabu
  - single port verify       -> stdlib (overhead too high to spawn binary)
"""

from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path
from typing import Any

from opensquilla.tools.registry import tool
from opensquilla.tools.builtin.recon import _binaries


@tool(
    name="recon_port_scan_tcp",
    description=(
        "Probe a single TCP port on a target IP. Returns `state` = "
        "`open` if a TCP connection completes within `timeout_s`, else "
        "`closed`. Does NOT send application data, does NOT grab banner "
        "(use `recon_grab_banner` for that)."
    ),
    params={
        "ip": {"type": "string", "description": "Target IPv4 or IPv6 address."},
        "port": {"type": "integer", "description": "TCP port number (1-65535)."},
        "timeout_s": {
            "type": "number",
            "description": "Connect timeout in seconds. Default: 2.0.",
            "default": 2.0,
        },
    },
    required=["ip", "port"],
    execution_timeout_seconds=15.0,
)
async def recon_port_scan_tcp(ip: str, port: int, timeout_s: float = 2.0) -> str:
    """Probe one TCP port."""
    result: dict[str, Any] = {"ip": ip, "port": port, "state": "closed", "error": None}
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout_s,
        )
        result["state"] = "open"
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001 — best-effort close
            pass
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError) as exc:
        result["state"] = "closed"
        result["error"] = f"{type(exc).__name__}: {exc}"

    return json.dumps(result, ensure_ascii=False)


async def _parse_naabu_text(text: str) -> list[dict[str, Any]]:
    """Parse naabu plain-text output. One 'ip:port' per line.

    naabu -json emits richer records; we accept the plain format here
    because the range tool is bandwidth-conscious.
    """
    out: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        try:
            host, p = line.rsplit(":", 1)
            out.append({"ip": host, "port": int(p), "state": "open"})
        except ValueError:
            continue
    return out


async def _parse_masscan_text(text: str) -> list[dict[str, Any]]:
    """Parse masscan plain-text output. Format: 'open tcp PORT IP TIMESTAMP'"""
    out: list[dict] = []
    for line in text.splitlines():
        parts = line.strip().split()
        if len(parts) >= 4 and parts[0] == "open":
            try:
                port = int(parts[2])
                ip = parts[3]
                out.append({"ip": ip, "port": port, "state": "open"})
            except (ValueError, IndexError):
                continue
    return out


@tool(
    name="recon_port_scan_range",
    description=(
        "Probe a list of TCP ports. v4.4-preferred: routes to naabu "
        "(SYN scan, fast) for normal ranges, masscan (Internet-scale) "
        "for >500 ports. Falls back to stdlib asyncio.open_connection "
        "when neither binary is on PATH. Returns only the open ports "
        "as a JSON list of {ip, port, state} records."
    ),
    params={
        "ip": {"type": "string", "description": "Target IP address."},
        "ports": {
            "type": "array",
            "items": {"type": "integer"},
            "description": "List of TCP port numbers to probe.",
        },
        "rate": {
            "type": "integer",
            "description": "naabu -rate / masscan --rate. Packets/sec. Default: 1000.",
            "default": 1000,
        },
        "timeout_s": {
            "type": "integer",
            "description": "Total scan timeout. Default: 60.",
            "default": 60,
        },
    },
    required=["ip", "ports"],
    execution_timeout_seconds=300.0,
)
async def recon_port_scan_range(
    ip: str,
    ports: list[int],
    rate: int = 1000,
    timeout_s: int = 60,
) -> str:
    """Range port scan via naabu/masscan (preferred) or stdlib (fallback)."""
    if not ports:
        return json.dumps({
            "ip": ip, "scanned": 0, "open": [], "open_count": 0,
            "source": "noop",
        }, ensure_ascii=False)

    # Pick binary by port count. >500 → masscan if available.
    if len(ports) > 500:
        bp = _binaries.detect("masscan")
        if bp.available:
            try:
                port_spec = ",".join(str(p) for p in ports)
                rc, stdout, stderr = await _binaries._run_binary(
                    ["masscan", ip, "-p", port_spec, "--rate", str(rate),
                     "-oL", "-", "--wait", "1"],
                    timeout_s=timeout_s,
                )
                open_ports = await _parse_masscan_text(stdout)
                return json.dumps({
                    "ip": ip, "scanned": len(ports), "open": open_ports,
                    "open_count": len(open_ports), "source": "masscan",
                    "binary_version": bp.version,
                }, ensure_ascii=False)
            except (asyncio.TimeoutError, OSError) as exc:
                pass  # fall through

    bp = _binaries.detect("naabu")
    if bp.available:
        try:
            port_spec = ",".join(str(p) for p in ports)
            rc, stdout, stderr = await _binaries._run_binary(
                ["naabu", "-host", ip, "-p", port_spec, "-rate", str(rate),
                 "-silent", "-no-stdin"],
                timeout_s=timeout_s,
            )
            open_ports = await _parse_naabu_text(stdout)
            return json.dumps({
                "ip": ip, "scanned": len(ports), "open": open_ports,
                "open_count": len(open_ports), "source": "naabu",
                "binary_version": bp.version,
            }, ensure_ascii=False)
        except (asyncio.TimeoutError, OSError) as exc:
            pass  # fall through to stdlib

    # Stdlib fallback.
    semaphore = asyncio.Semaphore(100)

    async def _probe(port: int) -> dict[str, Any] | None:
        async with semaphore:
            try:
                _reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port), timeout=2.0,
                )
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:  # noqa: BLE001
                    pass
                return {"ip": ip, "port": port, "state": "open"}
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return None

    results = await asyncio.gather(*[_probe(p) for p in ports])
    open_ports = [r for r in results if r is not None]
    return json.dumps(
        {"ip": ip, "scanned": len(ports), "open": open_ports,
         "open_count": len(open_ports), "source": "stdlib"},
        ensure_ascii=False,
    )





@tool(
    name="recon_port_verify",
    description=(
        "Verify a single TCP port is reachable. Thin wrapper around "
        "recon_port_scan_tcp that returns a ``verified`` boolean envelope "
        "suitable for the AssetTree add_node ``verification`` contract: "
        "PORT / SERVICE / URL nodes require ``verification.verified == true`` "
        "at add time. Returns ``verified=true`` ONLY if the TCP handshake "
        "completes within timeout. Returns ``verified=false`` with "
        "``reason`` on timeout / connection refused / DNS failure."
    ),
    params={
        "ip": {"type": "string", "description": "Target IPv4 or IPv6 address."},
        "port": {"type": "integer", "description": "TCP port number (1-65535)."},
        "timeout_s": {
            "type": "number",
            "description": "Connect timeout in seconds. Default: 3.0 (more generous than recon_port_scan_tcp's 2.0; we want to be sure a port is closed before rejecting it from the tree).",
            "default": 3.0,
        },
    },
    required=["ip", "port"],
    execution_timeout_seconds=15.0,
)
async def recon_port_verify(
    ip: str,
    port: int,
    timeout_s: float = 3.0,
) -> str:
    """Verify one TCP port is open.

    Returns a dict with:
      - verified: bool   (true only if TCP handshake completes)
      - reason: str      ("ok" if verified, else "timeout" / "connection_refused" / "dns_error" / "os_error")
      - probe:  {state: "open"|"closed", error: str|null}
      - verified_at: iso_ts
    """
    from datetime import datetime, timezone

    result: dict[str, Any] = {
        "ip": ip,
        "port": port,
        "verified": False,
        "reason": None,
        "probe": {"state": "closed", "error": None},
        "verified_at": None,
    }

    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout_s,
        )
        result["probe"]["state"] = "open"
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001 — best-effort close
            pass
        result["reason"] = "ok"
        result["verified"] = True
    except asyncio.TimeoutError:
        result["probe"]["error"] = "timeout"
        result["reason"] = "timeout"
    except ConnectionRefusedError as exc:
        result["probe"]["error"] = f"ConnectionRefusedError: {exc}"
        result["reason"] = "connection_refused"
    except OSError as exc:
        # Includes DNS resolution failures, network unreachable, etc.
        result["probe"]["error"] = f"{type(exc).__name__}: {exc}"
        err_name = type(exc).__name__
        if "gaierror" in err_name.lower() or "getaddrinfo" in str(exc).lower():
            result["reason"] = "dns_error"
        else:
            result["reason"] = "os_error"
    except Exception as exc:  # noqa: BLE001 — catch-all for unexpected
        result["probe"]["error"] = f"{type(exc).__name__}: {exc}"
        result["reason"] = "unexpected_error"

    result["verified_at"] = datetime.now(timezone.utc).isoformat()
    return json.dumps(result, ensure_ascii=False)



@tool(
    name="recon_grab_banner",
    description=(
        "Open a TCP connection to `ip:port`, read up to 1 KiB, return the "
        "raw banner string (decoded as UTF-8, errors='ignore'). Used to "
        "identify service types (SSH, HTTP, FTP, MySQL, etc.) without "
        "issuing a protocol-specific request."
    ),
    params={
        "ip": {"type": "string", "description": "Target IP."},
        "port": {"type": "integer", "description": "TCP port."},
        "timeout_s": {
            "type": "number",
            "description": "Read timeout in seconds. Default: 3.0.",
            "default": 3.0,
        },
    },
    required=["ip", "port"],
    execution_timeout_seconds=10.0,
)
async def recon_grab_banner(ip: str, port: int, timeout_s: float = 3.0) -> str:
    """Grab a service banner."""
    result: dict[str, Any] = {"ip": ip, "port": port, "banner": None, "error": None}
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout_s,
        )
        data = await asyncio.wait_for(reader.read(1024), timeout=timeout_s)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass
        result["banner"] = data.decode("utf-8", errors="ignore").strip() or None
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError) as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"

    return json.dumps(result, ensure_ascii=False)