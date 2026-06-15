"""TCP port recon tools — pure stdlib ``asyncio.open_connection``.

Group: ``group:recon:portscan``.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from opensquilla.tools.registry import tool


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


@tool(
    name="recon_port_scan_range",
    description=(
        "Probe a list of TCP ports concurrently with bounded fanout. "
        "Returns only the open ports (closed/filtered are omitted from "
        "the output to keep the payload small)."
    ),
    params={
        "ip": {"type": "string", "description": "Target IP address."},
        "ports": {
            "type": "array",
            "items": {"type": "integer"},
            "description": "List of TCP port numbers to probe.",
        },
        "concurrency": {
            "type": "integer",
            "description": "Max concurrent open connections. Default: 100.",
            "default": 100,
        },
        "timeout_s": {
            "type": "number",
            "description": "Per-port connect timeout. Default: 2.0.",
            "default": 2.0,
        },
    },
    required=["ip", "ports"],
    execution_timeout_seconds=120.0,
)
async def recon_port_scan_range(
    ip: str,
    ports: list[int],
    concurrency: int = 100,
    timeout_s: float = 2.0,
) -> str:
    """Concurrent TCP probe over a port list."""
    semaphore = asyncio.Semaphore(concurrency)

    async def _probe(port: int) -> dict[str, Any] | None:
        async with semaphore:
            try:
                _reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=timeout_s,
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
        {"ip": ip, "scanned": len(ports), "open": open_ports, "open_count": len(open_ports)},
        ensure_ascii=False,
    )


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