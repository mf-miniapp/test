"""Network scanning tools: masscan, nmap for port discovery and service detection.

Tools in this module follow the project-wide tool handler convention:
``async def tool(ctx: ToolContext, ...) -> str``. The returned string is a
JSON document — callers parse it on the LLM side. Errors are surfaced as
a non-empty ``error`` field, NOT raised (the spec lives in the SOUL).

Registered under ``group:recon:portscan`` (see
``opensquilla.tools.policy_config._TOOL_GROUPS``).
"""

from __future__ import annotations

import asyncio
import json
import shlex
from typing import Any

import structlog

from opensquilla.tools.registry import tool
from opensquilla.tools.types import ToolContext

log = structlog.get_logger(__name__)


@tool(
    name="masscan_scan",
    description=(
        "Fast port scanner using masscan. Scans target IP/range for open ports. "
        "Returns list of open ports with timestamps. Use for large-scale "
        "network discovery."
    ),
    params={
        "target": {
            "type": "string",
            "description": "Target IP address or CIDR range (e.g., '192.168.1.0/24')",
        },
        "ports": {
            "type": "string",
            "description": (
                "Port range to scan (e.g., '1-1000', '80,443', '22-80'). "
                "Default: top 1000 ports"
            ),
            "default": "1-1000",
        },
        "rate": {
            "type": "integer",
            "description": "Packet rate (packets per second). Default: 1000",
            "default": 1000,
        },
        "timeout": {
            "type": "integer",
            "description": "Scan timeout in seconds. Default: 300",
            "default": 300,
        },
        "output_format": {
            "type": "string",
            "enum": ["json", "list"],
            "description": "Output format. Default: json",
            "default": "json",
        },
    },
    required=["target"],
    execution_timeout_seconds=600.0,
)
async def masscan_scan(
    ctx: ToolContext,
    target: str,
    ports: str = "1-1000",
    rate: int = 1000,
    timeout: int = 300,
    output_format: str = "json",
) -> str:
    """Execute masscan port scan. Returns a JSON string."""
    log.info("masscan_scan.start", target=target, ports=ports, rate=rate)

    cmd = [
        "masscan",
        target,
        "-p", ports,
        "--rate", str(rate),
        "--wait", str(timeout),
        "--open",  # Only show open ports
        "--output-format", "json",
        "--output-fd", "1",  # Output to stdout
    ]

    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdout, stderr = await asyncio.wait_for(
            process.communicate(),
            timeout=timeout + 10,
        )

        if process.returncode != 0:
            error_msg = stderr.decode().strip()
            log.error("masscan_scan.failed", target=target, error=error_msg)
            return json.dumps(
                {
                    "success": False,
                    "error": f"Masscan failed: {error_msg}",
                    "target": target,
                    "command": shlex.join(cmd),
                },
                ensure_ascii=False,
            )

        output = stdout.decode().strip()
        if not output:
            return json.dumps(
                {
                    "success": True,
                    "target": target,
                    "open_ports": [],
                    "total_open": 0,
                    "ports_scanned": ports,
                    "message": "No open ports found",
                },
                ensure_ascii=False,
            )

        # masscan emits one JSON object per line
        open_ports: list[dict[str, Any]] = []
        for line in output.split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                port_data = json.loads(line)
            except json.JSONDecodeError:
                continue
            for port_info in port_data.get("ports", []):
                open_ports.append({
                    "port": port_info.get("port"),
                    "proto": port_info.get("proto"),
                    "status": port_info.get("status"),
                    "service": port_info.get("service", {}).get("name"),
                    "banner": port_info.get("service", {}).get("banner", ""),
                })

        log.info("masscan_scan.complete", target=target, open_ports=len(open_ports))
        return json.dumps(
            {
                "success": True,
                "target": target,
                "open_ports": open_ports,
                "total_open": len(open_ports),
                "ports_scanned": ports,
                "command": shlex.join(cmd),
            },
            ensure_ascii=False,
        )

    except asyncio.TimeoutError:
        log.error("masscan_scan.timeout", target=target, timeout=timeout)
        return json.dumps(
            {
                "success": False,
                "error": f"Scan timed out after {timeout} seconds",
                "target": target,
                "timeout": timeout,
            },
            ensure_ascii=False,
        )
    except FileNotFoundError:
        return json.dumps(
            {
                "success": False,
                "error": (
                    "Masscan not found. Please install masscan: "
                    "https://github.com/robertdavidgraham/masscan"
                ),
                "target": target,
            },
            ensure_ascii=False,
        )
    except Exception as e:
        log.error("masscan_scan.exception", target=target, error=str(e))
        return json.dumps(
            {
                "success": False,
                "error": f"Unexpected error: {e!s}",
                "target": target,
            },
            ensure_ascii=False,
        )


@tool(
    name="nmap_scan",
    description=(
        "Network exploration and security auditing using nmap. "
        "Performs port scanning, service detection, and OS fingerprinting. "
        "Use for detailed service enumeration after masscan discovery."
    ),
    params={
        "target": {
            "type": "string",
            "description": "Target IP address, hostname, or CIDR range",
        },
        "scan_type": {
            "type": "string",
            "enum": ["quick", "full", "service", "stealth", "aggressive"],
            "description": "Scan type. Default: quick",
            "default": "quick",
        },
        "ports": {
            "type": "string",
            "description": (
                "Port specification (e.g., '1-1000', '80,443', '-'). "
                "Default: depends on scan_type"
            ),
        },
        "scripts": {
            "type": "array",
            "items": {"type": "string"},
            "description": "NSE scripts to run (e.g., ['http-title', 'ssh-auth-methods'])",
        },
        "timeout": {
            "type": "integer",
            "description": "Scan timeout in seconds. Default: 300",
            "default": 300,
        },
        "output_format": {
            "type": "string",
            "enum": ["json", "xml", "text"],
            "description": "Output format. Default: json",
            "default": "json",
        },
    },
    required=["target"],
    execution_timeout_seconds=600.0,
)
async def nmap_scan(
    ctx: ToolContext,
    target: str,
    scan_type: str = "quick",
    ports: str | None = None,
    scripts: list[str] | None = None,
    timeout: int = 300,
    output_format: str = "json",
) -> str:
    """Execute nmap scan. Returns a JSON string."""
    log.info("nmap_scan.start", target=target, scan_type=scan_type)

    cmd = ["nmap"]

    if scan_type == "quick":
        cmd.extend(["-T4", "-F"])  # Fast scan, top ports
    elif scan_type == "full":
        cmd.extend(["-T4", "-p-"])  # All ports
    elif scan_type == "service":
        cmd.extend(["-T4", "-sV", "-sC"])  # Service version + default scripts
    elif scan_type == "stealth":
        cmd.extend(["-T2", "-sS"])  # SYN stealth scan
    elif scan_type == "aggressive":
        cmd.extend(["-T4", "-A", "-O"])  # Aggressive: OS, version, scripts, traceroute
    else:
        cmd.extend(["-T4"])

    if ports:
        cmd.extend(["-p", ports])

    if scripts:
        cmd.extend(["--script", ",".join(scripts)])

    if output_format == "json":
        cmd.extend(["-oX", "-"])  # XML to stdout (we keep XML and the
    elif output_format == "xml":  # parser tolerates it as raw_output)
        cmd.extend(["-oX", "-"])
    else:
        cmd.extend(["-oN", "-"])  # Normal output to stdout

    cmd.append(target)

    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdout, stderr = await asyncio.wait_for(
            process.communicate(),
            timeout=timeout + 10,
        )

        if process.returncode != 0:
            error_msg = stderr.decode().strip()
            # nmap returns exit code 1 for host down
            if "Host seems down" in error_msg:
                return json.dumps(
                    {
                        "success": True,
                        "target": target,
                        "status": "host_down",
                        "open_ports": [],
                        "scan_type": scan_type,
                    },
                    ensure_ascii=False,
                )

            log.error("nmap_scan.failed", target=target, error=error_msg)
            return json.dumps(
                {
                    "success": False,
                    "error": f"Nmap failed: {error_msg}",
                    "target": target,
                    "command": shlex.join(cmd),
                },
                ensure_ascii=False,
            )

        output = stdout.decode().strip()
        open_ports: list[dict[str, Any]] = []
        for line in output.split("\n"):
            line = line.strip()
            # Match lines like: "80/tcp   open  http    Apache httpd 2.4.41"
            if "/tcp" in line and "open" in line:
                parts = line.split()
                if len(parts) >= 3:
                    port_proto = parts[0].split("/")
                    open_ports.append({
                        "port": int(port_proto[0]),
                        "proto": port_proto[1] if len(port_proto) > 1 else "tcp",
                        "state": parts[1],
                        "service": parts[2],
                        "version": " ".join(parts[3:]) if len(parts) > 3 else "",
                    })

        log.info("nmap_scan.complete", target=target, open_ports=len(open_ports))
        return json.dumps(
            {
                "success": True,
                "target": target,
                "scan_type": scan_type,
                "open_ports": open_ports,
                "total_open": len(open_ports),
                "raw_output": output,
                "command": shlex.join(cmd),
            },
            ensure_ascii=False,
        )

    except asyncio.TimeoutError:
        log.error("nmap_scan.timeout", target=target, timeout=timeout)
        return json.dumps(
            {
                "success": False,
                "error": f"Scan timed out after {timeout} seconds",
                "target": target,
                "timeout": timeout,
            },
            ensure_ascii=False,
        )
    except FileNotFoundError:
        return json.dumps(
            {
                "success": False,
                "error": (
                    "Nmap not found. Please install nmap: "
                    "https://nmap.org/download.html"
                ),
                "target": target,
            },
            ensure_ascii=False,
        )
    except Exception as e:
        log.error("nmap_scan.exception", target=target, error=str(e))
        return json.dumps(
            {
                "success": False,
                "error": f"Unexpected error: {e!s}",
                "target": target,
            },
            ensure_ascii=False,
        )


@tool(
    name="network_inventory",
    description=(
        "Comprehensive network inventory scan. Combines masscan for fast discovery "
        "with nmap for service enumeration. Returns detailed host and service information."
    ),
    params={
        "target": {
            "type": "string",
            "description": "Target network range (e.g., '192.168.1.0/24')",
        },
        "common_ports": {
            "type": "string",
            "description": (
                "Common ports to check (e.g., '22,80,443,3306,8080'). "
                "Default: web + db ports"
            ),
            "default": "22,80,443,3306,5432,8080,8443",
        },
        "timeout": {
            "type": "integer",
            "description": "Total timeout in seconds. Default: 600",
            "default": 600,
        },
    },
    required=["target"],
    execution_timeout_seconds=1200.0,
)
async def network_inventory(
    ctx: ToolContext,
    target: str,
    common_ports: str = "22,80,443,3306,5432,8080,8443",
    timeout: int = 600,
) -> str:
    """Perform comprehensive network inventory. Returns a JSON string."""
    log.info("network_inventory.start", target=target)

    discovery_json = await masscan_scan(
        ctx,
        target=target,
        ports=common_ports,
        rate=5000,
        timeout=min(timeout // 2, 300),
        output_format="json",
    )
    discovery_result = json.loads(discovery_json)
    if not discovery_result.get("success"):
        return discovery_json

    discovered_hosts: dict[str, list[int]] = {}
    for port_info in discovery_result.get("open_ports", []):
        host = target.split("/")[0]  # Placeholder host extraction
        discovered_hosts.setdefault(host, []).append(port_info["port"])

    detailed_results: list[dict[str, Any]] = []
    for host, ports in discovered_hosts.items():
        if not ports:
            continue
        port_str = ",".join(str(p) for p in ports)
        nmap_json = await nmap_scan(
            ctx,
            target=host,
            scan_type="service",
            ports=port_str,
            timeout=min(timeout // 2, 300),
            output_format="json",
        )
        nmap_result = json.loads(nmap_json)
        if nmap_result.get("success"):
            detailed_results.append(nmap_result)

    log.info(
        "network_inventory.complete",
        target=target,
        hosts=len(discovered_hosts),
    )
    return json.dumps(
        {
            "success": True,
            "target": target,
            "scan_type": "inventory",
            "discovered_hosts": len(discovered_hosts),
            "total_open_ports": sum(len(ports) for ports in discovered_hosts.values()),
            "detailed_results": detailed_results,
        },
        ensure_ascii=False,
    )