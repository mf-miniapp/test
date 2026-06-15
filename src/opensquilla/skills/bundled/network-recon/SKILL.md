---
name: network-recon
description: "Network reconnaissance and port scanning using masscan and nmap. Trigger on 'scan network', 'find open ports', 'network discovery', 'port scan', 'service enumeration'. Combines fast masscan discovery with detailed nmap service detection."
homepage: ""
provenance:
  origin: opensquilla-internal
  license: MIT-0
  upstream_url: https://github.com/opensquilla/opensquilla
  maintained_by: OpenSquilla
metadata:
  {
    "platform":
      {
        "emoji": "🔍",
      },
  }
---

# network-recon

Perform network reconnaissance and port scanning using masscan and nmap. This skill provides a structured approach to network discovery and service enumeration.

## When to Use

| Need | Use |
|---|---|
| Quick port scan of a single host | `masscan_scan` or `nmap_scan` |
| Large network discovery (Class C, B) | `masscan_scan` with CIDR range |
| Detailed service enumeration | `nmap_scan` with `scan_type=service` |
| Comprehensive network inventory | `network_inventory` |
| OS fingerprinting | `nmap_scan` with `scan_type=aggressive` |

## Available Tools

### 1. `masscan_scan`
**Purpose**: Fast port scanning for large networks
**Best for**: Initial discovery, scanning large IP ranges quickly
**Parameters**:
- `target`: IP address or CIDR range (required)
- `ports`: Port range (default: 1-1000)
- `rate`: Packets per second (default: 1000)
- `timeout`: Scan timeout in seconds (default: 300)

**Example**:
```json
{
  "target": "192.168.1.0/24",
  "ports": "22,80,443,3306,8080",
  "rate": 5000
}
```

### 2. `nmap_scan`
**Purpose**: Detailed service detection and OS fingerprinting
**Best for**: After masscan discovery, for service enumeration
**Parameters**:
- `target`: IP address or hostname (required)
- `scan_type`: quick|full|service|stealth|aggressive (default: quick)
- `ports`: Specific ports to scan
- `scripts`: NSE scripts to run
- `timeout`: Scan timeout (default: 300)

**Example**:
```json
{
  "target": "192.168.1.100",
  "scan_type": "service",
  "ports": "80,443,8080",
  "scripts": ["http-title", "http-headers"]
}
```

### 3. `network_inventory`
**Purpose**: Comprehensive network inventory combining both tools
**Best for**: Full network assessment
**Parameters**:
- `target`: Network range (required)
- `common_ports`: Ports to check (default: web + db ports)
- `timeout`: Total timeout (default: 600)

## Workflow

### Basic Network Discovery
1. **Fast Scan**: Use `masscan_scan` for initial discovery
   ```json
   {"target": "10.0.0.0/24", "ports": "1-1000"}
   ```

2. **Service Enumeration**: Use `nmap_scan` on discovered hosts
   ```json
   {"target": "10.0.0.15", "scan_type": "service"}
   ```

### Detailed Assessment
1. **Inventory**: Use `network_inventory` for comprehensive scan
   ```json
   {"target": "172.16.0.0/24", "common_ports": "22,80,443,3306,5432,8080,8443"}
   ```

2. **Deep Scan**: Follow up with aggressive nmap on interesting hosts
   ```json
   {"target": "172.16.0.50", "scan_type": "aggressive"}
   ```

## Output Format

All tools return structured JSON with:
- `success`: Boolean indicating if scan completed
- `data`: Scan results (open ports, services, etc.)
- `metadata`: Command executed, target, timestamps

## Error Handling

- **Host Down**: Returns empty results with status "host_down"
- **Timeout**: Returns error with timeout details
- **Tool Missing**: Provides installation instructions
- **Permission Denied**: May require elevated privileges for SYN scans

## Legal Notice

⚠️ **Authorization Required**: Only scan networks you own or have explicit permission to test. Unauthorized scanning may violate laws and regulations.

## Tips

1. **Start with masscan** for large networks (faster)
2. **Use nmap service detection** after discovery
3. **Combine tools** for comprehensive assessment
4. **Adjust rates** based on network speed and stealth requirements
5. **Use scripts** for additional service information