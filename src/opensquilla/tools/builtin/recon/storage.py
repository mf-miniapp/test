"""Cloud storage bucket discovery tools (Batch 3, group:recon:storage).

Tools:
  - recon_bucket_naming_variants  Generate candidate bucket names from subdomain/company
  - recon_s3_check                 S3 ListBucket + ACL probe (no auth)
  - recon_oss_check                Alibaba OSS bucket probe
  - recon_gcs_check                Google Cloud Storage bucket probe
  - recon_azure_blob_check         Azure Blob container probe
  - recon_bucket_list_objects      List objects in a public bucket (max N)

Pure-stdlib; no AWS/GCP/Azure SDKs — uses HTTPS requests to public endpoints.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from typing import Any

from opensquilla.tools.registry import tool


# ── helpers ──────────────────────────────────────────


def _http_get(url: str, timeout: float = 5.0, headers: dict[str, str] | None = None) -> dict[str, Any]:
    import ssl

    result: dict[str, Any] = {
        "url": url,
        "status_code": None,
        "body": None,
        "headers": {},
        "error": None,
    }
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, method="GET")
        req.add_header("User-Agent", "hack-deep-find/2.0 (storage)")
        if headers:
            for k, v in headers.items():
                req.add_header(k, v)
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            result["status_code"] = resp.status
            for k, v in resp.headers.items():
                result["headers"].setdefault(k.lower(), v)
            result["body"] = resp.read(2 * 1024 * 1024).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        result["status_code"] = e.code
        try:
            result["body"] = e.read().decode("utf-8", errors="replace")
        except Exception:
            pass
    except Exception as e:  # noqa: BLE001
        result["error"] = f"{type(e).__name__}: {e}"
    return result


# ── 1. recon_bucket_naming_variants ──────────────────


@tool(
    name="recon_bucket_naming_variants",
    description=(
        "Generate ~30 candidate bucket names from a subdomain and company "
        "name. Covers common patterns: {company}, {company}-backup, "
        "{company}-prod, {company}-dev, {company}-logs, "
        "{company}-static, {company}-media, etc."
    ),
    params={
        "subdomain": {"type": "string"},
        "company_name": {"type": "string"},
        "max_variants": {"type": "integer", "default": 30},
    },
    required=["subdomain", "company_name"],
)
async def recon_bucket_naming_variants(
    subdomain: str,
    company_name: str,
    max_variants: int = 30,
) -> str:
    c = re.sub(r"[^a-z0-9-]", "", company_name.lower())
    s = re.sub(r"[^a-z0-9-]", "", subdomain.lower().split(".")[0])
    seeds: list[str] = []
    for base in {c, s}:
        if not base:
            continue
        # strip trailing -prod / -dev / -stg if present
        bare = re.sub(r"-(prod|dev|stg|staging|test|qa|beta|demo)$", "", base)
        seeds.extend(
            [
                bare, f"{bare}-backup", f"{bare}-backups", f"{bare}-db",
                f"{bare}-prod", f"{bare}-production", f"{bare}-dev",
                f"{bare}-staging", f"{bare}-stg", f"{bare}-test",
                f"{bare}-logs", f"{bare}-log", f"{bare}-data",
                f"{bare}-static", f"{bare}-assets", f"{bare}-media",
                f"{bare}-uploads", f"{bare}-files", f"{bare}-images",
                f"{bare}-public", f"{bare}-private", f"{bare}-internal",
                f"{bare}-archive", f"{bare}-dump", f"{bare}-sql",
                f"{bare}-env", f"{bare}-secrets", f"{bare}-config",
            ]
        )
    # dedupe preserving order
    seen: set[str] = set()
    out: list[str] = []
    for v in seeds:
        if v and v not in seen:
            seen.add(v)
            out.append(v)
        if len(out) >= max_variants:
            break
    return json.dumps({"subdomain": subdomain, "company_name": company_name, "variants": out}, ensure_ascii=False)


# ── 2. recon_s3_check ────────────────────────────────


@tool(
    name="recon_s3_check",
    description=(
        "Probe an S3 bucket by issuing an anonymous ListBucket request. "
        "Returns exists/public/region/objects_count/sample_objects. "
        "Does NOT authenticate; relies on public bucket ACL."
    ),
    params={
        "bucket": {"type": "string"},
        "region": {"type": "string", "default": "us-east-1"},
    },
    required=["bucket"],
    execution_timeout_seconds=10.0,
)
async def recon_s3_check(bucket: str, region: str = "us-east-1") -> str:
    url = f"https://{bucket}.s3.{region}.amazonaws.com/?list-type=2&max-keys=10"
    res = _http_get(url)
    out: dict[str, Any] = {
        "provider": "aws",
        "bucket": bucket,
        "region": region,
        "url": url,
    }
    if res["status_code"] == 404:
        out.update({"exists": False, "public": False})
        return json.dumps(out, ensure_ascii=False)
    if res["status_code"] in (403, 401):
        out.update({"exists": True, "public": False, "status_code": res["status_code"]})
        return json.dumps(out, ensure_ascii=False)
    if res["status_code"] == 200 and res["body"]:
        # Parse ListBucketV2 XML
        try:
            root = ET.fromstring(res["body"])
            ns = "{http://s3.amazonaws.com/doc/2006-03-01/}"
            keys = [k.find(f"{ns}Key").text for k in root.iter(f"{ns}Contents") if k.find(f"{ns}Key") is not None]
            out.update(
                {
                    "exists": True,
                    "public": True,
                    "objects_count": len(keys),
                    "sample_objects": keys[:10],
                    "status_code": 200,
                }
            )
        except ET.ParseError:
            out.update({"exists": True, "public": True, "parse_status": "xml_error", "status_code": 200})
    else:
        out.update({"exists": None, "error": res.get("error"), "status_code": res.get("status_code")})
    return json.dumps(out, ensure_ascii=False)


# ── 3. recon_oss_check ───────────────────────────────


@tool(
    name="recon_oss_check",
    description=(
        "Probe an Alibaba Cloud OSS bucket by anonymous ListBucket request. "
        "Returns exists/public/region/objects_count/sample_objects."
    ),
    params={
        "bucket": {"type": "string"},
        "region": {"type": "string", "default": "oss-cn-hangzhou"},
    },
    required=["bucket"],
    execution_timeout_seconds=10.0,
)
async def recon_oss_check(bucket: str, region: str = "oss-cn-hangzhou") -> str:
    endpoint = f"{region}.aliyuncs.com"
    url = f"https://{bucket}.{endpoint}/?max-keys=10"
    res = _http_get(url)
    out: dict[str, Any] = {
        "provider": "oss",
        "bucket": bucket,
        "region": region,
        "url": url,
    }
    if res["status_code"] == 404:
        out.update({"exists": False, "public": False})
        return json.dumps(out, ensure_ascii=False)
    if res["status_code"] in (403, 401):
        out.update({"exists": True, "public": False, "status_code": res["status_code"]})
        return json.dumps(out, ensure_ascii=False)
    if res["status_code"] == 200 and res["body"]:
        try:
            root = ET.fromstring(res["body"])
            keys = [c.text for c in root.iter("Key") if c.text]
            out.update(
                {
                    "exists": True,
                    "public": True,
                    "objects_count": len(keys),
                    "sample_objects": keys[:10],
                    "status_code": 200,
                }
            )
        except ET.ParseError:
            out.update({"exists": True, "public": True, "parse_status": "xml_error", "status_code": 200})
    else:
        out.update({"exists": None, "error": res.get("error"), "status_code": res.get("status_code")})
    return json.dumps(out, ensure_ascii=False)


# ── 4. recon_gcs_check ───────────────────────────────


@tool(
    name="recon_gcs_check",
    description=(
        "Probe a Google Cloud Storage bucket by anonymous ListBucket. "
        "Returns exists/public/objects_count/sample_objects."
    ),
    params={
        "bucket": {"type": "string"},
    },
    required=["bucket"],
    execution_timeout_seconds=10.0,
)
async def recon_gcs_check(bucket: str) -> str:
    url = f"https://storage.googleapis.com/storage/v1/b/{bucket}/o?maxResults=10"
    res = _http_get(url)
    out: dict[str, Any] = {"provider": "gcs", "bucket": bucket, "url": url}
    if res["status_code"] == 404:
        out.update({"exists": False, "public": False})
        return json.dumps(out, ensure_ascii=False)
    if res["status_code"] in (403, 401):
        out.update({"exists": True, "public": False, "status_code": res["status_code"]})
        return json.dumps(out, ensure_ascii=False)
    if res["status_code"] == 200 and res["body"]:
        try:
            doc = json.loads(res["body"])
            items = doc.get("items", [])
            keys = [i.get("name") for i in items if i.get("name")]
            out.update(
                {
                    "exists": True,
                    "public": True,
                    "objects_count": len(items),
                    "sample_objects": keys[:10],
                    "status_code": 200,
                }
            )
        except json.JSONDecodeError:
            out.update({"exists": True, "public": True, "parse_status": "json_error", "status_code": 200})
    else:
        out.update({"exists": None, "error": res.get("error"), "status_code": res.get("status_code")})
    return json.dumps(out, ensure_ascii=False)


# ── 5. recon_azure_blob_check ────────────────────────


@tool(
    name="recon_azure_blob_check",
    description=(
        "Probe an Azure Blob container by anonymous ListBlob. Returns "
        "exists/public/objects_count/sample_objects."
    ),
    params={
        "account": {"type": "string", "description": "Azure storage account name."},
        "container": {"type": "string", "description": "Container name."},
    },
    required=["account", "container"],
    execution_timeout_seconds=10.0,
)
async def recon_azure_blob_check(account: str, container: str) -> str:
    url = f"https://{account}.blob.core.windows.net/{container}?restype=container&comp=list&maxresults=10"
    res = _http_get(url)
    out: dict[str, Any] = {"provider": "azure", "account": account, "container": container, "url": url}
    if res["status_code"] == 404:
        out.update({"exists": False, "public": False})
        return json.dumps(out, ensure_ascii=False)
    if res["status_code"] in (403, 401, 409):
        out.update({"exists": True, "public": False, "status_code": res["status_code"]})
        return json.dumps(out, ensure_ascii=False)
    if res["status_code"] == 200 and res["body"]:
        try:
            root = ET.fromstring(res["body"])
            keys = [b.text for b in root.iter("Name") if b.text]
            out.update(
                {
                    "exists": True,
                    "public": True,
                    "objects_count": len(keys),
                    "sample_objects": keys[:10],
                    "status_code": 200,
                }
            )
        except ET.ParseError:
            out.update({"exists": True, "public": True, "parse_status": "xml_error", "status_code": 200})
    else:
        out.update({"exists": None, "error": res.get("error"), "status_code": res.get("status_code")})
    return json.dumps(out, ensure_ascii=False)


# ── 6. recon_bucket_list_objects ─────────────────────


_SENSITIVE_FILE_PATTERNS: tuple[tuple[re.Pattern[str], str, str], ...] = (
    (re.compile(r"(backup|dump|export).*\.sql(\.gz)?$", re.IGNORECASE), "database_dump", "high"),
    (re.compile(r".*\.bak$|.*\.old$|.*\.swp$", re.IGNORECASE), "backup", "high"),
    (re.compile(r".*\.zip$|.*\.tar\.gz$|.*\.tgz$", re.IGNORECASE), "archive", "medium"),
    (re.compile(r"\.env(\..+)?$|/secrets?\.json$|/credentials(\.json)?$|/\.aws/credentials$", re.IGNORECASE), "credential", "critical"),
    (re.compile(r".*\.pem$|.*\.key$|.*\.p12$|.*\.pfx$", re.IGNORECASE), "key", "critical"),
    (re.compile(r"application\.(properties|yml|yaml)$|config\.(yml|yaml|json)$", re.IGNORECASE), "config", "medium"),
    (re.compile(r".*\.log$", re.IGNORECASE), "log", "low"),
    (re.compile(r".*\.csv$|.*\.tsv$", re.IGNORECASE), "data", "medium"),
)


@tool(
    name="recon_bucket_list_objects",
    description=(
        "List up to max_keys objects in a public bucket (URL pointing to a "
        "list endpoint). Classifies each by sensitive_kind + sensitivity."
    ),
    params={
        "bucket_url": {"type": "string", "description": "Pre-signed or public list URL."},
        "provider": {"type": "string", "enum": ["aws", "oss", "gcs", "azure", "minio", "aliyun"]},
        "max_keys": {"type": "integer", "default": 100},
    },
    required=["bucket_url", "provider"],
    execution_timeout_seconds=30.0,
)
async def recon_bucket_list_objects(
    bucket_url: str,
    provider: str,
    max_keys: int = 100,
) -> str:
    res = _http_get(bucket_url)
    if res["status_code"] != 200 or not res["body"]:
        return json.dumps(
            {"status_code": res["status_code"], "error": res.get("error"), "objects": []},
            ensure_ascii=False,
        )
    keys: list[str] = []
    try:
        if provider == "gcs":
            doc = json.loads(res["body"])
            keys = [i.get("name") for i in doc.get("items", []) if i.get("name")]
        else:
            root = ET.fromstring(res["body"])
            for tag in ("Key", "Name"):
                keys.extend([n.text for n in root.iter(tag) if n.text])
    except Exception as e:  # noqa: BLE001
        return json.dumps(
            {"status_code": res["status_code"], "error": f"parse: {e}", "objects": []},
            ensure_ascii=False,
        )
    keys = sorted(set(keys))[:max_keys]
    objects: list[dict[str, Any]] = []
    for k in keys:
        sensitive_kind = "other"
        sensitivity = "low"
        for pat, kind, sens in _SENSITIVE_FILE_PATTERNS:
            if pat.search(k):
                sensitive_kind, sensitivity = kind, sens
                break
        objects.append(
            {
                "filename": k,
                "sensitive_kind": sensitive_kind,
                "sensitivity": sensitivity,
            }
        )
    return json.dumps(
        {"status_code": 200, "provider": provider, "objects": objects, "total": len(objects)},
        ensure_ascii=False,
    )
