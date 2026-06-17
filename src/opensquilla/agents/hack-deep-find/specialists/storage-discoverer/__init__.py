"""storage-discoverer specialist (v4, 2026-06-17).

Renamed from cloud-storage. v4 keeps the same scope (sub_domain ->
storage + storage_object) but uses a v4-canonical name. The v3
directory cloud-storage/ stays on disk for reference; the clone
script does not register it in config.toml.

The SOUL_BODY.md describes the same tools and workflow (sub_domain
in, S3/OSS/GCS/Azure blob discovery + per-bucket object listing).
"""

from __future__ import annotations

from pathlib import Path

_HERE = Path(__file__).parent

SOUL_BODY: str = (_HERE / "SOUL_BODY.md").read_text(encoding="utf-8")


def reload() -> None:
    global SOUL_BODY
    SOUL_BODY = (_HERE / "SOUL_BODY.md").read_text(encoding="utf-8")


__all__ = ["SOUL_BODY", "reload"]
