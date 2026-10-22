"""Local scan-result cache keyed by APK content hash.

Repeat scans of the same bytes return instantly. Cache files live under
``data/scan_cache/`` (gitignored via data/*.db and we also skip JSON in
.gitignore only if needed — filenames are hashes, no APK bytes stored).

The cached object is the PermGuard ``ScanResult`` JSON plus optional
supporting evidence. Reloading never re-scores; it restores the original
offline score unchanged.
"""
from __future__ import annotations

import hashlib
import json
import os
from typing import Any, Optional

from .models import ScanResult

_DEFAULT_DIR = os.path.join("data", "scan_cache")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _key(apk_sha256: str, category: str, scan_mode: str, environment: str) -> str:
    raw = f"{apk_sha256}|{category or ''}|{scan_mode or 'auto'}|{environment or 'low'}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class ScanCache:
    def __init__(self, directory: Optional[str] = None):
        self.directory = directory or _DEFAULT_DIR
        os.makedirs(self.directory, exist_ok=True)

    def _path(self, key: str) -> str:
        return os.path.join(self.directory, f"{key}.json")

    def get(
        self,
        apk_sha256: str,
        category: str = "",
        scan_mode: str = "auto",
        environment: str = "low",
    ) -> Optional[ScanResult]:
        path = self._path(_key(apk_sha256, category, scan_mode, environment))
        if not os.path.isfile(path):
            return None
        try:
            with open(path, encoding="utf-8") as fh:
                doc = json.load(fh)
            return ScanResult.model_validate(doc)
        except (OSError, ValueError, json.JSONDecodeError):
            return None

    def put(
        self,
        result: ScanResult,
        apk_sha256: str,
        category: str = "",
        scan_mode: str = "auto",
        environment: str = "low",
    ) -> str:
        path = self._path(_key(apk_sha256, category, scan_mode, environment))
        payload: dict[str, Any] = result.model_dump(mode="json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False)
        return path
