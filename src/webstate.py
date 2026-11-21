"""Browser-carried, signed state and per-browser history for Vercel workers."""
from __future__ import annotations

import base64
from typing import Any

from itsdangerous import BadSignature, URLSafeSerializer

from .models import ScanResult


def encode(value: Any) -> Any:
    """Recursively encode complex objects (ScanResult, bytes) for JSON serialization."""
    if isinstance(value, ScanResult):
        return {"__scan__": value.model_dump(mode="json")}
    if isinstance(value, bytes):
        return {"__bytes__": base64.b64encode(value).decode("ascii")}
    if isinstance(value, dict):
        return {k: encode(v) for k, v in value.items() if k != "_uploads"}
    if isinstance(value, (list, tuple)):
        return [encode(v) for v in value]
    return value


def decode(value: Any) -> Any:
    """Recursively decode serialized dictionary structures back into objects."""
    if isinstance(value, dict):
        if set(value) == {"__scan__"}:
            return ScanResult.model_validate(value["__scan__"])
        if set(value) == {"__bytes__"}:
            return base64.b64decode(value["__bytes__"])
        return {k: decode(v) for k, v in value.items()}
    if isinstance(value, list):
        return [decode(v) for v in value]
    return value


def dump_state(state: dict[str, Any], secret: str, identity: str) -> str:
    """Serialize and sign state with URLSafeSerializer."""
    return URLSafeSerializer(secret, salt=f"permguard-dashboard:{identity}").dumps(encode(state))


def load_state(token: str, secret: str, identity: str) -> dict[str, Any]:
    """Verify signature and deserialize state."""
    value = URLSafeSerializer(secret, salt=f"permguard-dashboard:{identity}").loads(token)
    if not isinstance(value, dict):
        raise BadSignature("Invalid dashboard state")
    return decode(value)


class BrowserStore:
    """In-memory or browser-carried scan history store."""

    def __init__(self, state: dict[str, Any]) -> None:
        self.rows: dict[str, dict[str, Any]] = state.setdefault("_history", {})

    def save(self, result: ScanResult, keep_full: bool = False) -> None:
        r = result
        self.rows[r.scan_id] = {
            "scan_id": r.scan_id,
            "scanned_at": r.scan_finished_at,
            "filename": r.metadata.filename,
            "package_name": r.metadata.package_name,
            "app_label": r.metadata.app_label,
            "category": r.purpose.category if r.purpose else None,
            "input_type": r.metadata.input_type,
            "scan_mode": r.scan_mode,
            "scan_depth": r.scan_depth_used,
            "risk_score": r.risk.score,
            "risk_level": r.risk.level.value,
            "permission_count": len(r.metadata.permissions),
            "finding_count": len(r.findings),
            "critical_count": r.severity_counts.get("CRITICAL",0),
            "high_count": r.severity_counts.get("HIGH", 0),
        }
        while len(self.rows) > 200:
            del self.rows[next(iter(self.rows))]

    def list_scans(self, limit: int = 200) -> list[dict[str, Any]]:
        return sorted(self.rows.values(), key=lambda x: x["risk_score"], reverse=True)[:limit]

    def count(self) -> int:
        return len(self.rows)

    def get(self, key: str) -> dict[str, Any] | None:
        return self.rows.get(key)

    def delete(self, key: str) -> bool:
        return self.rows.pop(key, None) is not None

    def delete_all(self) -> int:
        count = len(self.rows)
        self.rows.clear()
        return count


class BrowserCache:
    """Client-carried cache for recent scan results."""

    def __init__(self, state: dict[str, Any]) -> None:
        self.rows: dict[str, ScanResult] = state.setdefault("_scan_cache", {})

    def _key(self, *args: Any) -> str:
        return "|".join(str(x or "") for x in args)

    def get(self, *args: Any) -> ScanResult | None:
        result = self.rows.get(self._key(*args))
        return result.model_copy(deep=True) if result else None

    def put(self, result: ScanResult, *args: Any) -> None:
        self.rows[self._key(*args)] = result.model_copy(deep=True)
        # Keep signed responses small enough for serverless request limits
        while len(self.rows) > 6:
            del self.rows[next(iter(self.rows))]
