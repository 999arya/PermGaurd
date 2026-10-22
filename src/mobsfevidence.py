"""Parse MobSF JSON into supporting evidence. Does not score.

MobSF findings are shown beside the PermGuard result. They must never be
passed into ``riskengine.score`` — overlapping permissions would be
double-counted. The MobSF numeric score is copied as-is and labelled
"MobSF score".
"""
from __future__ import annotations

from typing import Any, Iterable, Optional

from .models import PurposeCompatibility, ScanResult

# Agreement labels — wording is "confirmed", not extra risk.
AGREE_BOTH = "confirmed by MobSF"
AGREE_PERMGUARD_ONLY = "only PermGuard"
AGREE_MOBSF_ONLY = "only MobSF"
AGREE_NEITHER = "not flagged"


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _perm_name(raw: str) -> str:
    name = (raw or "").strip()
    if name.startswith("android.permission.") or "." in name:
        return name
    if name:
        return f"android.permission.{name}"
    return name


def _permission_entries(report: dict[str, Any]) -> dict[str, dict[str, str]]:
    """Normalise MobSF permission maps (dict-of-dicts or dict-of-lists)."""
    raw = report.get("permissions") or {}
    out: dict[str, dict[str, str]] = {}
    if isinstance(raw, dict):
        items = raw.items()
    elif isinstance(raw, list):
        items = []
        for item in raw:
            if isinstance(item, str):
                items.append((item, {}))
            elif isinstance(item, dict):
                items.append((item.get("name") or item.get("permission") or "", item))
        items = [(k, v) for k, v in items if k]
    else:
        return out

    for name, info in items:
        status = ""
        desc = ""
        extra = ""
        if isinstance(info, dict):
            status = str(info.get("status") or info.get("protection_level") or "")
            desc = str(info.get("info") or info.get("description") or "")
            extra = str(info.get("description") or "")
        elif isinstance(info, (list, tuple)) and info:
            status = str(info[0] or "")
            if len(info) > 1:
                desc = str(info[1] or "")
            if len(info) > 2:
                extra = str(info[2] or "")
        elif isinstance(info, str):
            status = info
        out[_perm_name(str(name))] = {
            "status": status.lower(),
            "info": desc,
            "description": extra,
        }
    return out


def dangerous_permissions(report: dict[str, Any]) -> list[dict[str, str]]:
    """Permissions MobSF itself marks dangerous / special / signatureOrSystem."""
    flagged = []
    for name, info in _permission_entries(report).items():
        status = info.get("status", "")
        if status in ("dangerous", "signatureorsystem", "signatureorprivileged", "special"):
            flagged.append({
                "name": name,
                "status": status,
                "info": info.get("info") or info.get("description") or "",
            })
    return flagged


def _manifest_issues(report: dict[str, Any]) -> list[dict[str, str]]:
    block = report.get("manifest_analysis") or report.get("manifest") or {}
    findings = []
    if isinstance(block, dict):
        findings = (
            block.get("manifest_findings")
            or block.get("findings")
            or block.get("issues")
            or []
        )
    elif isinstance(block, list):
        findings = block
    out = []
    for item in _as_list(findings):
        if isinstance(item, str):
            out.append({"title": item, "severity": "", "description": ""})
            continue
        if not isinstance(item, dict):
            continue
        title = item.get("title") or item.get("name") or item.get("rule") or "Manifest issue"
        sev = item.get("stat") or item.get("severity") or item.get("level") or ""
        desc = item.get("desc") or item.get("description") or item.get("info") or ""
        if isinstance(title, list):
            title = "; ".join(str(t) for t in title)
        out.append({
            "title": str(title)[:240],
            "severity": str(sev),
            "description": str(desc)[:500],
        })
    return out[:40]


def _exported_components(report: dict[str, Any]) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for key, ctype in (
        ("activities", "activity"),
        ("services", "service"),
        ("receivers", "receiver"),
        ("providers", "provider"),
        ("exported_activities", "activity"),
        ("exported_services", "service"),
        ("exported_receivers", "receiver"),
        ("exported_providers", "provider"),
    ):
        for item in _as_list(report.get(key)):
            name = ""
            exported = None
            if isinstance(item, str):
                name = item
            elif isinstance(item, dict):
                name = str(item.get("name") or item.get("component") or "")
                exported = item.get("exported")
            if not name:
                continue
            # MobSF "exported_*" lists are exported by definition.
            is_exported = True if key.startswith("exported_") else exported
            if is_exported in (True, "true", "1", 1, "exported", None) and key.startswith("exported_"):
                is_exported = True
            if is_exported is True or (key.startswith("exported_") and name):
                out.append({"type": ctype, "name": name})
    # de-dup
    seen = set()
    uniq = []
    for item in out:
        k = (item["type"], item["name"])
        if k in seen:
            continue
        seen.add(k)
        uniq.append(item)
    return uniq[:60]


def _trackers(report: dict[str, Any]) -> dict[str, Any]:
    block = report.get("trackers") or {}
    if not isinstance(block, dict):
        return {"count": 0, "items": []}
    items = []
    for t in _as_list(block.get("trackers") or block.get("detected")):
        if isinstance(t, str):
            items.append({"name": t, "categories": ""})
        elif isinstance(t, dict):
            items.append({
                "name": str(t.get("name") or t.get("id") or "tracker"),
                "categories": ", ".join(_as_list(t.get("categories") or t.get("category"))),
            })
    count = block.get("detected_trackers")
    if count is None:
        count = len(items)
    return {"count": int(count or 0), "items": items[:40]}


def _mobsf_score(report: dict[str, Any]) -> Optional[float]:
    """Copy MobSF's own score as-is. Never blend with PermGuard."""
    appsec = report.get("appsec") or {}
    if isinstance(appsec, dict) and appsec.get("security_score") is not None:
        try:
            return float(appsec["security_score"])
        except (TypeError, ValueError):
            pass
    for key in ("security_score", "average_cvss", "app_score"):
        if report.get(key) is not None:
            try:
                return float(report[key])
            except (TypeError, ValueError):
                continue
    return None


def permguard_flagged_permissions(result: ScanResult) -> set[str]:
    """Permissions PermGuard treats as excessive for the declared purpose."""
    flagged = {
        c.permission
        for c in (result.purpose_compatibility or [])
        if c.verdict == "UNEXPECTED"
    }
    return flagged


def mobsf_flagged_permissions(report: dict[str, Any]) -> set[str]:
    return {p["name"] for p in dangerous_permissions(report)}


def agreement_rows(
    result: ScanResult,
    report: dict[str, Any],
) -> list[dict[str, str]]:
    """Per-permission agreement. Confirmation ≠ extra PermGuard points."""
    pg = permguard_flagged_permissions(result)
    mf = mobsf_flagged_permissions(report)
    names = sorted(pg | mf)
    rows = []
    for name in names:
        in_pg = name in pg
        in_mf = name in mf
        if in_pg and in_mf:
            label = AGREE_BOTH
        elif in_pg:
            label = AGREE_PERMGUARD_ONLY
        else:
            label = AGREE_MOBSF_ONLY
        rows.append({
            "permission": name,
            "agreement": label,
            "permguard": "flagged" if in_pg else "—",
            "mobsf": "dangerous" if in_mf else "—",
        })
    return rows


def extract_runtime_vs_declared(
    report: dict[str, Any],
    declared: Iterable[str],
) -> dict[str, Any]:
    """Experimental dynamic-analysis view. Informational only."""
    declared_set = {_perm_name(p) for p in declared}
    runtime: set[str] = set()
    for key in ("runtime_permissions", "permissions_used", "api_permissions"):
        block = report.get(key)
        if isinstance(block, dict):
            for name, val in block.items():
                used = val
                if isinstance(val, dict):
                    used = val.get("used") or val.get("granted") or val.get("status")
                if used in (True, "true", "granted", "used", "allow", 1, "1"):
                    runtime.add(_perm_name(str(name)))
                elif used not in (False, "false", "denied", 0, "0", None):
                    runtime.add(_perm_name(str(name)))
        elif isinstance(block, list):
            for item in block:
                if isinstance(item, str):
                    runtime.add(_perm_name(item))
                elif isinstance(item, dict):
                    runtime.add(_perm_name(str(item.get("name") or item.get("permission") or "")))
    runtime.discard("")
    return {
        "runtime_used": sorted(runtime),
        "declared_only": sorted(declared_set - runtime),
        "runtime_only": sorted(runtime - declared_set),
        "both": sorted(declared_set & runtime),
    }


def build_evidence(
    report: dict[str, Any],
    result: Optional[ScanResult] = None,
    *,
    source: str = "live",
    notice: str = "",
    experimental_dynamic: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Structured supporting-evidence payload stored on ScanResult.

    ``used`` is True only when we actually have a MobSF (or sample) report.
    """
    declared = []
    if result is not None:
        declared = [p.name for p in result.metadata.permissions]
    dyn = experimental_dynamic or {}
    runtime_view = None
    if dyn.get("report"):
        runtime_view = extract_runtime_vs_declared(dyn["report"], declared)
        runtime_view["error"] = dyn.get("error") or ""
        runtime_view["ok"] = bool(dyn.get("ok"))
    elif dyn.get("error"):
        runtime_view = {"ok": False, "error": dyn.get("error"), "runtime_used": []}

    payload = {
        "used": True,
        "optional": True,
        "badge": "Optional — external cross-check",
        "source": source,  # live | saved_json | sample
        "notice": notice,
        "mobsf_score": _mobsf_score(report),
        "mobsf_score_label": "MobSF score (not blended with PermGuard)",
        "dangerous_permissions": dangerous_permissions(report),
        "manifest_issues": _manifest_issues(report),
        "exported_components": _exported_components(report),
        "trackers": _trackers(report),
        "agreement": agreement_rows(result, report) if result is not None else [],
        "experimental_dynamic": runtime_view,
        "score_unchanged": True,
    }
    return payload


def unused_placeholder(notice: str, source: str = "skipped") -> dict[str, Any]:
    """Not attached to the result — callers should omit evidence entirely."""
    return {
        "used": False,
        "optional": True,
        "source": source,
        "notice": notice,
        "score_unchanged": True,
    }


def purpose_map(compat: list[PurposeCompatibility]) -> dict[str, str]:
    return {c.permission: c.verdict for c in compat}
