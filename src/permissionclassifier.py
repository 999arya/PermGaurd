"""Permission classifier — attaches knowledge-base context to permissions.

Feeds each extracted permission its documented description, Android
protection level, PermissionGuard sensitivity tier, runtime category,
legitimate uses, excess conditions and less-intrusive alternatives.

The sensitivity tier is PermissionGuard's own privacy-risk rating and is
kept DISTINCT from Android's official protection level: a `normal`
permission may still be privacy-relevant (e.g. INTERNET as an exfiltration
channel), and a `dangerous` permission may be perfectly ordinary for the
right app.
"""
from __future__ import annotations

from typing import Any, Optional

from .knowledgebase import KnowledgeBase, permission_entry
from .models import (
    ApkMetadata,
    Permission,
    ProtectionLevel,
    RuntimeCategory,
    SensitivityTier,
)

_PROTECTION_MAP = {
    "normal": ProtectionLevel.NORMAL,
    "dangerous": ProtectionLevel.DANGEROUS,
    "signature": ProtectionLevel.SIGNATURE,
    "signatureorsystem": ProtectionLevel.SIGNATURE_OR_SYSTEM,
    "signature_or_system": ProtectionLevel.SIGNATURE_OR_SYSTEM,
    "internal": ProtectionLevel.INTERNAL,
}

_RUNTIME_MAP = {
    "install-time": RuntimeCategory.INSTALL_TIME,
    "install_time": RuntimeCategory.INSTALL_TIME,
    "runtime": RuntimeCategory.RUNTIME,
    "special": RuntimeCategory.SPECIAL,
    "signature": RuntimeCategory.SIGNATURE,
}

_SENSITIVITY_MAP = {
    "none": SensitivityTier.NONE,
    "low": SensitivityTier.LOW,
    "moderate": SensitivityTier.MODERATE,
    "high": SensitivityTier.HIGH,
    "critical": SensitivityTier.CRITICAL,
}


def _safe_enum(mapping: dict[str, Any], value: Any, fallback):
    try:
        return mapping.get(str(value).lower().strip(), fallback)
    except AttributeError:  # pragma: no cover
        return fallback


def classify_permission(perm: Permission, kb: KnowledgeBase) -> Permission:
    """Populate a single permission with knowledge-base context."""
    entry: Optional[dict[str, Any]] = permission_entry(kb, perm.name)

    if perm.custom:
        # custom app-defined permission — inherit declared protection level
        perm.sensitivity = SensitivityTier.MODERATE
        perm.description = (
            "Custom permission defined by this application (not a platform "
            "permission). Its protection level is decided by the developer."
        )
        perm.known_to_android = False
        perm.notes = perm.notes or "Custom permission — review its protection level."
        return perm

    if entry is None:
        perm.known_to_android = False
        perm.description = "Permission not present in the knowledge base."
        perm.sensitivity = SensitivityTier.MODERATE
        perm.notes = (
            "Unknown permission — classification may be incomplete. It may be "
            "an OEM/vendor permission or a newer platform permission."
        )
        return perm

    perm.description = entry.get("description", "")
    perm.protection_level = _safe_enum(_PROTECTION_MAP, entry.get("protection_level"), ProtectionLevel.UNKNOWN)
    perm.runtime_category = _safe_enum(_RUNTIME_MAP, entry.get("runtime_category"), RuntimeCategory.UNKNOWN)
    perm.sensitivity = _safe_enum(_SENSITIVITY_MAP, entry.get("sensitivity"), SensitivityTier.LOW)
    perm.data_or_functionality = entry.get("data_or_functionality", "")
    perm.legitimate_uses = list(entry.get("legitimate_uses", []))
    perm.excess_conditions = list(entry.get("excess_conditions", []))
    perm.alternatives = list(entry.get("alternatives", []))
    perm.doc_urls = list(entry.get("doc_urls", []))
    perm.notes = entry.get("notes", "")
    perm.known_to_android = True
    return perm


def classify_metadata(meta: ApkMetadata, kb: KnowledgeBase) -> ApkMetadata:
    """Classify every permission in a metadata object (in place)."""
    for perm in meta.permissions:
        classify_permission(perm, kb)

    # A manifest may declare custom permissions; reflect them as permission
    # objects too so they appear in the inventory.
    existing = {p.name for p in meta.permissions}
    for custom in meta.custom_permissions:
        name = custom.get("name")
        if not name or name in existing:
            continue
        perm = Permission(name=name, custom=True)
        level_raw = str(custom.get("protection_level", "unknown"))
        perm.protection_level = _PROTECTION_MAP.get(level_raw, ProtectionLevel.UNKNOWN)
        perm.description = (
            f"Custom permission declared by this app (protection level: "
            f"{custom.get('protection_level_raw', level_raw)})."
        )
        if perm.protection_level in (ProtectionLevel.NORMAL, ProtectionLevel.UNKNOWN):
            perm.sensitivity = SensitivityTier.HIGH
            perm.notes = (
                "Custom permission with a weak protection level — any app "
                "holding it can exercise whatever it guards."
            )
        else:
            perm.sensitivity = SensitivityTier.MODERATE
        perm.known_to_android = False
        meta.permissions.append(perm)
        existing.add(name)

    return meta


def sensitivity_summary(meta: ApkMetadata) -> dict[str, int]:
    counts = {t.value: 0 for t in SensitivityTier}
    for p in meta.permissions:
        counts[p.sensitivity.value] = counts.get(p.sensitivity.value, 0) + 1
    return counts


def expected_permissions_for_category(kb: KnowledgeBase, category: Optional[str]) -> tuple[set[str], set[str]]:
    """Return (expected, optional) permission sets for a category key."""
    from .knowledgebase import category_entry

    entry = category_entry(kb, category or "")
    if not entry:
        return set(), set()
    expected = set(entry.get("expected_permissions", []))
    optional = set(entry.get("optional_permissions", []))
    return expected, optional
