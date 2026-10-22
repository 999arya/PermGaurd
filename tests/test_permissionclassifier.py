"""Permission classification + purpose-aware checks."""
from __future__ import annotations

from src.models import (
    ApkMetadata,
    Permission,
    PurposeProfile,
    ProtectionLevel,
    SensitivityTier,
)
from src.permissionclassifier import classify_metadata, classify_permission
from src.purposeanalyzer import (
    JUSTIFIED,
    PLAUSIBLE,
    UNDETERMINED,
    UNEXPECTED,
    assess_compatibility,
    infer_category,
)


def test_known_permission_classified(kb):
    p = Permission(name="android.permission.READ_SMS")
    classify_permission(p, kb)
    assert p.known_to_android is True
    assert p.sensitivity == SensitivityTier.CRITICAL
    assert p.protection_level == ProtectionLevel.DANGEROUS
    assert p.description
    assert p.doc_urls


def test_normal_permission_is_not_automatically_dangerous(kb):
    """Distinguish Android protection level from our sensitivity tier."""
    p = Permission(name="android.permission.VIBRATE")
    classify_permission(p, kb)
    assert p.protection_level == ProtectionLevel.NORMAL
    assert p.sensitivity in (SensitivityTier.LOW, SensitivityTier.NONE)


def test_unknown_permission_flagged(kb):
    p = Permission(name="android.permission.SOME_OEM_THING")
    classify_permission(p, kb)
    assert p.known_to_android is False
    assert p.sensitivity != SensitivityTier.NONE  # conservative default
    assert p.notes  # uncertainty noted


def test_custom_permission_detected(kb):
    meta = ApkMetadata(package_name="com.x")
    meta.custom_permissions = [
        {"name": "com.x.CUSTOM", "protection_level": "normal",
         "protection_level_raw": "normal"}
    ]
    classify_metadata(meta, kb)
    custom = next(p for p in meta.permissions if p.name == "com.x.CUSTOM")
    assert custom.custom is True
    assert custom.known_to_android is False
    # weak custom permission should raise sensitivity (escalation concern)
    assert custom.sensitivity == SensitivityTier.HIGH


def test_justified_for_navigation(kb):
    meta = ApkMetadata(package_name="com.nav")
    meta.permissions = [
        Permission(name="android.permission.ACCESS_FINE_LOCATION"),
        Permission(name="android.permission.INTERNET"),
    ]
    classify_metadata(meta, kb)
    purpose = PurposeProfile(category="navigation", source="user")
    verdicts = {c.permission: c.verdict
                for c in assess_compatibility(meta, purpose, kb)}
    assert verdicts["android.permission.ACCESS_FINE_LOCATION"] == JUSTIFIED
    assert verdicts["android.permission.INTERNET"] == JUSTIFIED


def test_unexpected_for_calculator(kb):
    meta = ApkMetadata(package_name="com.calc")
    meta.permissions = [
        Permission(name="android.permission.READ_CONTACTS"),
        Permission(name="android.permission.ACCESS_FINE_LOCATION"),
        Permission(name="android.permission.VIBRATE"),
    ]
    classify_metadata(meta, kb)
    purpose = PurposeProfile(category="calculator", source="user")
    comp = assess_compatibility(meta, purpose, kb)
    verdicts = {c.permission: c.verdict for c in comp}
    assert verdicts["android.permission.READ_CONTACTS"] == UNEXPECTED
    assert verdicts["android.permission.ACCESS_FINE_LOCATION"] == UNEXPECTED
    assert verdicts["android.permission.VIBRATE"] == JUSTIFIED
    # rationale must explain WHY
    contacts = next(c for c in comp
                    if c.permission == "android.permission.READ_CONTACTS")
    assert "calculator" in contacts.rationale.lower() or "not required" in contacts.rationale.lower()


def test_unknown_purpose_yields_undetermined(kb):
    meta = ApkMetadata(package_name="com.mystery")
    meta.permissions = [Permission(name="android.permission.READ_CONTACTS")]
    classify_metadata(meta, kb)
    verdicts = {c.permission: c.verdict
                for c in assess_compatibility(meta, None, kb)}
    assert verdicts["android.permission.READ_CONTACTS"] == UNDETERMINED


def test_optional_permission_plausible(kb):
    """Navigation + background location = plausible (optional), not unexpected."""
    meta = ApkMetadata(package_name="com.nav")
    meta.permissions = [
        Permission(name="android.permission.ACCESS_BACKGROUND_LOCATION")]
    classify_metadata(meta, kb)
    purpose = PurposeProfile(category="navigation", source="user")
    verdicts = {c.permission: c.verdict
                for c in assess_compatibility(meta, purpose, kb)}
    assert verdicts["android.permission.ACCESS_BACKGROUND_LOCATION"] == PLAUSIBLE


def test_infer_category_uses_metadata_not_permissions():
    meta = ApkMetadata(package_name="com.torch.flashlight.app",
                       app_label="My Torch")
    cat, rationale, signals = infer_category(meta, _empty_kb())
    assert cat == "flashlight"
    assert signals  # used package/label signals


def test_infer_category_fails_gracefully():
    meta = ApkMetadata()
    cat, rationale, signals = infer_category(meta, _empty_kb())
    assert cat is None
    # no signals available -> honest message, no fabricated category
    assert "no package name" in rationale.lower() or "select" in rationale.lower()
    assert signals == []


class _EmptyKB:
    categories = {"keywords": {"flashlight": ["torch", "flash", "light"]}}


def _empty_kb():
    return _EmptyKB()
