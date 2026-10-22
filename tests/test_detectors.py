"""Suspicious-combination detector + privilege-escalation + kernel/root.

Combination findings must always be indicators-for-review, never proof.
Escalation and kernel/root findings must carry evidence and limitations.
"""
from __future__ import annotations

from src.combinationdetector import evaluate as eval_combos
from src.escalationdetector import evaluate as eval_esc
from src.kernelrootdetector import evaluate as eval_kr
from src.models import (
    ApkMetadata,
    AssessmentStatus,
    Component,
    Permission,
    PurposeProfile,
)
from src.permissionclassifier import classify_metadata


def _meta(perms, **kw) -> ApkMetadata:
    m = ApkMetadata(package_name=kw.pop("package", "com.t.app"), **kw)
    m.permissions = [Permission(name=p) for p in perms]
    return m


# ------------------------------------------------------------ combinations
def test_location_contacts_combo(kb):
    m = _meta([
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.READ_CONTACTS",
    ])
    classify_metadata(m, kb)
    findings = eval_combos(kb, m, None)
    combo = [f for f in findings if f.rule_id == "COMBO-LOC-CONTACT-001"]
    assert combo
    f = combo[0]
    # must be framed as an indicator, not proof
    assert f.assessment_status in (AssessmentStatus.POTENTIAL_CONCERN,
                                   AssessmentStatus.NEEDS_REVIEW)
    assert "not proof" in f.limitations.lower() or "indicator" in f.limitations.lower()
    assert f.affected_permissions  # evidence: both permissions listed
    assert "legitimate" in f.recommended_action.lower()


def test_mic_background_combo(kb):
    m = _meta([
        "android.permission.RECORD_AUDIO",
        "android.permission.RECEIVE_BOOT_COMPLETED",
    ])
    classify_metadata(m, kb)
    findings = eval_combos(kb, m, None)
    combo = [f for f in findings if f.rule_id == "COMBO-MIC-BG-001"]
    assert combo
    assert combo[0].severity.value == "CRITICAL"


def test_files_network_combo(kb):
    m = _meta([
        "android.permission.MANAGE_EXTERNAL_STORAGE",
        "android.permission.INTERNET",
    ])
    classify_metadata(m, kb)
    findings = eval_combos(kb, m, PurposeProfile(category="news"))
    combo = [f for f in findings if f.rule_id == "COMBO-FILE-NET-001"]
    assert combo


def test_no_combo_when_permissions_absent(kb):
    m = _meta(["android.permission.VIBRATE"])
    classify_metadata(m, kb)
    findings = eval_combos(kb, m, None)
    # no location/contacts pair, no mic+bg, no files+net
    ids = {f.rule_id for f in findings}
    assert "COMBO-LOC-CONTACT-001" not in ids
    assert "COMBO-MIC-BG-001" not in ids
    assert "COMBO-FILE-NET-001" not in ids


def test_expected_category_downgrades_severity(kb):
    """Mic+bg is expected for a voice recorder -> still reviewable, softer."""
    m = _meta([
        "android.permission.RECORD_AUDIO",
        "android.permission.RECEIVE_BOOT_COMPLETED",
    ])
    classify_metadata(m, kb)
    as_none = eval_combos(kb, m, None)
    as_recorder = eval_combos(kb, m, PurposeProfile(category="voice_recorder"))
    sev_none = next(f.severity.value for f in as_none
                    if f.rule_id == "COMBO-MIC-BG-001")
    sev_rec = next(f.severity.value for f in as_recorder
                   if f.rule_id == "COMBO-MIC-BG-001")
    order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    assert order[sev_rec] < order[sev_none]
    # still reported, never silently dropped
    assert any(f.rule_id == "COMBO-MIC-BG-001" for f in as_recorder)


# ------------------------------------------------------------ escalation
def test_exported_service_flagged(kb):
    m = _meta(["android.permission.INTERNET"])
    m.components = [
        Component(type="service", name=".Stealth", exported=True, intent_filters=1),
    ]
    findings = eval_esc(kb, m)
    svc = [f for f in findings if f.rule_id == "ESC-SVC-001"]
    assert svc and svc[0].severity.value == "HIGH"
    assert ".Stealth" in svc[0].evidence


def test_exported_provider_is_critical(kb):
    m = _meta([])
    m.components = [
        Component(type="provider", name=".Data", exported=True),
    ]
    findings = eval_esc(kb, m)
    prov = [f for f in findings if f.rule_id == "ESC-PROV-001"]
    assert prov and prov[0].severity.value == "CRITICAL"


def test_gated_component_not_flagged(kb):
    """An exported activity protected by a permission is NOT an open door."""
    m = _meta([])
    m.components = [
        Component(type="activity", name=".Secure", exported=True,
                  permission="com.t.sig.PERMISSION"),
    ]
    findings = eval_esc(kb, m)
    assert not any(f.rule_id == "ESC-EXPORT-001" for f in findings)


def test_launcher_activity_not_flagged(kb):
    """MAIN/LAUNCHER activities must be exported and are benign."""
    m = _meta([])
    m.components = [
        Component(type="activity", name=".Main", exported=True, intent_filters=1,
                  actions=["android.intent.action.MAIN"]),
    ]
    findings = eval_esc(kb, m)
    assert not any(f.rule_id == "ESC-EXPORT-001" for f in findings)


def test_shared_user_flagged(kb):
    m = _meta([])
    m.shared_user_id = "android.uid.system"
    findings = eval_esc(kb, m)
    su = [f for f in findings if f.rule_id == "ESC-SHAREDUID-001"]
    assert su and su[0].severity.value == "CRITICAL"
    assert "android.uid.system" in su[0].evidence


def test_weak_custom_permission_flagged(kb):
    m = _meta([])
    m.custom_permissions = [
        {"name": "com.t.WEAK", "protection_level": "normal",
         "protection_level_raw": "normal"},
    ]
    findings = eval_esc(kb, m)
    weak = [f for f in findings if f.rule_id == "ESC-CUSTOMPERM-001"]
    assert weak and weak[0].severity.value == "HIGH"
    assert "signature" in weak[0].recommended_action


def test_debuggable_fails(kb):
    m = _meta([])
    m.debuggable = True
    findings = eval_esc(kb, m)
    dbg = [f for f in findings if f.rule_id == "ESC-DEBUG-001"]
    assert dbg and dbg[0].assessment_status == AssessmentStatus.FAIL


def test_cleartext_flagged(kb):
    m = _meta([])
    m.uses_cleartext_traffic = True
    findings = eval_esc(kb, m)
    assert any(f.rule_id == "ESC-CLEARTEXT-001" for f in findings)


# ------------------------------------------------------------ kernel/root
def test_root_strings_only_low_severity(kb):
    """Root-detection strings alone are consistent with a SECURITY FEATURE."""
    m = _meta([])
    m.dex_string_findings = [
        "[DEX-ROOT-001] root/hook framework reference: magisk",
        "[DEX-SU-001] superuser / su reference: su",
    ]
    findings = eval_kr(kb, m)
    root = [f for f in findings if f.rule_id == "KR-ROOT-001"]
    assert root
    # detection-only -> LOW, and description says defensive is plausible
    assert root[0].severity.value == "LOW"
    assert "detection" in root[0].description.lower()
    assert root[0].limitations  # honest limitation recorded


def test_root_plus_exec_escalates(kb):
    """Root strings + exec/chmod -> needs review, higher severity."""
    m = _meta([])
    m.dex_string_findings = [
        "[DEX-ROOT-001] root/hook framework reference: magisk",
        "[DEX-EXEC-001] runtime process execution: Runtime.getRuntime().exec",
        "[DEX-EXEC-002] file-permission / remount command: chmod 755",
    ]
    findings = eval_kr(kb, m)
    root = [f for f in findings if f.rule_id == "KR-ROOT-001"]
    assert root[0].severity.value == "HIGH"
    assert root[0].assessment_status == AssessmentStatus.NEEDS_REVIEW
    execs = [f for f in findings if f.rule_id == "KR-EXEC-001"]
    assert execs


def test_kernel_cve_strings_critical(kb):
    m = _meta([])
    m.dex_string_findings = [
        "[DEX-KERNEL-001] CVE identifier string (possible exploit reference): cve-2016-5195",
    ]
    findings = eval_kr(kb, m)
    kr = [f for f in findings if f.rule_id == "KR-KERNEL-001"]
    assert kr and kr[0].severity.value == "CRITICAL"
    assert "code review" in kr[0].limitations.lower()


def test_elf_assets_flagged(kb):
    m = _meta([])
    m.elf_assets = ["assets/helper"]
    findings = eval_kr(kb, m)
    elf = [f for f in findings if f.rule_id == "KR-ASSET-ELF-001"]
    assert elf and elf[0].severity.value == "HIGH"
    assert elf[0].assessment_status == AssessmentStatus.NEEDS_REVIEW


def test_kernel_never_claims_proof(kb):
    """Every kernel/root finding must carry the 'indicator, not proof' caveat."""
    m = _meta([])
    m.dex_string_findings = [
        "[DEX-KERNEL-001] CVE identifier: cve-2021-22555",
        "[DEX-ROOT-001] magisk",
        "[DEX-EXEC-001] Runtime.getRuntime().exec",
        "[DEX-SELINUX-001] setenforce 0",
    ]
    m.elf_assets = ["assets/bin"]
    for f in eval_kr(kb, m):
        assert f.limitations, f"{f.rule_id} lacks limitations"
        assert f.assessment_status != AssessmentStatus.FAIL or f.severity.value == "CRITICAL"


def test_clean_app_no_escalation_or_kernel_findings(kb):
    m = _meta(["android.permission.VIBRATE"])
    m.debuggable = False
    assert eval_esc(kb, m) == []
    assert eval_kr(kb, m) == []
