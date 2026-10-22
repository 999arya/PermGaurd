"""Google Play policy engine + OWASP engine + org policy engine tests."""
from __future__ import annotations

from src.models import (
    ApkMetadata,
    AssessmentStatus,
    Permission,
    PurposeProfile,
)
from src.permissionclassifier import classify_metadata
from src.policyengine import evaluate as eval_play
from src.owaspengine import evaluate as eval_owasp
from src.orgpolicyengine import evaluate as eval_org


def _meta(permissions, **kwargs) -> ApkMetadata:
    m = ApkMetadata(package_name=kwargs.pop("package", "com.test.app"), **kwargs)
    m.permissions = [Permission(name=p) for p in permissions]
    return m


# ---------------- Google Play ----------------

def test_sms_policy_fails_when_purpose_known_and_non_communicational(kb):
    m = _meta(["android.permission.READ_SMS"], package="com.calc")
    classify_metadata(m, kb)
    purpose = PurposeProfile(category="calculator")
    findings = eval_play(kb, m, purpose, [])
    sms = [f for f in findings if f.rule_id == "GP-SMS-001"]
    assert sms, "SMS rule should trigger"
    assert sms[0].assessment_status == AssessmentStatus.FAIL
    assert sms[0].source_framework == "google_play"
    assert sms[0].source_urls


def test_sms_policy_insufficient_evidence_without_purpose(kb):
    m = _meta(["android.permission.READ_SMS"])
    classify_metadata(m, kb)
    findings = eval_play(kb, m, None, [])
    sms = [f for f in findings if f.rule_id == "GP-SMS-001"]
    assert sms[0].assessment_status == AssessmentStatus.INSUFFICIENT_EVIDENCE


def test_background_location_needs_evidence(kb):
    m = _meta(["android.permission.ACCESS_BACKGROUND_LOCATION"])
    findings = eval_play(kb, m, None, [])
    loc = [f for f in findings if f.rule_id == "GP-LOC-001"]
    assert loc, "background location rule triggers"
    # must NOT be FAIL without evidence
    assert loc[0].assessment_status != AssessmentStatus.FAIL
    assert loc[0].assessment_status in (
        AssessmentStatus.INSUFFICIENT_EVIDENCE,
        AssessmentStatus.NEEDS_REVIEW,
    )


def test_no_sms_no_sms_rule(kb):
    m = _meta(["android.permission.INTERNET", "android.permission.VIBRATE"])
    classify_metadata(m, kb)
    findings = eval_play(kb, m, PurposeProfile(category="calculator"), [])
    assert not any(f.rule_id == "GP-SMS-001" for f in findings)


def test_manage_external_storage_flags(kb):
    m = _meta(["android.permission.MANAGE_EXTERNAL_STORAGE"])
    classify_metadata(m, kb)
    findings = eval_play(kb, m, PurposeProfile(category="news"), [])
    photo = [f for f in findings if f.rule_id == "GP-PHOTO-001"]
    assert photo
    assert photo[0].assessment_status == AssessmentStatus.POTENTIAL_CONCERN


def test_disclosure_check_always_needs_review(kb):
    """Evidence lives outside the APK -> never PASS/FAIL."""
    m = _meta(["android.permission.CAMERA"])
    classify_metadata(m, kb)
    findings = eval_play(kb, m, PurposeProfile(category="camera"), [])
    disc = [f for f in findings if f.rule_id == "GP-DISC-001"]
    assert disc
    assert disc[0].assessment_status == AssessmentStatus.NEEDS_REVIEW


# ---------------- OWASP ----------------

def test_owasp_excessive_permission_fires(kb):
    m = _meta(["android.permission.READ_CONTACTS"], package="com.calc")
    classify_metadata(m, kb)
    purpose = PurposeProfile(category="calculator")
    from src.purposeanalyzer import assess_compatibility
    compat = assess_compatibility(m, purpose, kb)
    findings = eval_owasp(kb, m, purpose, compat)
    priv = [f for f in findings if f.rule_id == "OWASP-PRIV-001"]
    assert priv
    assert priv[0].source_framework == "owasp_informed"
    assert "MASWE-0066" in (priv[0].source_urls[0] if priv[0].source_urls else "") \
        or "mas.owasp.org" in " ".join(priv[0].source_urls)


def test_owasp_debuggable_flags_high(kb):
    m = _meta(["android.permission.INTERNET"], package="com.x")
    m.debuggable = True
    classify_metadata(m, kb)
    findings = eval_owasp(kb, m, None, [])
    arch = [f for f in findings if f.rule_id == "OWASP-ARCH-001"
            and "debuggable" in f.evidence]
    assert arch and arch[0].severity.value == "HIGH"


def test_owasp_insufficient_without_purpose(kb):
    m = _meta(["android.permission.READ_CONTACTS"])
    classify_metadata(m, kb)
    findings = eval_owasp(kb, m, None, [])
    priv = [f for f in findings if f.rule_id == "OWASP-PRIV-001"]
    assert priv[0].assessment_status == AssessmentStatus.INSUFFICIENT_EVIDENCE


def test_owasp_labels_itself_as_informed_not_official(kb):
    """Rules must not masquerade as official OWASP automated tests."""
    for rule in kb.owasp_rules["rules"]:
        assert rule["rule_type"].startswith("application_specific") or \
            rule["rule_type"] in ("masvs_mapping",)
        assert "mas.owasp.org" in rule["source_url"]


# ---------------- Org policy ----------------

def test_org_deny_list_fails(kb):
    m = _meta(["android.permission.READ_SMS", "android.permission.VIBRATE"])
    classify_metadata(m, kb)
    findings = eval_org(kb, m, None, [])
    deny = [f for f in findings if f.rule_id == "ORG-DENY-001"]
    assert deny
    assert deny[0].assessment_status == AssessmentStatus.FAIL
    assert deny[0].source_framework == "org_policy"
    assert "android.permission.READ_SMS" in deny[0].affected_permissions


def test_org_review_list_needs_review(kb):
    m = _meta(["android.permission.REQUEST_INSTALL_PACKAGES"])
    classify_metadata(m, kb)
    findings = eval_org(kb, m, None, [])
    rev = [f for f in findings if f.rule_id == "ORG-REVIEW-001"]
    assert rev and rev[0].assessment_status == AssessmentStatus.NEEDS_REVIEW


def test_org_category_allowlist(kb):
    m = _meta(["android.permission.READ_CONTACTS", "android.permission.CAMERA"])
    classify_metadata(m, kb)
    findings = eval_org(kb, m, PurposeProfile(category="calculator"), [])
    cat = [f for f in findings if f.rule_id == "ORG-CAT-001"]
    assert cat
    assert "android.permission.READ_CONTACTS" in cat[0].affected_permissions


def test_org_disabled_produces_nothing(kb):
    """If org policy is disabled, no org findings."""
    import copy
    kb2 = copy.deepcopy(kb)
    kb2.orgpolicy["enabled"] = False
    m = _meta(["android.permission.READ_SMS"])
    classify_metadata(m, kb2)
    findings = eval_org(kb2, m, None, [])
    assert findings == []
