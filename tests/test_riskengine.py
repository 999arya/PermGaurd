"""Risk-scoring engine tests: determinism, floors, dedup, breakdown."""
from __future__ import annotations

import copy

from src.models import (
    ApkMetadata,
    AssessmentStatus,
    Confidence,
    Finding,
    Permission,
    PurposeCompatibility,
    SensitivityTier,
    Severity,
)
from src.riskengine import score


def _meta(perms: list[str]) -> ApkMetadata:
    m = ApkMetadata(package_name="com.x")
    m.permissions = [Permission(name=p) for p in perms]
    for p in m.permissions:
        p.sensitivity = SensitivityTier.CRITICAL if "SMS" in p.name or "CONTACTS" in p.name else SensitivityTier.LOW
    return m


def _finding(fid, sev, conf=Confidence.HIGH, status=AssessmentStatus.POTENTIAL_CONCERN,
             key=None, rule="R-1"):
    return Finding(
        finding_id=fid, rule_id=rule, source_framework="permissionguard",
        title=f"Finding {fid}", description="d", severity=sev, confidence=conf,
        assessment_status=status, correlation_key=key,
    )


def test_score_bounded_0_100(kb):
    m = _meta(["android.permission.READ_SMS"])
    findings = [_finding(f"F{i}", Severity.CRITICAL) for i in range(50)]
    r = score(kb, findings, m, [])
    assert 0 <= r.score <= 100


def test_no_findings_low_score(kb):
    m = _meta(["android.permission.VIBRATE"])
    r = score(kb, [], m, [])
    assert r.level.value == "LOW"
    assert r.score < 30


def test_deterministic(kb):
    m = _meta(["android.permission.READ_SMS", "android.permission.READ_CONTACTS"])
    findings = [
        _finding("F1", Severity.HIGH, key="k1"),
        _finding("F2", Severity.MEDIUM, key="k2"),
    ]
    r1 = score(kb, findings, m, [])
    r2 = score(kb, findings, m, [])
    assert r1.score == r2.score
    assert r1.level == r2.level


def test_dedup_correlated_findings(kb):
    """Findings sharing a correlation key count ONCE (no double counting)."""
    m = _meta(["android.permission.READ_SMS"])
    shared = "root:same_cause"
    deduped = [
        _finding("F1", Severity.HIGH, key=shared, rule="A"),
        _finding("F2", Severity.CRITICAL, key=shared, rule="B"),
        _finding("F3", Severity.MEDIUM, key=shared, rule="C"),
    ]
    no_dedup = [
        _finding("F1", Severity.HIGH, key=None, rule="A"),
        _finding("F2", Severity.CRITICAL, key=None, rule="B"),
        _finding("F3", Severity.MEDIUM, key=None, rule="C"),
    ]
    r_dedup = score(kb, deduped, m, [])
    r_full = score(kb, no_dedup, m, [])
    # dedup keeps only the highest (CRITICAL) contribution of the three
    assert r_dedup.score < r_full.score
    assert r_dedup.deduplicated_findings  # the dropped ones are recorded


def test_critical_finding_forces_at_least_medium_band(kb):
    """Anti-burying: one CRITICAL can never classify as LOW."""
    m = _meta(["android.permission.VIBRATE"])
    # even with a single critical and everything else minimal
    findings = [_finding("F1", Severity.CRITICAL, conf=Confidence.LOW,
                         status=AssessmentStatus.POTENTIAL_CONCERN)]
    r = score(kb, findings, m, [])
    assert r.level.value in ("MEDIUM", "HIGH")


def test_insufficient_evidence_not_scored(kb):
    """NEEDS REVIEW / INSUFFICIENT EVIDENCE must not inflate the score."""
    m = _meta(["android.permission.VIBRATE"])
    nonev = [_finding(f"F{i}", Severity.CRITICAL,
                      status=AssessmentStatus.INSUFFICIENT_EVIDENCE)
             for i in range(10)]
    r = score(kb, nonev, m, [])
    baseline_only = score(kb, [], m, [])
    assert r.score == baseline_only.score


def test_pass_status_not_scored(kb):
    m = _meta(["android.permission.VIBRATE"])
    passes = [_finding("F1", Severity.CRITICAL, status=AssessmentStatus.PASS)]
    assert score(kb, passes, m, []).score == score(kb, [], m, []).score


def test_breakdown_has_every_contribution(kb):
    m = _meta(["android.permission.READ_SMS"])
    findings = [
        _finding("F1", Severity.HIGH, key="a", rule="A"),
        _finding("F2", Severity.LOW, key="b", rule="B"),
    ]
    r = score(kb, findings, m, [])
    assert r.breakdown, "breakdown must not be empty"
    # every scored contribution has a reason
    assert all(b.reason for b in r.breakdown)
    assert all(b.rule_id for b in r.breakdown)
    # sum of applied points (pre-clamp) matches reported raw total
    total = sum(b.applied_points for b in r.breakdown)
    assert abs(total - r.thresholds["raw_total"]) < 0.01


def test_configurable_weights_respected(kb):
    """Changing weights in config changes the score."""
    m = _meta(["android.permission.READ_SMS"])
    findings = [_finding("F1", Severity.MEDIUM)]
    kb2 = copy.deepcopy(kb)
    r_low = score(kb2, findings, m, [])
    kb3 = copy.deepcopy(kb)
    kb3.riskconfig["severity_weights"]["MEDIUM"] = 50.0
    r_high = score(kb3, findings, m, [])
    assert r_high.score > r_low.score


def test_confidence_scales_contribution(kb):
    # use MEDIUM severity so the CRITICAL/HIGH score floors don't mask
    # the confidence effect
    m = _meta(["android.permission.READ_SMS"])
    hi = score(kb, [_finding("F1", Severity.MEDIUM, conf=Confidence.HIGH)], m, [])
    lo = score(kb, [_finding("F1", Severity.MEDIUM, conf=Confidence.LOW)], m, [])
    assert hi.score > lo.score


def test_thresholds_bands(kb):
    """LOW <=29, MEDIUM 30-59, HIGH 60+."""
    m = _meta(["android.permission.READ_SMS"])
    # few findings -> low
    assert score(kb, [_finding("F1", Severity.LOW)], m, []).level.value == "LOW"
    # many high findings -> high
    many = [_finding(f"F{i}", Severity.HIGH, key=f"k{i}") for i in range(6)]
    assert score(kb, many, m, []).level.value == "HIGH"


def test_explanation_present(kb):
    m = _meta(["android.permission.READ_SMS"])
    r = score(kb, [_finding("F1", Severity.CRITICAL)], m, [])
    assert r.explanation
    assert "not a probability of malware" in r.explanation
    assert r.method  # method documented
