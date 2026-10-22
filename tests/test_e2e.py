"""End-to-end scans on all five synthetic fixtures + evaluation harness.

Each fixture has a manually reviewed expectation file
(data/sampleapps/expectations.json) stating the expected risk band, expected
finding rule IDs and per-permission verdicts. This suite asserts the pipeline
matches those expectations, and computes precision/recall over the
over-privilege verdicts.
"""
from __future__ import annotations

import os

import pytest

from src.models import AssessmentStatus
from src.pipeline import run_scan

# fixture key -> declared category used at scan time
CATEGORIES = {
    "calculator": "calculator",
    "navigation": "navigation",
    "voice_recorder": "voice_recorder",
    "photo_editor": "photo_editor",
    "shopping": "shopping",
    "flashlight_overprivileged": "flashlight",
}


@pytest.fixture(scope="module")
def all_scans():
    """Run every fixture once, from the materialised sampleapps directory."""
    import shutil
    import tempfile

    from src.pipeline import run_scan as _scan

    tmp = tempfile.mkdtemp(prefix="permguard_e2e_")
    out = {}
    for key, cat in CATEGORIES.items():
        src = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "data", "sampleapps", f"{key}.apk",
        )
        if not os.path.isfile(src):
            # fall back to session fixtures if sampleapps not materialised
            pytest.skip(f"fixture {key} not built")
        work = os.path.join(tmp, f"{key}.apk")
        shutil.copy2(src, work)
        out[key] = _scan(work, f"{key}.apk", purpose_category=cat, scan_mode="auto")
    return out


# ---------------------------------------------------------------- band checks
def test_risk_band_matches_expectation(all_scans, expectations):
    for key, res in all_scans.items():
        expected = expectations[key]["expected_risk"]
        assert res.risk.level.value == expected, (
            f"{key}: expected {expected}, got {res.risk.level.value} "
            f"({res.risk.score})"
        )


def test_expected_findings_present(all_scans, expectations):
    for key, res in all_scans.items():
        rule_ids = {f.rule_id for f in res.findings}
        for rid in expectations[key].get("expected_findings", []):
            assert rid in rule_ids, f"{key}: expected finding {rid} missing"


def test_permission_verdicts_match(all_scans, expectations):
    for key, res in all_scans.items():
        verdicts = {c.permission: c.verdict for c in res.purpose_compatibility}
        for perm, expected in expectations[key]["expected_verdicts"].items():
            assert verdicts.get(perm) == expected, (
                f"{key}: {perm} expected {expected}, got {verdicts.get(perm)}"
            )


def test_legitimate_apps_have_no_critical(all_scans):
    """Calculator/nav/recorder are clean -> no CRITICAL findings."""
    for key in ("calculator", "navigation", "voice_recorder"):
        counts = all_scans[key].severity_counts
        assert counts.get("CRITICAL", 0) == 0, (
            f"{key} should have no critical findings: {counts}"
        )


def test_overprivileged_app_has_critical_and_fail(all_scans):
    res = all_scans["flashlight_overprivileged"]
    counts = res.severity_counts
    assert counts.get("CRITICAL", 0) >= 1
    fails = [f for f in res.findings if f.assessment_status == AssessmentStatus.FAIL]
    assert fails, "over-privileged fixture should produce at least one FAIL"


def test_flashlight_finds_all_excess_permissions(all_scans):
    """The over-privileged fixture's excess permissions must be named."""
    res = all_scans["flashlight_overprivileged"]
    flagged = set()
    for f in res.findings:
        flagged.update(f.affected_permissions)
    for excess in ("android.permission.READ_CONTACTS",
                   "android.permission.READ_SMS",
                   "android.permission.ACCESS_FINE_LOCATION",
                   "android.permission.RECORD_AUDIO",
                   "android.permission.READ_CALL_LOG"):
        assert excess in flagged, f"{excess} not flagged as excessive"


def test_deep_scan_runs_on_risky_app(all_scans):
    """Triage must escalate the flashlight to a deep scan."""
    assert all_scans["flashlight_overprivileged"].scan_depth_used == "deep"


def test_basic_scan_stays_basic_on_clean_app(all_scans):
    assert all_scans["calculator"].scan_depth_used == "basic"


def test_scan_result_has_all_required_sections(all_scans):
    """Executive summary / compatibility / findings / score / evidence /
    limitations / corrective actions / uncertainty must all exist."""
    for key, res in all_scans.items():
        assert res.metadata.package_name, key
        assert res.purpose_compatibility, key
        assert res.findings, key
        assert res.risk.breakdown, key
        assert res.recommendations, key
        assert res.disclaimer and "not an official Google Play" in res.disclaimer
        assert res.rule_versions, key
        # every finding must state limitations (honesty requirement)
        missing = [f.rule_id for f in res.findings if not f.limitations]
        assert not missing, f"{key}: findings lacking limitations: {missing}"


def test_scan_deletes_input(scan_apk):
    path = scan_apk("photo_editor")
    run_scan(path, "photo_editor.apk", purpose_category="photo_editor")
    assert not os.path.isfile(path)


def test_scan_without_purpose_still_works(scan_apk):
    """No category -> UNDETERMINED verdicts, INSUFFICIENT_EVIDENCE finding."""
    res = run_scan(scan_apk("calculator"), "calculator.apk",
                   purpose_category=None)
    assert res.risk.score >= 0
    assert all(c.verdict == "UNDETERMINED" for c in res.purpose_compatibility)
    assert any(f.rule_id == "PG-PURPOSE-000" for f in res.findings)
    # must NOT claim over-privilege without a purpose
    assert not any(f.rule_id.startswith("PG-PURPOSE-CRITICAL") for f in res.findings)


# ---------------------------------------------------------------- precision / recall
def test_precision_recall_over_privilege(all_scans, expectations):
    """Evaluate the UNEXPECTED verdicts against the reviewed ground truth.

    Ground truth = permissions listed under expected_verdicts with value
    UNEXPECTED (positives) vs everything else in the fixture (negatives).
    """
    tp = fp = fn = tn = 0
    for key, res in all_scans.items():
        expected = expectations[key]["expected_verdicts"]
        got = {c.permission: c.verdict for c in res.purpose_compatibility}
        for perm in [p.name for p in res.metadata.permissions]:
            is_pos = expected.get(perm) == "UNEXPECTED"
            says_pos = got.get(perm) == "UNEXPECTED"
            if is_pos and says_pos:
                tp += 1
            elif not is_pos and says_pos:
                fp += 1
            elif is_pos and not says_pos:
                fn += 1
            else:
                tn += 1

    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0

    # report for the record (visible with -s)
    print(f"\nover-privilege detection: TP={tp} FP={fp} FN={fn} TN={tn} "
          f"precision={precision:.2f} recall={recall:.2f}")

    # strict expectations on the five reviewed fixtures
    assert precision >= 0.95, f"precision too low: {precision:.2f}"
    assert recall >= 0.95, f"recall too low: {recall:.2f}"


def test_determinism_same_input_same_score(scan_apk, expectations):
    """Two scans of the same file must produce identical scores."""
    a = run_scan(scan_apk("photo_editor"), "pe.apk", purpose_category="photo_editor")
    b = run_scan(scan_apk("photo_editor"), "pe.apk", purpose_category="photo_editor")
    assert a.risk.score == b.risk.score
    assert a.risk.level == b.risk.level
    assert len(a.findings) == len(b.findings)
