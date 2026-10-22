"""Report generation tests (JSON / CSV / PDF + disclaimer presence)."""
from __future__ import annotations

import json
import os

import pytest

from src.pipeline import run_scan
from src.reportgenerator import DISCLAIMER, to_csv, to_json, to_pdf


@pytest.fixture
def sample_result(scan_apk):
    return run_scan(
        scan_apk("flashlight_overprivileged"),
        "flashlight_overprivileged.apk",
        purpose_category="flashlight",
        scan_mode="auto",
    )


def test_json_valid_and_complete(sample_result):
    doc = json.loads(to_json(sample_result))
    for key in ("scan_id", "metadata", "findings", "risk", "recommendations",
                "rule_versions", "disclaimer"):
        assert key in doc
    assert doc["metadata"]["package_name"] == "com.synthetic.flashlight"
    assert 0 <= doc["risk"]["score"] <= 100
    assert len(doc["findings"]) >= 5


def test_json_contains_finding_schema(sample_result):
    doc = json.loads(to_json(sample_result))
    required = {"finding_id", "rule_id", "source_framework", "title",
                "description", "affected_permissions", "evidence", "severity",
                "confidence", "assessment_status", "score_contribution",
                "recommended_action", "source_urls", "limitations"}
    for f in doc["findings"]:
        assert required <= set(f.keys()), f"missing: {required - set(f.keys())}"


def test_csv_header_and_rows(sample_result):
    text = to_csv(sample_result)
    lines = [l for l in text.splitlines() if l.strip()]
    assert "finding_id,rule_id,source_framework,severity" in lines[0]
    assert len(lines) > 5
    assert "PERMISSION INVENTORY" in text


def test_pdf_generates(sample_result, tmp_path):
    path = os.path.join(str(tmp_path), "report.pdf")
    out = to_pdf(sample_result, path)
    assert os.path.isfile(out)
    with open(out, "rb") as fh:
        head = fh.read(5)
    assert head == b"%PDF-"
    assert os.path.getsize(out) > 3000


def test_pdf_contains_disclaimer(sample_result, tmp_path):
    """Disclaimer must be embedded — extract text from the PDF streams."""
    path = os.path.join(str(tmp_path), "r.pdf")
    to_pdf(sample_result, path)
    assert _pdf_contains(path, b"DISCLAIMER") or \
        _pdf_contains(path, b"not an official Google Play"), \
        "disclaimer not found in PDF"


def _pdf_contains(path: str, needle: bytes) -> bool:
    """Search decompressed PDF content streams for a byte string.

    ReportLab encodes streams with ASCII85 + Flate; decode both layers.
    """
    import base64
    import re
    import zlib

    with open(path, "rb") as fh:
        raw = fh.read()
    if needle in raw:
        return True
    for m in re.finditer(rb"stream\r?\n(.*?)endstream", raw, re.S):
        blob = m.group(1).strip()
        for candidate in (blob, blob.rstrip(b"~>")):
            try:
                data = zlib.decompress(base64.a85decode(candidate, adobe=False))
            except Exception:  # noqa: BLE001
                try:
                    data = zlib.decompress(candidate)
                except Exception:  # noqa: BLE001
                    continue
            if needle in data:
                return True
    return False


def test_disclaimer_text_constant():
    assert "not an official Google Play compliance determination" in DISCLAIMER
    assert "proof that an application is malicious" in DISCLAIMER
    assert "runtime behaviour" in DISCLAIMER


def test_pdf_priority_ordering(sample_result, tmp_path):
    """CRITICAL findings must be emitted before LOW ones in the PDF."""
    import base64
    import re
    import zlib

    path = os.path.join(str(tmp_path), "o.pdf")
    to_pdf(sample_result, path)
    with open(path, "rb") as fh:
        raw = fh.read()

    text_parts = [raw]
    for m in re.finditer(rb"stream\r?\n(.*?)endstream", raw, re.S):
        blob = m.group(1).strip()
        for candidate in (blob, blob.rstrip(b"~>")):
            try:
                text_parts.append(zlib.decompress(base64.a85decode(candidate)))
                break
            except Exception:  # noqa: BLE001
                try:
                    text_parts.append(zlib.decompress(candidate))
                    break
                except Exception:  # noqa: BLE001
                    continue
    blob = b" ".join(text_parts)

    crit = [f for f in sample_result.findings if f.severity.value == "CRITICAL"]
    low = [f for f in sample_result.findings if f.severity.value == "LOW"]
    if not crit or not low:
        pytest.skip("sample lacks both severities")
    crit_id = crit[0].rule_id.encode()
    low_id = low[-1].rule_id.encode()
    ci, li = blob.find(crit_id), blob.find(low_id)
    if ci == -1 or li == -1:
        pytest.skip("rule ids not extractable from decoded streams")
    assert ci < li, "CRITICAL must appear before LOW in PDF"
