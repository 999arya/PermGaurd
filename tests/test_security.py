"""Upload validation, hostile-input hardening and privacy guarantees."""
from __future__ import annotations

import io
import os
import zipfile

import pytest

from src.pipeline import ScanError, run_scan, save_upload
from src.security import (
    UploadValidationError,
    sanitize_filename,
    validate_upload,
)


# ---------------------------------------------------------------- filename
def test_filename_traversal_stripped():
    assert sanitize_filename("../../etc/passwd") == "passwd"
    assert sanitize_filename("..\\..\\windows\\system32\\cmd.exe") == "cmd.exe"
    assert sanitize_filename("/absolute/path/app.apk") == "app.apk"


def test_filename_empty_fallback():
    assert sanitize_filename("") == "upload.bin"
    assert sanitize_filename("///") == "upload.bin"


def test_filename_length_capped():
    long = "a" * 500 + ".apk"
    out = sanitize_filename(long)
    assert len(out) <= 181
    assert out.endswith(".apk")


def test_filename_control_chars_removed():
    out = sanitize_filename("evil\x00.apk")
    assert "\x00" not in out


# ---------------------------------------------------------------- size/structure
def test_empty_file_rejected(tmp_path):
    p = tmp_path / "empty.apk"
    p.write_bytes(b"")
    with pytest.raises(UploadValidationError):
        validate_upload(str(p), "empty.apk")


def test_fake_apk_extension_rejected(tmp_path):
    """APK extension but not a ZIP -> reject (no fabricated analysis)."""
    p = tmp_path / "fake.apk"
    p.write_bytes(b"this is just text pretending to be an apk")
    with pytest.raises(UploadValidationError, match="not a valid ZIP"):
        validate_upload(str(p), "fake.apk")


def test_zip_traversal_entry_rejected(tmp_path):
    """Archive with ../ path-traversal entry -> reject."""
    p = tmp_path / "evil.apk"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"<?xml version='1.0'?><manifest/>")
        zf.writestr("../../evil.sh", b"#!/bin/sh\nrm -rf /\n")
    with pytest.raises(UploadValidationError, match="unsafe entry path"):
        validate_upload(str(p), "evil.apk")


def test_zip_absolute_entry_rejected(tmp_path):
    p = tmp_path / "abs.apk"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("/etc/cron.d/pwn", b"* * * * * root sh -c evil\n")
    with pytest.raises(UploadValidationError, match="unsafe entry path"):
        validate_upload(str(p), "abs.apk")


def test_zip_bomb_ratio_rejected(tmp_path):
    """Highly-compressible oversized entry -> suspected zip bomb."""
    p = tmp_path / "bomb.apk"
    with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", b"<?xml version='1.0'?><manifest/>")
        zf.writestr("assets/bomb", b"\x00" * 20_000_000)  # 20 MB of zeros
    limits = type("L", (), {
        "max_bytes": 100_000_000, "max_entries": 1000,
        "max_uncompressed": 1_000_000_000, "max_compression_ratio": 50.0,
        "max_single_entry": 500_000_000,
    })()
    with pytest.raises(UploadValidationError, match="zip bomb"):
        validate_upload(str(p), "bomb.apk", limits)


def test_too_many_entries_rejected(tmp_path):
    p = tmp_path / "many.apk"
    with zipfile.ZipFile(p, "w") as zf:
        for i in range(120):
            zf.writestr(f"assets/f{i}", b"x")
    limits = type("L", (), {
        "max_bytes": 100_000_000, "max_entries": 100,
        "max_uncompressed": 1_000_000_000, "max_compression_ratio": 200.0,
        "max_single_entry": 500_000_000,
    })()
    with pytest.raises(UploadValidationError, match="entries"):
        validate_upload(str(p), "many.apk", limits)


def test_valid_fixture_passes(apk_path):
    v = validate_upload(apk_path("calculator"), "calculator.apk")
    assert v.sha256 and len(v.sha256) == 64
    assert v.size > 0
    assert v.filename == "calculator.apk"


# ---------------------------------------------------------------- privacy
def test_upload_deleted_after_scan(scan_apk):
    """The uploaded file must be gone once the scan completes."""
    path = scan_apk("calculator")
    assert os.path.isfile(path)
    run_scan(path, "calculator.apk", purpose_category="calculator")
    assert not os.path.isfile(path), "uploaded file must be deleted after scan"


def test_upload_deleted_even_on_failure(scan_apk, tmp_path):
    """Failure path must not leave the upload behind either."""
    path = scan_apk("calculator")
    # force a failure: absurd scan mode is fine; instead break the file mid-way
    # by truncating to a non-zip with apk extension
    bad = tmp_path / "broken.apk"
    with open(path, "rb") as fh:
        data = fh.read(64)
    bad.write_bytes(data)  # truncated -> not a valid zip
    os.unlink(path)
    with pytest.raises(ScanError):
        run_scan(str(bad), "broken.apk", purpose_category="calculator")
    assert not os.path.isfile(str(bad))


def test_save_upload_uses_safe_name(tmp_path):
    path = save_upload(b"data", "../../../malware.apk", str(tmp_path))
    assert os.path.dirname(os.path.abspath(path)) == os.path.abspath(str(tmp_path))
    base = os.path.basename(path)
    assert ".." not in base
    assert base.endswith("malware.apk")
    assert os.path.isfile(path)


def test_no_network_imports_in_source():
    """Offline guarantee: no source module may import an HTTP client."""
    import glob
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    banned = ("requests", "httpx", "urllib.request", "aiohttp", "socket",
              "ftplib", "telnetlib", "smtplib")
    offenders = []
    for path in glob.glob(os.path.join(root, "src", "*.py")):
        text = open(path, encoding="utf-8").read()
        for mod in banned:
            # match `import mod` / `from mod import` statements only
            for needle in (f"import {mod}", f"from {mod} import"):
                for line in text.splitlines():
                    stripped = line.strip()
                    if stripped.startswith(needle) and not stripped.startswith("#"):
                        offenders.append(f"{os.path.basename(path)}: {stripped}")
    assert not offenders, f"network imports found: {offenders}"
