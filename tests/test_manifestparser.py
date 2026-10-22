"""Manifest parsing tests (binary AXML round-trip + failure modes)."""
from __future__ import annotations

import zipfile

import pytest

from src.axmldecoder import AxmlDecodeError, decode_axml
from src.manifestparser import ManifestParseError, parse_manifest_text
from src.apkextractor import ExtractionError, extract_apk


def test_binary_manifest_decodes(apk_path):
    meta = extract_apk(apk_path("calculator"))
    assert meta.package_name == "com.synthetic.calculator"
    assert meta.version_name == "1.0-synthetic"
    assert meta.version_code == "1"
    assert meta.min_sdk == 26
    assert meta.target_sdk == 34
    assert meta.app_label == "Synthetic Calculator"
    assert meta.debuggable is False
    assert meta.allow_backup is True


def test_permissions_extracted(apk_path):
    meta = extract_apk(apk_path("navigation"))
    names = {p.name for p in meta.permissions}
    assert "android.permission.ACCESS_FINE_LOCATION" in names
    assert "android.permission.INTERNET" in names
    assert len(meta.permissions) == 7


def test_components_and_exported(apk_path):
    meta = extract_apk(apk_path("flashlight_overprivileged"))
    activity = next(c for c in meta.components if c.type == "activity")
    assert activity.exported is True
    assert "android.intent.action.MAIN" in activity.actions
    services = [c for c in meta.components if c.type == "service"]
    assert services and services[0].exported is True


def test_deep_scan_finds_dex_strings(apk_path):
    meta = extract_apk(apk_path("flashlight_overprivileged"), deep=True)
    assert meta.dex_string_count > 0
    joined = " ".join(meta.dex_string_findings)
    assert "DEX-SU-001" in joined or "DEX-ROOT-001" in joined
    assert "su" in joined.lower()


def test_elf_asset_detected(apk_path):
    meta = extract_apk(apk_path("flashlight_overprivileged"))
    assert any("assets/helper" in e for e in meta.elf_assets)


def test_non_zip_raises(tmp_path):
    bad = tmp_path / "not_an_apk.apk"
    bad.write_bytes(b"this is definitely not a zip archive at all")
    with pytest.raises(ExtractionError):
        extract_apk(str(bad))


def test_corrupt_zip_raises(tmp_path):
    # valid zip magic but truncated garbage
    bad = tmp_path / "corrupt.apk"
    bad.write_bytes(b"PK\x03\x04" + b"\x00" * 40)
    with pytest.raises((ExtractionError, Exception)):
        extract_apk(str(bad))


def test_missing_manifest_raises(tmp_path):
    import zipfile as zf
    path = str(tmp_path / "nomanifest.apk")
    with zf.ZipFile(path, "w") as z:
        z.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 200)
    with pytest.raises(ExtractionError):
        extract_apk(path)


def test_garbage_axml_rejected():
    with pytest.raises(AxmlDecodeError):
        decode_axml(b"garbage that is not xml")
    with pytest.raises(AxmlDecodeError):
        decode_axml(b"\x03\x00")  # too small


def test_text_manifest_parsing():
    xml = """<?xml version="1.0"?>
    <manifest xmlns:android="http://schemas.android.com/apk/res/android"
              package="com.example.app" android:versionName="2.0">
      <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="33"/>
      <uses-permission android:name="android.permission.INTERNET"/>
      <uses-permission android:name="android.permission.CAMERA"/>
      <application android:label="Test" android:debuggable="true">
        <activity android:name=".Main" android:exported="true"/>
      </application>
    </manifest>"""
    meta = parse_manifest_text(xml)
    assert meta.package_name == "com.example.app"
    assert meta.min_sdk == 24
    assert meta.debuggable is True
    assert {p.name for p in meta.permissions} == {
        "android.permission.INTERNET", "android.permission.CAMERA"}
    assert meta.components[0].exported is True


def test_invalid_xml_raises():
    with pytest.raises(ManifestParseError):
        parse_manifest_text("<manifest><unclosed>")


def test_root_element_must_be_manifest():
    with pytest.raises(ManifestParseError):
        parse_manifest_text("<application/>")


def test_dedupe_repeated_permissions():
    xml = """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
              package="com.x">
      <uses-permission android:name="android.permission.INTERNET"/>
      <uses-permission android:name="android.permission.INTERNET"/>
    </manifest>"""
    meta = parse_manifest_text(xml)
    assert sum(1 for p in meta.permissions if p.name.endswith("INTERNET")) == 1
