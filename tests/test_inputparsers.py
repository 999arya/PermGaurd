"""Alternative input parsing: JSON / CSV / XML reports, valid and invalid."""
from __future__ import annotations

import json

import pytest

from src.inputparsers import (
    InputParseError,
    parse_csv_report,
    parse_json_report,
    parse_manifest_xml_report,
    parse_structured,
)


# ---------------------------------------------------------------- JSON
def test_json_valid_simple():
    meta = parse_json_report(json.dumps({
        "package_name": "com.example.app",
        "permissions": ["android.permission.INTERNET", "android.permission.CAMERA"],
    }))
    assert meta.package_name == "com.example.app"
    assert {p.name for p in meta.permissions} == {
        "android.permission.INTERNET", "android.permission.CAMERA"}
    assert meta.input_type == "json_report"


def test_json_object_form():
    meta = parse_json_report(json.dumps({
        "permissions": [{"name": "android.permission.RECORD_AUDIO"}],
    }))
    assert meta.permissions[0].name == "android.permission.RECORD_AUDIO"


def test_json_invalid_raises():
    with pytest.raises(InputParseError, match="Invalid JSON"):
        parse_json_report("{not json")


def test_json_not_object_raises():
    with pytest.raises(InputParseError, match="object"):
        parse_json_report("[1,2,3]")


def test_json_missing_permissions_raises():
    with pytest.raises(InputParseError, match="permissions"):
        parse_json_report('{"package_name": "com.x"}')


def test_json_filters_non_android():
    meta = parse_json_report(json.dumps({
        "permissions": ["android.permission.CAMERA", "totally not a permission"],
    }))
    assert len(meta.permissions) == 1


# ---------------------------------------------------------------- CSV
def test_csv_single_column():
    text = "permission\nandroid.permission.INTERNET\nandroid.permission.CAMERA\n"
    meta = parse_csv_report(text)
    assert len(meta.permissions) == 2


def test_csv_no_header_bare_names():
    text = "INTERNET\nCAMERA\nVIBRATE\n"
    meta = parse_csv_report(text)
    names = {p.name for p in meta.permissions}
    assert "android.permission.INTERNET" in names
    assert len(meta.permissions) == 3


def test_csv_with_package_column():
    text = ("package,permission\n"
            "com.foo,android.permission.READ_CONTACTS\n")
    meta = parse_csv_report(text)
    assert meta.package_name == "com.foo"
    assert meta.permissions[0].name == "android.permission.READ_CONTACTS"


def test_csv_empty_raises():
    with pytest.raises(InputParseError):
        parse_csv_report("")


def test_csv_no_permissions_raises():
    with pytest.raises(InputParseError, match="No recognisable"):
        parse_csv_report("col1,col2\nhello,world\nfoo,bar\n")


# ---------------------------------------------------------------- XML
def test_manifest_xml_valid():
    xml = """<?xml version="1.0"?>
    <manifest xmlns:android="http://schemas.android.com/apk/res/android"
              package="com.example.app">
      <uses-permission android:name="android.permission.INTERNET"/>
      <application android:label="X"/>
    </manifest>"""
    meta = parse_manifest_xml_report(xml)
    assert meta.package_name == "com.example.app"
    assert meta.input_type == "manifest_xml"


def test_manifest_xml_binary_rejected():
    with pytest.raises(InputParseError, match="plain-text"):
        parse_manifest_xml_report("\x03\x00\x08\x00binary garbage here")


def test_manifest_xml_malformed_raises():
    with pytest.raises(InputParseError):
        parse_manifest_xml_report("<manifest><broken>")


# ---------------------------------------------------------------- dispatch
def test_dispatch_by_extension(tmp_path):
    j = parse_structured("report.json", '{"permissions": ["android.permission.CAMERA"]}')
    assert j.input_type == "json_report"
    c = parse_structured("report.csv", "permission\nandroid.permission.INTERNET\n")
    assert c.input_type == "csv_report"
    x = parse_structured("report.xml", """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
        package="a.b"><uses-permission android:name="android.permission.CAMERA"/></manifest>""")
    assert x.input_type == "manifest_xml"


def test_dispatch_sniffs_content():
    j = parse_structured("unknown.bin", '{"permissions": ["android.permission.CAMERA"]}')
    assert j.input_type == "json_report"


def test_dispatch_unknown_raises():
    with pytest.raises(InputParseError, match="Unrecognised"):
        parse_structured("notes.txt", "just some prose, not a report")
