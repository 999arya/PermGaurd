"""Alternative input parsers: permission reports as XML / JSON / CSV.

Supports structured permission reports so the tool can be used without an
APK. All inputs are validated and treated as untrusted.
"""
from __future__ import annotations

import csv
import io
import json
from typing import Optional

from .models import ApkMetadata, Permission
from .security import sanitize_filename

MAX_INPUT_BYTES = 8 * 1024 * 1024
MAX_ROWS = 5000


class InputParseError(ValueError):
    """Raised when a structured report cannot be parsed."""


def _coerce_int(value) -> Optional[int]:
    if value in (None, ""):
        return None
    try:
        return int(str(value).strip())
    except ValueError:
        return None


def parse_json_report(text: str) -> ApkMetadata:
    """Parse a JSON permission report.

    Accepted shapes:
      {"package_name": "...", "permissions": ["android.permission.INTERNET"]}
      {"permissions": [{"name": "android.permission.CAMERA"}]}
      {"app": {...}, "permission_list": [...]}
    """
    if len(text.encode("utf-8", errors="ignore")) > MAX_INPUT_BYTES:
        raise InputParseError("JSON report exceeds 8 MB limit.")
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise InputParseError(f"Invalid JSON: {exc}") from exc

    if not isinstance(doc, dict):
        raise InputParseError("JSON report must be an object at the top level.")

    meta = ApkMetadata(input_type="json_report")
    app_doc = doc.get("app") if isinstance(doc.get("app"), dict) else {}
    meta.package_name = doc.get("package_name") or doc.get("package") \
        or app_doc.get("package_name")
    meta.version_name = doc.get("version_name") or doc.get("versionName") \
        or app_doc.get("version_name")
    meta.app_label = doc.get("app_name") or doc.get("app_label") \
        or doc.get("label") or app_doc.get("name")
    meta.min_sdk = _coerce_int(doc.get("min_sdk") or doc.get("minSdkVersion"))
    meta.target_sdk = _coerce_int(doc.get("target_sdk") or doc.get("targetSdkVersion"))

    raw_perms = doc.get("permissions")
    if raw_perms is None:
        raw_perms = doc.get("permission_list") or doc.get("declared_permissions")
    if raw_perms is None:
        raise InputParseError(
            "JSON report has no 'permissions' array. Expected at least "
            '{"permissions": ["android.permission.INTERNET"]}.'
        )
    # MobSF exports map permission names to supporting metadata.
    # Only names enter the local scoring engine; MobSF scores stay separate.
    if isinstance(raw_perms, dict):
        raw_perms = list(raw_perms)
    if not isinstance(raw_perms, list):
        raise InputParseError("'permissions' must be an array.")

    meta.permissions = _coerce_permissions(raw_perms)
    meta.extraction_notes.append("Parsed from JSON permission report (user supplied).")
    meta.extraction_tool = "json-input"
    if not meta.permissions:
        raise InputParseError("No valid permissions found in JSON report.")
    return meta


def parse_csv_report(text: str) -> ApkMetadata:
    """Parse a CSV permission report.

    Accepts a single column of permission names (header optional) or a header
    row containing a 'permission'/'name' column.
    """
    if len(text.encode("utf-8", errors="ignore")) > MAX_INPUT_BYTES:
        raise InputParseError("CSV report exceeds 8 MB limit.")

    sample = text.lstrip("﻿")[:4096]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t")
    except csv.Error:
        dialect = csv.excel

    reader = csv.reader(io.StringIO(text), dialect)
    rows: list[list[str]] = []
    for i, row in enumerate(reader):
        if i >= MAX_ROWS:
            break
        rows.append([c.strip() for c in row])
    rows = [r for r in rows if any(r)]

    if not rows:
        raise InputParseError("CSV report is empty.")

    # find header
    header_idx: Optional[int] = None
    perm_col = 0
    for i, row in enumerate(rows[:5]):
        lowered = [c.lower() for c in row]
        for j, cell in enumerate(lowered):
            if cell in ("permission", "permissions", "name", "permission_name",
                        "android_permission"):
                header_idx, perm_col = i, j
                break
        if header_idx is not None:
            break

    meta = ApkMetadata(input_type="csv_report")
    data_rows = rows[header_idx + 1:] if header_idx is not None else rows

    # capture optional package/app columns
    if header_idx is not None:
        header = rows[header_idx]
        for i, cell in enumerate(header):
            low = cell.lower()
            if i == perm_col:
                continue
            for row in data_rows:
                if i >= len(row) or not row[i]:
                    continue
                val = row[i]
                if low in ("package", "package_name", "app_package"):
                    meta.package_name = meta.package_name or val
                elif low in ("app_name", "app", "label") :
                    meta.app_label = meta.app_label or val
                elif low in ("version_name", "version"):
                    meta.version_name = meta.version_name or val

    perms: list[Permission] = []
    seen: set[str] = set()
    for row in data_rows:
        if perm_col >= len(row):
            continue
        name = row[perm_col]
        if not name or name.lower() in ("permission", "permissions", "name"):
            continue
        if not name.startswith("android.permission.") \
                and not name.startswith("com."):
            # allow bare names like INTERNET / CAMERA
            if name.upper() == name and name.replace("_", "").isalnum():
                name = "android.permission." + name
            else:
                continue
        if name in seen:
            continue
        seen.add(name)
        perms.append(Permission(name=name))

    if not perms:
        raise InputParseError(
            "No recognisable Android permissions found in CSV. Expected a "
            "column of values like 'android.permission.CAMERA'."
        )
    meta.permissions = perms
    meta.extraction_notes.append("Parsed from CSV permission report (user supplied).")
    meta.extraction_tool = "csv-input"
    return meta


def parse_manifest_xml_report(text: str) -> ApkMetadata:
    """Parse a plain-text AndroidManifest.xml."""
    from .manifestparser import ManifestParseError, parse_manifest_text

    if len(text.encode("utf-8", errors="ignore")) > MAX_INPUT_BYTES:
        raise InputParseError("Manifest XML exceeds 8 MB limit.")

    # reject binary payloads mistakenly labelled .xml
    stripped = text.lstrip()
    if stripped and not stripped.startswith("<"):
        raise InputParseError(
            "File is not plain-text XML (looks like binary data). "
            "If this is an APK manifest, upload the APK instead."
        )

    try:
        meta = parse_manifest_text(text)
    except ManifestParseError as exc:
        raise InputParseError(f"Invalid manifest XML: {exc}") from exc
    if not meta.permissions and not meta.package_name:
        raise InputParseError("Manifest parsed but contains no permissions or package.")
    meta.input_type = "manifest_xml"
    meta.extraction_notes.append("Parsed from plain-text AndroidManifest.xml.")
    meta.extraction_tool = "text-xml"
    return meta


def _coerce_permissions(raw: list) -> list[Permission]:
    perms: list[Permission] = []
    seen: set[str] = set()
    for item in raw:
        if isinstance(item, str):
            name = item.strip()
        elif isinstance(item, dict):
            name = str(item.get("name") or item.get("permission") or "").strip()
        else:
            continue
        if not name or name in seen:
            continue
        if not (name.startswith("android.permission.")
                or name.startswith("com.") or name.startswith("android.")):
            continue
        seen.add(name)
        perms.append(Permission(name=name))
    return perms


def parse_structured(filename: str, text: str) -> ApkMetadata:
    """Dispatch to the right parser based on file extension/content."""
    name = sanitize_filename(filename)
    low = name.lower()
    if low.endswith(".json"):
        return parse_json_report(text)
    if low.endswith(".csv") or low.endswith(".tsv"):
        return parse_csv_report(text)
    if low.endswith(".xml"):
        return parse_manifest_xml_report(text)
    # sniff
    head = text.lstrip()[:1]
    if head == "{":
        return parse_json_report(text)
    if head == "<":
        return parse_manifest_xml_report(text)
    raise InputParseError(
        "Unrecognised report format. Supported: .apk, .xml, .json, .csv"
    )
