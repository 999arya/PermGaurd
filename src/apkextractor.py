"""APK metadata extraction.

Orchestrates everything needed to turn an uploaded APK into an
:class:`~src.models.ApkMetadata`:

  * ZIP structure validation (via :mod:`src.security`)
  * binary manifest decode (via :mod:`src.axmldecoder`)
  * manifest parse (via :mod:`src.manifestparser`)
  * ZIP inventory: native libraries, assets, staged ELF binaries
  * APK signing block detection (v2/v3 scheme presence)
  * DEX string scanning for permission/privilege indicators (deep scan)

Also supports alternative inputs (manifest XML, JSON/CSV permission reports)
through :mod:`src.inputparsers`.

No file is ever executed and nothing leaves the machine.
"""
from __future__ import annotations

import os
import re
import struct
import zipfile
from typing import Optional

from .axmldecoder import AxmlDecodeError, decode_axml
from .dexscanner import DexScanResult, scan_dex
from .manifestparser import ManifestParseError, parse_manifest
from .models import ApkMetadata, SignatureInfo
from .security import UploadValidationError, read_zip_member, validate_upload

MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_DEX_BYTES = 128 * 1024 * 1024
MAX_ASSET_PATHS = 20_000
MAX_NATIVE_LIBS = 400
ELF_MAGIC = b"\x7fELF"

# Signing-block magic (APK Signing Block, v2/v3)
APK_SIG_BLOCK_MAGIC = b"APK Sig Block 42"


class ExtractionError(RuntimeError):
    """Raised when an APK cannot be analysed. Never fabricates metadata."""


def extract_apk(path: str, filename: str = "", deep: bool = False,
                sha256: str = "") -> ApkMetadata:
    """Extract metadata and declared permissions from an APK file."""
    meta = ApkMetadata(input_type="apk")
    meta.filename = filename or os.path.basename(path)
    meta.file_size = os.path.getsize(path)

    if not zipfile.is_zipfile(path):
        raise ExtractionError(
            "The file is not a valid ZIP/APK archive. The file may be "
            "corrupted or renamed. No metadata can be extracted."
        )

    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
            _extract_manifest(zf, meta)
            _inventory(zf, names, meta)
            _signing_schemes(path, meta)
            if deep:
                _scan_dex(zf, names, meta)
    except (zipfile.BadZipFile, OSError) as exc:
        raise ExtractionError(f"Failed to read APK archive: {exc}") from exc

    if not meta.permissions and not meta.package_name:
        raise ExtractionError(
            "APK parsed but no manifest data could be decoded. The manifest "
            "may use an unsupported encoding. No metadata was fabricated."
        )
    return meta


# ---------------------------------------------------------------------------
# manifest
# ---------------------------------------------------------------------------

def _extract_manifest(zf: zipfile.ZipFile, meta: ApkMetadata) -> None:
    try:
        raw = read_zip_member(zf, "AndroidManifest.xml", MAX_MANIFEST_BYTES)
    except KeyError:
        meta.extraction_notes.append("No AndroidManifest.xml in archive.")
        return
    except UploadValidationError as exc:
        meta.extraction_notes.append(str(exc))
        return

    # Plain text manifest? (some test/unsigned builds store text XML)
    if raw[:5] == b"<?xml" or raw[:9] == b"<manifest":
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(raw.decode("utf-8", errors="replace"))
            parse_manifest(root, into=meta)
            meta.extraction_tool = "text-xml"
            return
        except Exception as exc:  # noqa: BLE001
            meta.extraction_notes.append(f"Text manifest parse failed: {exc}")

    try:
        root = decode_axml(raw)
    except AxmlDecodeError as exc:
        raise ExtractionError(
            f"Could not decode the Android binary manifest: {exc}. "
            "No metadata was fabricated."
        ) from exc

    try:
        parse_manifest(root, into=meta)
        meta.extraction_tool = "builtin-axml"
    except ManifestParseError as exc:
        raise ExtractionError(f"Manifest structure invalid: {exc}") from exc


# ---------------------------------------------------------------------------
# zip inventory: native libs, assets, staged ELF binaries
# ---------------------------------------------------------------------------

def _inventory(zf: zipfile.ZipFile, names: list[str], meta: ApkMetadata) -> None:
    libs: list[str] = []
    assets: list[str] = []
    elf_assets: list[str] = []

    for name in names:
        if name.endswith("/"):
            continue
        low = name.lower()
        if low.startswith("lib/") and low.endswith(".so"):
            # lib/<abi>/<name>.so
            parts = name.split("/")
            if len(parts) >= 3:
                lib_name = parts[-1]
                abi = parts[1]
                if f"{lib_name} ({abi})" not in libs:
                    libs.append(f"{lib_name} ({abi})")
            if len(libs) >= MAX_NATIVE_LIBS:
                break
        elif low.startswith("assets/"):
            if len(assets) < MAX_ASSET_PATHS:
                assets.append(name)

    # look for staged executables/binaries inside assets (privilege concern)
    for name in assets:
        if len(elf_assets) >= 64:
            break
        try:
            head = zf.open(name).read(4)
        except (OSError, zipfile.BadZipFile, RuntimeError):
            continue
        if head == ELF_MAGIC:
            elf_assets.append(name)
        elif name.lower().endswith((".bin", ".sh", ".elf", ".so", ".ko")) \
                and not name.lower().endswith(".js"):
            elf_assets.append(name + " (suspicious extension)")

    meta.native_libraries = libs
    meta.asset_entries = assets[:500] if len(assets) > 500 else assets
    meta.elf_assets = elf_assets
    if len(assets) > 500:
        meta.extraction_notes.append(
            f"{len(assets)} asset entries found; first 500 listed."
        )


# ---------------------------------------------------------------------------
# APK signing block -> v2/v3 scheme presence (pure byte inspection)
# ---------------------------------------------------------------------------

def _signing_schemes(path: str, meta: ApkMetadata) -> None:
    schemes: list[SignatureInfo] = []

    # v1 (JAR signature) = META-INF/*.RSA|DSA|EC + MANIFEST.MF
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
            has_manifest = any(n.upper() == "META-INF/MANIFEST.MF" for n in names)
            has_sig = any(
                n.upper().startswith("META-INF/")
                and n.upper().endswith((".RSA", ".DSA", ".EC"))
                for n in names
            )
            if has_manifest and has_sig:
                schemes.append(SignatureInfo(scheme="v1", details="JAR signature present"))
            elif has_manifest:
                schemes.append(SignatureInfo(scheme="v1", details="MANIFEST.MF only"))
    except (zipfile.BadZipFile, OSError):
        pass

    # v2/v3: APK Signing Block sits immediately before the central directory
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as fh:
            # EOCD: find central directory offset & size from the tail
            tail_start = max(0, size - 65557)
            fh.seek(tail_start)
            tail = fh.read(size - tail_start)
            eocd = tail.rfind(b"PK\x05\x06")
            if eocd == -1:
                meta.signature_schemes = schemes
                return
            cd_offset = struct.unpack_from("<I", tail, eocd + 16)[0]
            # read the 24 bytes immediately before the central directory:
            # size of block (8) + magic (16) at the end of the signing block
            if cd_offset < 24:
                meta.signature_schemes = schemes
                return
            fh.seek(cd_offset - 24)
            footer = fh.read(24)
            if footer[8:] == APK_SIG_BLOCK_MAGIC:
                block_size = struct.unpack_from("<Q", footer, 0)[0]
                # verify pair of size fields
                if 16 <= block_size <= cd_offset:
                    schemes.append(SignatureInfo(scheme="v2", details="APK Signing Block present (v2/v3 capable)"))
    except (OSError, struct.error):
        meta.extraction_notes.append("Signing block could not be inspected.")

    if not schemes:
        schemes.append(SignatureInfo(scheme="unknown", present=False,
                                     details="No signature detected"))
    meta.signature_schemes = schemes


# ---------------------------------------------------------------------------
# DEX string scanning (deep scan only)
# ---------------------------------------------------------------------------

def _scan_dex(zf: zipfile.ZipFile, names: list[str], meta: ApkMetadata) -> None:
    from .dexscanner import DEX_STRING_LIMIT

    dex_names = sorted(n for n in names if re.fullmatch(r"classes\d*\.dex", n))
    if not dex_names:
        meta.extraction_notes.append("No classes*.dex found for string scanning.")
        return

    merged: dict[str, dict] = {}
    total = 0
    for dn in dex_names[:12]:
        try:
            data = read_zip_member(zf, dn, MAX_DEX_BYTES)
        except UploadValidationError as exc:
            meta.extraction_notes.append(str(exc))
            continue
        result: DexScanResult = scan_dex(data, DEX_STRING_LIMIT)
        total += result.total_strings
        meta.extraction_notes.extend(result.notes)
        for ind in result.indicators:
            merged[f"{ind['rule_id']}:{ind['evidence']}"] = ind

    meta.dex_string_count = total
    meta.dex_string_findings = [
        f"[{i['rule_id']}] {i['label']}: {i['evidence']}"
        for i in sorted(merged.values(), key=lambda x: x["rule_id"])[:300]
    ]


def extraction_supported_tools() -> dict[str, Optional[str]]:
    """Detect optional external tools (apkanalyzer/aapt2). Purely additive —
    the builtin parser is the default and always used as fallback."""
    import shutil
    return {
        "apkanalyzer": shutil.which("apkanalyzer"),
        "aapt2": shutil.which("aapt2"),
        "adb": shutil.which("adb"),
    }
