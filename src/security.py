"""Upload validation and archive hardening.

Uploaded files are treated as hostile input:
  * size limits before any parsing
  * ZIP structure validation (no directory traversal, no absolute paths)
  * zip-bomb guards (entry count, total uncompressed size, compression ratio)
  * no extraction to disk — entries are read in memory with caps
  * uploaded files are never executed
"""
from __future__ import annotations

import hashlib
import os
import zipfile
from dataclasses import dataclass, field
from typing import Optional


class UploadValidationError(ValueError):
    """Raised when an uploaded file fails validation."""


@dataclass
class ValidationLimits:
    max_bytes: int = 250 * 1024 * 1024
    max_entries: int = 65536
    max_uncompressed: int = 1024 * 1024 * 1024
    max_compression_ratio: float = 200.0
    max_single_entry: int = 512 * 1024 * 1024


@dataclass
class ValidatedFile:
    path: str
    filename: str
    size: int
    sha256: str
    warnings: list[str] = field(default_factory=list)


def sanitize_filename(name: str) -> str:
    """Strip path components and dangerous characters from a filename."""
    if not name:
        return "upload.bin"
    # take basename on both POSIX and Windows separators
    name = name.replace("\\", "/").split("/")[-1]
    name = os.path.basename(name)
    cleaned = "".join(c for c in name if c.isalnum() or c in "._- ()[]")
    cleaned = cleaned.strip("._") or "upload.bin"
    if len(cleaned) > 180:
        root, ext = os.path.splitext(cleaned)
        cleaned = root[:160] + ext[:20]
    return cleaned


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _is_zip_safe(name: str) -> bool:
    """Reject absolute paths and traversal attempts in archive entries."""
    if not name:
        return False
    if name.startswith("/") or name.startswith("\\"):
        return False
    if re_drive(name):
        return False
    parts = name.replace("\\", "/").split("/")
    for part in parts:
        if part == "..":
            return False
    return True


def re_drive(name: str) -> bool:
    return len(name) >= 2 and name[1] == ":"


def validate_upload(path: str, original_name: str,
                     limits: Optional[ValidationLimits] = None) -> ValidatedFile:
    """Validate an uploaded file. Raises UploadValidationError on failure."""
    limits = limits or ValidationLimits()

    if not os.path.isfile(path):
        raise UploadValidationError("Uploaded file not found.")

    size = os.path.getsize(path)
    if size == 0:
        raise UploadValidationError("The uploaded file is empty.")
    if size > limits.max_bytes:
        raise UploadValidationError(
            f"File is {_fmt(size)} which exceeds the "
            f"{_fmt(limits.max_bytes)} upload limit."
        )

    safe_name = sanitize_filename(original_name)
    warnings: list[str] = []

    is_zip = zipfile.is_zipfile(path)
    has_apk_ext = safe_name.lower().endswith((".apk", ".aab", ".zip", ".jar"))

    if has_apk_ext and not is_zip:
        raise UploadValidationError(
            "File has an APK/ZIP extension but is not a valid ZIP archive. "
            "The file may be corrupted or is not a real APK."
        )

    if is_zip:
        try:
            with zipfile.ZipFile(path) as zf:
                infos = zf.infolist()
        except (zipfile.BadZipFile, OSError) as exc:
            raise UploadValidationError(f"Cannot read archive: {exc}") from exc

        if len(infos) > limits.max_entries:
            raise UploadValidationError(
                f"Archive contains {len(infos)} entries "
                f"(limit {limits.max_entries}). Refusing to parse."
            )

        total_uncompressed = 0
        for info in infos:
            if not _is_zip_safe(info.filename):
                raise UploadValidationError(
                    f"Archive contains an unsafe entry path: {info.filename!r}. "
                    "Possible path-traversal payload — rejected."
                )
            total_uncompressed += info.file_size
            if info.file_size > limits.max_single_entry:
                raise UploadValidationError(
                    f"Archive entry {info.filename!r} expands to "
                    f"{_fmt(info.file_size)} (too large)."
                )
            # compression-ratio bomb guard (skip tiny entries)
            if info.compress_size and info.file_size > 1_000_000:
                ratio = info.file_size / max(info.compress_size, 1)
                if ratio > limits.max_compression_ratio:
                    raise UploadValidationError(
                        f"Archive entry {info.filename!r} has a compression "
                        f"ratio of {ratio:.0f}:1 — suspected zip bomb. "
                        "Rejected."
                    )
        if total_uncompressed > limits.max_uncompressed:
            raise UploadValidationError(
                f"Archive expands to {_fmt(total_uncompressed)} "
                f"(limit {_fmt(limits.max_uncompressed)}). Rejected."
            )
        if total_uncompressed == 0:
            raise UploadValidationError("Archive contains no data.")

    if not is_zip and not safe_name.lower().endswith((".xml", ".json", ".csv")):
        # Allow unknown single-file payloads only if small — they may be a
        # structured permission report. Otherwise reject.
        if size > 8 * 1024 * 1024:
            raise UploadValidationError(
                "Unrecognised file format. Supported inputs: .apk, "
                ".xml (manifest), .json, .csv permission reports."
            )

    return ValidatedFile(
        path=path,
        filename=safe_name,
        size=size,
        sha256=sha256_file(path),
        warnings=warnings,
    )


def read_zip_member(zf: zipfile.ZipFile, name: str, max_bytes: int) -> bytes:
    """Read a single archive entry with a hard size cap (memory-safe)."""
    with zf.open(name) as fh:
        data = fh.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise UploadValidationError(
            f"Archive member {name!r} exceeds {max_bytes} bytes — truncated."
        )
    return data


def _fmt(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024.0
    return f"{n} B"
