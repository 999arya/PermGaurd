"""Optional MobSF REST client (supporting evidence only).

This module is deliberately *outside* ``src/`` so the offline engine stays
network-free. Default PermGuard analysis never imports or calls this file.

MobSF REST API (Authorization header = API key):
  POST /api/v1/upload
  POST /api/v1/scan
  POST /api/v1/report_json
  POST /api/v1/download_pdf
  POST /api/v1/scans                (used for "Test connection")
  POST /api/v1/dynamic_analysis     (experimental)
  POST /api/v1/dynamic_report_json  (experimental)

No extra pip packages: uses the Python standard library only (urllib).
The PermGuard risk score is never computed or adjusted here.
"""
from __future__ import annotations

import json
import mimetypes
import os
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin
from urllib.request import Request, urlopen

ProgressFn = Optional[Callable[[str, int], None]]


class MobSFError(RuntimeError):
    """User-facing MobSF failure. ``kind`` drives UI copy, never a crash."""

    def __init__(self, message: str, kind: str = "error"):
        super().__init__(message)
        self.kind = kind  # timeout | auth | down | invalid | error


@dataclass
class MobSFSettings:
    """Connection settings collected from the Streamlit sidebar."""

    base_url: str = "http://localhost:8000"
    api_key: str = ""
    timeout_seconds: int = 30
    scan_timeout_seconds: int = 180

    def configured(self) -> bool:
        return bool(self.base_url.strip() and self.api_key.strip())

    def origin(self) -> str:
        return self.base_url.strip().rstrip("/") + "/"


@dataclass
class MobSFJob:
    """Result of a live (or attempted) MobSF static scan."""

    ok: bool
    hash: str = ""
    report: dict[str, Any] = field(default_factory=dict)
    pdf_bytes: Optional[bytes] = None
    error: str = ""
    error_kind: str = ""


def _headers(api_key: str, extra: Optional[dict[str, str]] = None) -> dict[str, str]:
    h = {"Authorization": api_key}
    if extra:
        h.update(extra)
    return h


def _open(req: Request, timeout: int) -> bytes:
    try:
        with urlopen(req, timeout=timeout) as resp:
            return resp.read()
    except HTTPError as exc:
        body = b""
        try:
            body = exc.read() or b""
        except Exception:
            body = b""
        text = body.decode("utf-8", errors="replace")[:400]
        if exc.code in (401, 403):
            raise MobSFError(
                "MobSF rejected the API key (invalid or missing).",
                kind="auth",
            ) from exc
        raise MobSFError(
            f"MobSF HTTP {exc.code}: {text or exc.reason}",
            kind="invalid",
        ) from exc
    except TimeoutError as exc:
        raise MobSFError(
            f"MobSF request timed out after {timeout}s.",
            kind="timeout",
        ) from exc
    except URLError as exc:
        reason = getattr(exc, "reason", exc)
        raise MobSFError(
            f"MobSF server is unreachable ({reason}).",
            kind="down",
        ) from exc


def _post_form(
    settings: MobSFSettings,
    path: str,
    fields: dict[str, Any],
    timeout: Optional[int] = None,
) -> bytes:
    url = urljoin(settings.origin(), path.lstrip("/"))
    data = urlencode({k: v for k, v in fields.items() if v is not None}).encode("utf-8")
    req = Request(
        url,
        data=data,
        headers=_headers(
            settings.api_key,
            {"Content-Type": "application/x-www-form-urlencoded"},
        ),
        method="POST",
    )
    return _open(req, timeout or settings.timeout_seconds)


def _post_multipart_file(
    settings: MobSFSettings,
    path: str,
    filename: str,
    file_bytes: bytes,
    timeout: Optional[int] = None,
) -> bytes:
    """Upload an APK as multipart/form-data field ``file`` (MobSF REST)."""
    boundary = "----PermGuardBoundary" + uuid.uuid4().hex
    ctype = mimetypes.guess_type(filename)[0] or "application/octet-stream"
    safe_name = os.path.basename(filename) or "upload.apk"
    chunks = [
        f"--{boundary}\r\n".encode("utf-8"),
        (
            f'Content-Disposition: form-data; name="file"; '
            f'filename="{safe_name}"\r\n'
            f"Content-Type: {ctype}\r\n\r\n"
        ).encode("utf-8"),
        file_bytes,
        f"\r\n--{boundary}--\r\n".encode("utf-8"),
    ]
    body = b"".join(chunks)
    url = urljoin(settings.origin(), path.lstrip("/"))
    req = Request(
        url,
        data=body,
        headers=_headers(
            settings.api_key,
            {"Content-Type": f"multipart/form-data; boundary={boundary}"},
        ),
        method="POST",
    )
    return _open(req, timeout or settings.scan_timeout_seconds)


def _as_json(raw: bytes) -> dict[str, Any]:
    try:
        data = json.loads(raw.decode("utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        raise MobSFError(
            "MobSF returned a non-JSON response. Check the URL and API key.",
            kind="invalid",
        ) from exc
    if not isinstance(data, dict):
        raise MobSFError("MobSF JSON was not an object.", kind="invalid")
    return data


def test_connection(settings: MobSFSettings) -> tuple[bool, str]:
    """Probe MobSF without uploading anything. Never raises."""
    if not settings.base_url.strip():
        return False, "Enter a MobSF URL first."
    if not settings.api_key.strip():
        return False, "Enter the MobSF REST API key (MobSF UI → API Docs)."
    try:
        raw = _post_form(settings, "/api/v1/scans", {"page": 1})
        data = _as_json(raw)
        count = data.get("count", data.get("num_scans"))
        extra = f" ({count} scans on server)" if count is not None else ""
        return True, f"Connected to MobSF{extra}."
    except MobSFError as exc:
        return False, str(exc)
    except Exception as exc:  # noqa: BLE001 — UI must never crash
        return False, f"MobSF connection failed: {exc}"


def upload_apk(
    settings: MobSFSettings,
    filename: str,
    file_bytes: bytes,
) -> dict[str, Any]:
    raw = _post_multipart_file(settings, "/api/v1/upload", filename, file_bytes)
    data = _as_json(raw)
    if not data.get("hash"):
        raise MobSFError("MobSF upload did not return a file hash.", kind="invalid")
    return data


def start_scan(
    settings: MobSFSettings,
    file_hash: str,
    filename: str,
    scan_type: str = "apk",
) -> dict[str, Any]:
    raw = _post_form(
        settings,
        "/api/v1/scan",
        {"hash": file_hash, "file_name": filename, "scan_type": scan_type},
        timeout=settings.scan_timeout_seconds,
    )
    # Some MobSF versions return the full report from /scan; others return {}.
    try:
        return _as_json(raw)
    except MobSFError:
        return {}


def fetch_report_json(settings: MobSFSettings, file_hash: str) -> dict[str, Any]:
    raw = _post_form(
        settings,
        "/api/v1/report_json",
        {"hash": file_hash},
        timeout=settings.scan_timeout_seconds,
    )
    return _as_json(raw)


def download_pdf(settings: MobSFSettings, file_hash: str) -> Optional[bytes]:
    """Best-effort MobSF PDF. Failures are ignored (supporting file only)."""
    try:
        raw = _post_form(
            settings,
            "/api/v1/download_pdf",
            {"hash": file_hash},
            timeout=settings.scan_timeout_seconds,
        )
        if raw[:4] == b"%PDF":
            return raw
        return None
    except MobSFError:
        return None


def start_dynamic_analysis(settings: MobSFSettings, file_hash: str) -> dict[str, Any]:
    """Experimental: ask MobSF to start dynamic analysis on a running emulator."""
    raw = _post_form(
        settings,
        "/api/v1/dynamic_analysis",
        {"hash": file_hash},
        timeout=settings.scan_timeout_seconds,
    )
    try:
        return _as_json(raw)
    except MobSFError:
        return {"raw": raw.decode("utf-8", errors="replace")[:500]}


def fetch_dynamic_report(settings: MobSFSettings, file_hash: str) -> dict[str, Any]:
    raw = _post_form(
        settings,
        "/api/v1/dynamic_report_json",
        {"hash": file_hash},
        timeout=settings.scan_timeout_seconds,
    )
    return _as_json(raw)


def run_static_crosscheck(
    settings: MobSFSettings,
    filename: str,
    file_bytes: bytes,
    progress: ProgressFn = None,
    fetch_pdf: bool = False,
) -> MobSFJob:
    """Upload → scan → report_json. Never raises; returns ``MobSFJob``.

    Callers must not feed this into the PermGuard scorer.
    """
    def _note(msg: str, pct: int) -> None:
        if progress:
            progress(msg, pct)

    if not settings.configured():
        return MobSFJob(ok=False, error="MobSF is not configured.", error_kind="invalid")
    try:
        _note("MobSF: uploading APK", 10)
        uploaded = upload_apk(settings, filename, file_bytes)
        file_hash = str(uploaded.get("hash") or "")
        scan_type = str(uploaded.get("scan_type") or "apk")
        _note("MobSF: static scan", 45)
        start_scan(settings, file_hash, os.path.basename(filename), scan_type)
        _note("MobSF: fetching JSON report", 75)
        report = fetch_report_json(settings, file_hash)
        pdf = None
        if fetch_pdf:
            _note("MobSF: downloading PDF", 90)
            pdf = download_pdf(settings, file_hash)
        _note("MobSF: done", 100)
        return MobSFJob(ok=True, hash=file_hash, report=report, pdf_bytes=pdf)
    except MobSFError as exc:
        return MobSFJob(ok=False, error=str(exc), error_kind=exc.kind)
    except Exception as exc:  # noqa: BLE001
        return MobSFJob(ok=False, error=f"MobSF failed: {exc}", error_kind="error")


def run_dynamic_crosscheck(
    settings: MobSFSettings,
    file_hash: str,
    progress: ProgressFn = None,
) -> tuple[bool, dict[str, Any], str]:
    """Experimental dynamic analysis. Never raises. Never affects the score."""
    def _note(msg: str, pct: int) -> None:
        if progress:
            progress(msg, pct)

    try:
        _note("MobSF experimental: starting dynamic analysis", 20)
        start_dynamic_analysis(settings, file_hash)
        _note("MobSF experimental: fetching dynamic report", 70)
        report = fetch_dynamic_report(settings, file_hash)
        _note("MobSF experimental: done", 100)
        return True, report, ""
    except MobSFError as exc:
        return False, {}, str(exc)
    except Exception as exc:  # noqa: BLE001
        return False, {}, f"Dynamic analysis failed: {exc}"
