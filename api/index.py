"""Stateless Vercel HTTP adapter for the existing local analysis engine."""
import json
import tempfile
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from pydantic import ValidationError

from src.knowledgebase import load_knowledgebase
from src.pipeline import ScanError, run_scan, save_upload
from src.reportgenerator import to_csv, to_json, to_pdf

ROOT = Path(__file__).resolve().parents[1]
MAX_UPLOAD = 4_000_000  # Below Vercel's 4.5 MB request/response limit.


class handler(BaseHTTPRequestHandler):
    def reply(self, status, body, content_type="application/json", filename=None):
        if isinstance(body, dict):
            body = json.dumps(body).encode()
        elif isinstance(body, str):
            body = body.encode()
        if len(body) > MAX_UPLOAD:
            status, body, content_type, filename = 413, b'{"error":"Report is too large. Run this scan locally."}', "application/json", None
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if filename:
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        route = urlsplit(self.path).path
        if route == "/api/health":
            self.reply(200, {"status": "ok"})
        elif route == "/api/categories":
            self.reply(200, {"categories": sorted(load_knowledgebase().categories.get("categories", {}))})
        elif route == "/api/demo":
            self.reply(200, (ROOT / "samples" / "flashlight_mobsf.json").read_bytes())
        else:
            self.reply(404, {"error": "Not found"})

    def do_POST(self):
        if urlsplit(self.path).path != "/api/scan":
            self.reply(404, {"error": "Not found"})
            return
        path = None
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= MAX_UPLOAD:
                self.reply(413, {"error": "Upload a non-empty file up to 4 MB. Use the local dashboard for larger APKs."})
                return
            query = parse_qs(urlsplit(self.path).query)
            filename = query.get("filename", ["report.json"])[0]
            category = query.get("category", ["auto"])[0]
            mode = query.get("mode", ["auto"])[0]
            export = query.get("format", ["json"])[0]
            categories = load_knowledgebase().categories.get("categories", {})
            if category not in {"auto", *categories} or mode not in {"auto", "basic", "deep"} or export not in {"json", "csv", "pdf"}:
                raise ValueError("Invalid category, scan mode, or report format.")
            data = self.rfile.read(length)
            if len(data) != length:
                raise ValueError("Upload was incomplete.")
            path = save_upload(data, filename)
            result = run_scan(path, filename, purpose_category=category, scan_mode=mode)
            if export == "pdf":
                with tempfile.TemporaryDirectory(prefix="permguard_report_") as directory:
                    report = Path(directory) / "report.pdf"
                    to_pdf(result, str(report))
                    self.reply(200, report.read_bytes(), "application/pdf", "permguard-report.pdf")
            elif export == "csv":
                self.reply(200, to_csv(result), "text/csv; charset=utf-8", "permguard-report.csv")
            else:
                self.reply(200, to_json(result))
        except (ScanError, ValueError, ValidationError):
            self.reply(400, {"error": "Invalid input. Check the file type, report contents, category and scan mode."})
        except Exception:
            self.reply(500, {"error": "Analysis failed. Try a smaller input or run the local dashboard."})
        finally:
            if path:
                Path(path).unlink(missing_ok=True)

    def log_message(self, format, *args):
        # Do not log user filenames or request parameters.
        pass
