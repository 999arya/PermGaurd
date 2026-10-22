"""Exercise the HTTP adapter without a running server or cloud credentials."""
import io
import json
from pathlib import Path

import pytest

from api.index import MAX_UPLOAD, handler
from src.inputparsers import parse_json_report

ROOT = Path(__file__).resolve().parents[1]


def request(method, url, body=b"", length=None):
    endpoint = handler.__new__(handler)
    endpoint.path = url
    endpoint.headers = {"Content-Length": str(len(body) if length is None else length)}
    endpoint.rfile = io.BytesIO(body)
    endpoint.wfile = io.BytesIO()
    response = {"headers": {}}
    endpoint.send_response = lambda code: response.update(status=code)
    endpoint.send_header = lambda key, value: response["headers"].update({key: value})
    endpoint.end_headers = lambda: None
    getattr(endpoint, "do_" + method)()
    response["body"] = endpoint.wfile.getvalue()
    return response


def test_mobsf_sample_permissions():
    doc = json.loads((ROOT / "samples/flashlight_mobsf.json").read_text())
    result = parse_json_report(json.dumps(doc))
    assert {p.name for p in result.permissions} == set(doc["permissions"])


@pytest.mark.parametrize("format,mime", [("json", "application/json"), ("csv", "text/csv"), ("pdf", "application/pdf")])
def test_demo_scan_and_exports(format, mime):
    sample = request("GET", "/api/demo")["body"]
    result = request("POST", f"/api/scan?filename=flashlight.json&category=flashlight&format={format}", sample)
    assert result["status"] == 200
    assert result["headers"]["Content-Type"].startswith(mime)
    assert result["headers"]["Cache-Control"] == "no-store"
    if format == "json":
        report = json.loads(result["body"])
        assert report["metadata"]["package_name"] == "com.synthetic.flashlight"
        assert report["risk"]["score"] > 0
        assert report["findings"]
    elif format == "pdf":
        assert result["body"].startswith(b"%PDF")
    else:
        assert b"severity" in result["body"].lower()


def test_categories_and_health():
    assert request("GET", "/api/health")["status"] == 200
    assert "flashlight" in json.loads(request("GET", "/api/categories")["body"])["categories"]
    assert request("GET", "/api/missing")["status"] == 404


@pytest.mark.parametrize("body,length,code", [(b"", 0, 413), (b"bad", MAX_UPLOAD + 1, 413), (b"bad", 3, 400)])
def test_invalid_uploads(body, length, code):
    assert request("POST", "/api/scan?filename=input.json", body, length)["status"] == code


def test_failed_scan_cleans_up_upload(monkeypatch, tmp_path):
    import api.index as endpoint
    upload = tmp_path / "upload.json"
    def save(data, filename):
        upload.write_bytes(data)
        return str(upload)
    def fail(*args, **kwargs):
        raise RuntimeError("private internals")
    monkeypatch.setattr(endpoint, "save_upload", save)
    monkeypatch.setattr(endpoint, "run_scan", fail)
    response = request("POST", "/api/scan", b"{}")
    assert response["status"] == 500
    assert b"private internals" not in response["body"]
    assert not upload.exists()
