"""PermGuard Flask entry point for local execution, Docker, and Vercel serverless deployment."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Mapping

from flask import Flask, Response, jsonify, send_from_directory
from werkzeug.exceptions import RequestEntityTooLarge

ROOT = Path(__file__).resolve().parent


def create_app(test_config: Mapping[str, Any] | None = None) -> Flask:
    """Application factory for PermGuard Flask web service."""
    app = Flask(__name__, static_folder=None)
    hosted = os.environ.get("VERCEL") == "1"

    app.config.update(
        HOSTED=hosted,
        MAX_CONTENT_LENGTH=4_000_000 if hosted else 262_144_000,
        MAX_FORM_MEMORY_SIZE=4_000_000,
        DATABASE=str(ROOT / "data" / "scans.db"),
        CACHE_DIR=str(ROOT / "data" / "scan_cache"),
        SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SECURE=hosted,
    )

    if test_config:
        app.config.update(test_config)

    app.secret_key = os.environ.get("PERMGUARD_SESSION_SECRET") or (
        None if app.config["HOSTED"] else os.urandom(32)
    )
    if app.config["HOSTED"] and app.secret_key and len(app.secret_key) < 32:
        app.secret_key = None

    @app.after_request
    def apply_security_headers(response: Response) -> Response:
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = (
            "no-store" if response.mimetype == "text/html" else "public, max-age=3600"
        )
        if (
            app.config["HOSTED"]
            and response.content_length
            and response.content_length > 4_000_000
        ):
            return Response(
                "This report exceeds the hosted response limit. Run the same dashboard locally for this scan.",
                status=413,
            )
        return response

    @app.errorhandler(RequestEntityTooLarge)
    def handle_oversized_payload(error: Exception):
        return (
            jsonify(
                error="Upload exceeds the server request limit. Use the local dashboard for larger files."
            ),
            413,
        )

    @app.route("/", methods=["GET", "POST"])
    def home():
        if not app.secret_key:
            return (
                Response(
                    "Set PERMGUARD_SESSION_SECRET to a random secret of at least 32 characters in Vercel Environment Variables, then redeploy.",
                    status=503,
                )
            )
        from src.webruntime import render_dashboard

        return render_dashboard()

    @app.get("/api/health")
    def health():
        status = "ok" if app.secret_key else "configuration_required"
        code = 200 if app.secret_key else 503
        return jsonify(status=status), code

    @app.get("/_ui/<name>")
    def ui_asset(name: str):
        if name == "plotly.js":
            from plotly.offline import get_plotlyjs

            return Response(get_plotlyjs(), mimetype="application/javascript")
        return send_from_directory(ROOT / "public" / "_ui", name)

    return app


app = create_app()

if __name__ == "__main__":
    from waitress import serve

    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8501"))
    print(f"PermGuard service running on http://{host}:{port}")
    serve(app, host=host, port=port)
