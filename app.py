"""PermGuard — Application Entry Point.

Starts the interactive security dashboard. Can be executed directly with:
    streamlit run streamlit_app.py
or:
    python app.py
"""
from __future__ import annotations

import os
from pathlib import Path
import runpy
import sys

ROOT = Path(__file__).resolve().parent
APP_SCRIPT = str(ROOT / "streamlit_app.py")

if __name__ == "__main__":
    from streamlit.web import cli as stcli

    port = os.environ.get("PORT", "8501")
    host = os.environ.get("HOST", "0.0.0.0")
    sys.argv = [
        "streamlit",
        "run",
        APP_SCRIPT,
        "--server.port",
        str(port),
        "--server.address",
        host,
    ]
    sys.exit(stcli.main())
else:
    # When loaded via `streamlit run app.py`
    runpy.run_path(APP_SCRIPT, run_name="__main__")
