"""One-time, process-wide pandas preload.

Streamlit imports pandas lazily inside each session thread (the first
``st.dataframe`` call), and some of its helpers import pandas *submodules*
directly (``from pandas.api.types import ...``), which bypasses the top-level
import lock. When two sessions hit that path at the same time, pandas can be
caught half-initialised: ``pandas._libs`` stays in ``sys.modules`` while the
top-level ``pandas`` module is evicted, and from then on every ``import pandas``
in the process fails with

    AttributeError: partially initialized module 'pandas' ... has no attribute
    '_pandas_parser_CAPI' (most likely due to a circular import)
    SystemError: <class 'pandas._libs.lib.__pyx_defaults'> returned a result
    with an exception set

Importing pandas once here, under a lock, turns every later import into a plain
cache hit. This module is imported once and cached in ``sys.modules``, so the
lock is shared by every Streamlit session in the process.
"""

from __future__ import annotations

import threading

_lock = threading.Lock()
_loaded = False


def preload_pandas() -> None:
    """Import pandas once per process, serialising concurrent sessions."""
    global _loaded
    if _loaded:
        return
    with _lock:
        if _loaded:
            return
        import pandas  # noqa: F401
        _loaded = True
