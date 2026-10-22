"""Shared pytest fixtures — synthetic APKs built in-process."""
from __future__ import annotations

import os
import sys
import tempfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from tools.build_fixtures import FIXTURES, build_apk  # noqa: E402
from src.knowledgebase import load_knowledgebase  # noqa: E402


@pytest.fixture(scope="session")
def kb():
    return load_knowledgebase()


@pytest.fixture(scope="session")
def fixture_dir():
    """Build all five synthetic APKs once per session."""
    d = tempfile.mkdtemp(prefix="permguard_fixtures_")
    for key, spec in FIXTURES.items():
        build_apk(
            path=os.path.join(d, f"{key}.apk"),
            package=spec["package"],
            version_name=spec["version_name"],
            version_code=spec["version_code"],
            min_sdk=spec["min_sdk"],
            target_sdk=spec["target_sdk"],
            permissions=spec["permissions"],
            application_attrs=spec["application_attrs"],
            extra_elements=spec.get("extra_elements"),
            dex=spec.get("dex"),
            extra_files=spec.get("extra_files"),
        )
    return d


@pytest.fixture
def apk_path(fixture_dir):
    def _get(key: str) -> str:
        path = os.path.join(fixture_dir, f"{key}.apk")
        assert os.path.isfile(path), f"fixture {key} missing"
        return path
    return _get


@pytest.fixture
def scan_apk(apk_path, tmp_path):
    """Disposable copy of a fixture APK, safe to hand to run_scan.

    run_scan deletes its input file after parsing (privacy guarantee), so
    tests that scan must copy the session fixture first.
    """
    import shutil

    def _copy(key: str) -> str:
        work = tmp_path / f"{key}.apk"
        shutil.copy2(apk_path(key), str(work))
        return str(work)
    return _copy


@pytest.fixture(scope="session")
def expectations():
    """Reviewed ground truth maintained by tools/build_fixtures.py."""
    import json
    path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "data", "sampleapps", "expectations.json",
    )
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture
def tmp_apk(tmp_path):
    """Builder for ad-hoc APKs inside a single test."""
    def _build(name: str, **kwargs) -> str:
        path = str(tmp_path / name)
        build_apk(path=path, **kwargs)
        return path
    return _build
