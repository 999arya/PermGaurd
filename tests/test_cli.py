"""Automated tests for the PermGuard CLI interface."""
from __future__ import annotations

import json
from pathlib import Path
import pytest

import cli


def test_cli_help(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["--help"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "PermGuard" in captured.out


def test_cli_scan_calculator(capsys):
    calc_path = Path(__file__).resolve().parents[1] / "data" / "sampleapps" / "calculator.apk"
    code = cli.main([str(calc_path)])
    assert code == 0
    captured = capsys.readouterr()
    assert "com.synthetic.calculator" in captured.out
    assert "OVERALL RISK SCORE" in captured.out


def test_cli_json_format(capsys):
    calc_path = Path(__file__).resolve().parents[1] / "data" / "sampleapps" / "calculator.apk"
    code = cli.main([str(calc_path), "--format", "json"])
    assert code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["metadata"]["package_name"] == "com.synthetic.calculator"
    assert "risk" in data


def test_cli_ci_gate_fails_on_critical(capsys):
    flashlight_path = Path(__file__).resolve().parents[1] / "data" / "sampleapps" / "flashlight_overprivileged.apk"
    code = cli.main([str(flashlight_path), "--fail-on-critical"])
    assert code == 1
    captured = capsys.readouterr()
    assert "[CI/CD GATE FAILED]" in captured.err


def test_cli_export_json(tmp_path):
    calc_path = Path(__file__).resolve().parents[1] / "data" / "sampleapps" / "calculator.apk"
    out_file = tmp_path / "scan_output.json"
    code = cli.main([str(calc_path), "-o", str(out_file)])
    assert code == 0
    assert out_file.exists()
    payload = json.loads(out_file.read_text(encoding="utf-8"))
    assert payload["metadata"]["package_name"] == "com.synthetic.calculator"


def test_cli_file_not_found(capsys):
    code = cli.main(["non_existent_file.apk"])
    assert code == 2
    captured = capsys.readouterr()
    assert "File not found" in captured.err
