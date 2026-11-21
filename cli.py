"""PermGuard CLI — Enterprise command-line static security scanner for Android apps.

Usage:
    python cli.py <path_to_apk_or_manifest> [options]

Examples:
    python cli.py my_app.apk
    python cli.py my_app.apk --category calculator --max-score 50
    python cli.py my_app.apk --output report.pdf
    python cli.py my_app.apk --output report.json --fail-on-critical
"""
from __future__ import annotations

import argparse
from pathlib import Path
import shutil
import sys
import tempfile
from typing import Optional

from src.pipeline import ScanError, run_scan
from src.reportgenerator import to_csv, to_json, to_pdf


def format_summary_table(result) -> str:
    """Format an executive terminal summary of scan findings."""
    meta = result.metadata
    risk = result.risk
    counts = result.severity_counts

    lines = [
        "=" * 68,
        "  PERMGUARD SECURITY AUDIT REPORT",
        "=" * 68,
        f"  App Package  : {meta.package_name or 'N/A'}",
        f"  App Label    : {meta.app_label or 'N/A'}",
        f"  Version      : {meta.version_name or 'N/A'} (code: {meta.version_code or 'N/A'})",
        f"  Target SDK   : {meta.target_sdk or 'N/A'} (min: {meta.min_sdk or 'N/A'})",
        f"  Scan Depth   : {result.scan_depth_used.upper()}",
        "-" * 68,
        f"  OVERALL RISK SCORE : {risk.score:.1f} / 100  [{risk.level.value.upper()}]",
        f"  Permissions Total  : {len(meta.permissions)}",
        f"  Critical Findings  : {counts.get('CRITICAL', 0)}",
        f"  High Severity      : {counts.get('HIGH', 0)}",
        f"  Medium Severity    : {counts.get('MEDIUM', 0)}",
        f"  Low Severity       : {counts.get('LOW', 0)}",
        "-" * 68,
    ]

    if result.findings:
        lines.append("  KEY FINDINGS:")
        for finding in result.findings[:8]:
            sev = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
            lines.append(f"    [{sev:<8}] {finding.title}")
            if finding.description:
                first_line = finding.description.splitlines()[0][:65]
                lines.append(f"               {first_line}...")
        if len(result.findings) > 8:
            lines.append(f"    ... and {len(result.findings) - 8} more findings.")
        lines.append("-" * 68)

    if result.recommendations:
        lines.append("  TOP RECOMMENDED ACTIONS:")
        for rec in result.recommendations[:4]:
            if isinstance(rec, dict):
                title = rec.get("title", "")
                act = rec.get("action", "")
            else:
                title = getattr(rec, "title", "")
                act = getattr(rec, "action", "")
            lines.append(f"    • [{act}] {title}")
        lines.append("-" * 68)

    lines.append("=" * 68)
    return "\n".join(lines)


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="PermGuard — Static Android Permission & Privacy-Risk Security Scanner",
        prog="permguard-cli",
    )
    parser.add_argument("file", help="Path to APK, AAB, or AndroidManifest.xml file")
    parser.add_argument(
        "-c", "--category",
        help="Declared app category (e.g. calculator, navigation, shopping, photography, tools)",
        default=None,
    )
    parser.add_argument(
        "-d", "--depth",
        choices=["auto", "basic", "deep"],
        default="auto",
        help="Scan depth mode (default: auto)",
    )
    parser.add_argument(
        "-o", "--output",
        help="Save report to file (.json, .csv, or .pdf)",
        default=None,
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Stdout output format (default: text table)",
    )
    parser.add_argument(
        "--max-score",
        type=float,
        default=None,
        help="Fail (exit code 1) if risk score exceeds this threshold (e.g., 50.0)",
    )
    parser.add_argument(
        "--fail-on-critical",
        action="store_true",
        help="Fail (exit code 1) if any CRITICAL finding is detected",
    )

    args = parser.parse_args(argv)
    target_path = Path(args.file)

    if not target_path.exists():
        sys.stderr.write(f"Error: File not found: {args.file}\n")
        return 2

    # Protect user's original file by copying to a temporary file before scan
    with tempfile.NamedTemporaryFile(delete=False, suffix=target_path.suffix) as tmp_file:
        shutil.copy2(target_path, tmp_file.name)
        work_path = tmp_file.name

    try:
        result = run_scan(
            path=work_path,
            original_filename=target_path.name,
            purpose_category=args.category,
            scan_mode=args.depth,
        )
    except ScanError as exc:
        sys.stderr.write(f"Scan failed: {exc}\n")
        return 2
    except Exception as exc:
        sys.stderr.write(f"Unexpected error during scan: {exc}\n")
        return 3

    # Handle output file export
    if args.output:
        out_path = Path(args.output)
        suffix = out_path.suffix.lower()
        if suffix == ".json":
            out_path.write_text(to_json(result), encoding="utf-8")
        elif suffix == ".csv":
            out_path.write_text(to_csv(result), encoding="utf-8")
        elif suffix == ".pdf":
            out_path.write_bytes(to_pdf(result))
        else:
            sys.stderr.write(f"Warning: Unknown file extension '{suffix}'. Saving as JSON.\n")
            out_path.write_text(to_json(result), encoding="utf-8")
        print(f"Report exported to: {out_path.resolve()}")

    # Handle stdout
    if args.format == "json":
        print(to_json(result))
    else:
        print(format_summary_table(result))

    # Evaluate CI/CD failure gates
    if args.max_score is not None and result.risk.score > args.max_score:
        sys.stderr.write(
            f"\n[CI/CD GATE FAILED] Risk score {result.risk.score:.1f} exceeds threshold of {args.max_score:.1f}\n"
        )
        return 1

    if args.fail_on_critical:
        critical_count = result.severity_counts.get("CRITICAL", 0)
        if critical_count > 0:
            sys.stderr.write(
                f"\n[CI/CD GATE FAILED] {critical_count} CRITICAL finding(s) detected.\n"
            )
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
