"""Report generation — JSON, CSV and colour-coded PDF exports.

The PDF is priority-ordered: findings are grouped and sorted so that
CRITICAL/HIGH issues appear at the top in red, then medium (amber), then
low (yellow), then passed checks (green). Every report carries the mandatory
disclaimer, the scoring method, rule versions and evidence links.
"""
from __future__ import annotations

import csv
import io
import json
import os
from datetime import datetime, timezone
from typing import Any, Optional

from .models import AssessmentStatus, ScanResult, Severity

DISCLAIMER = (
    "This report is an automated, evidence-based assessment. It is not an "
    "official Google Play compliance determination, an OWASP certification, "
    "or proof that an application is malicious. Manifest analysis alone "
    "cannot establish actual runtime behaviour."
)

# priority order for sorting (critical first)
_SEV_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

# colour palette (RGB)
_COLORS = {
    "CRITICAL": (0xB7, 0x1C, 0x1C),   # red
    "HIGH": (0xE6, 0x51, 0x00),       # orange-red
    "MEDIUM": (0xF9, 0xA8, 0x25),     # amber
    "LOW": (0xFD, 0xD8, 0x35),        # yellow
    "INFO": (0x90, 0xCA, 0xF9),       # blue
    "PASS": (0x43, 0xA0, 0x47),       # green
    "HEADER": (0x1A, 0x23, 0x7E),     # dark blue
    "TEXT": (0x21, 0x21, 0x21),
    "GREY": (0x75, 0x75, 0x75),
}

_LEVEL_COLOR = {"HIGH": "CRITICAL", "MEDIUM": "MEDIUM", "LOW": "PASS"}


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------

def to_json(result: ScanResult) -> str:
    doc = result.model_dump(mode="json")
    doc["generated_at"] = datetime.now(timezone.utc).isoformat()
    doc["generator"] = "PermissionGuard AI"
    doc["disclaimer"] = DISCLAIMER
    return json.dumps(doc, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# CSV
# ---------------------------------------------------------------------------

def to_csv(result: ScanResult) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "finding_id", "rule_id", "source_framework", "severity",
        "assessment_status", "confidence", "title", "affected_permissions",
        "score_contribution", "recommended_action", "evidence", "source_urls",
        "limitations",
    ])
    for f in _sorted_findings(result):
        writer.writerow([
            f.finding_id, f.rule_id, f.source_framework, f.severity.value,
            f.assessment_status.value, f.confidence.value, f.title,
            ";".join(f.affected_permissions), f.score_contribution,
            _flat(f.recommended_action), _flat(f.evidence),
            ";".join(u for u in f.source_urls if u), _flat(f.limitations),
        ])
    # permission inventory appended as a second section
    writer.writerow([])
    writer.writerow(["# PERMISSION INVENTORY"])
    writer.writerow(["permission", "sensitivity", "protection_level",
                     "runtime_category", "purpose_verdict", "description"])
    verdicts = {c.permission: c.verdict for c in result.purpose_compatibility}
    for p in result.metadata.permissions:
        writer.writerow([
            p.name, p.sensitivity.value, p.protection_level.value,
            p.runtime_category.value, verdicts.get(p.name, "UNDETERMINED"),
            _flat(p.description),
        ])
    return buf.getvalue()


def _flat(text: str) -> str:
    return " ".join((text or "").split())


def _sorted_findings(result: ScanResult):
    """Findings in report priority: CRITICAL first, PASS/NA last."""
    scored = [
        f for f in result.findings
        if f.assessment_status not in (AssessmentStatus.PASS,
                                       AssessmentStatus.NOT_APPLICABLE)
    ]
    tail = [
        f for f in result.findings
        if f.assessment_status in (AssessmentStatus.PASS,
                                   AssessmentStatus.NOT_APPLICABLE)
    ]
    scored.sort(key=lambda f: (_SEV_ORDER.get(f.severity, 5), f.rule_id))
    tail.sort(key=lambda f: f.rule_id)
    return scored + tail


# ---------------------------------------------------------------------------
# PDF (colour-coded, priority ordered)
# ---------------------------------------------------------------------------

def to_pdf(result: ScanResult, path: str) -> str:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
    )

    meta = result.metadata
    risk = result.risk
    level_color = _COLORS[_LEVEL_COLOR.get(risk.level.value, "MEDIUM")]

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "TitleX", parent=styles["Title"], fontSize=19, leading=23,
        textColor=colors.HexColor("#1A237E"), spaceAfter=2,
    )
    sub_style = ParagraphStyle(
        "SubX", parent=styles["Normal"], fontSize=9.5, leading=13,
        textColor=colors.HexColor("#546E7A"), spaceAfter=10,
    )
    h_style = ParagraphStyle(
        "HeadX", parent=styles["Heading2"], fontSize=13, leading=16,
        textColor=colors.HexColor("#1A237E"), spaceBefore=13, spaceAfter=6,
    )
    body = ParagraphStyle(
        "BodyX", parent=styles["Normal"], fontSize=9, leading=12.5,
        textColor=colors.HexColor("#212121"),
    )
    small = ParagraphStyle(
        "SmallX", parent=styles["Normal"], fontSize=7.8, leading=10.5,
        textColor=colors.HexColor("#424242"),
    )
    white_small = ParagraphStyle(
        "WhiteSmall", parent=body, textColor=colors.white, fontSize=9,
    )

    doc = SimpleDocTemplate(
        path, pagesize=A4,
        leftMargin=16 * mm, rightMargin=16 * mm,
        topMargin=15 * mm, bottomMargin=15 * mm,
        title=f"PermissionGuard Report — {meta.package_name or meta.filename}",
    )
    story = []

    # ---- header --------------------------------------------------------
    story.append(Paragraph("PermissionGuard AI — Security Assessment", title_style))
    story.append(Paragraph(
        f"Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} "
        f"&nbsp;|&nbsp; Scan ID {result.scan_id} "
        f"&nbsp;|&nbsp; Depth: {result.scan_depth_used.upper()} "
        f"&nbsp;|&nbsp; Mode: {result.scan_mode}",
        sub_style,
    ))

    # ---- score badge ---------------------------------------------------
    score_text = f"<font size=30 color='white'><b>{risk.score:.0f}</b></font>" \
                 f"<font size=12 color='white'>/100 &nbsp; {risk.level.value}</font>"
    badge = Table(
        [[Paragraph(score_text, white_small),
          Paragraph(
              f"<b>App:</b> {meta.app_label or '—'}<br/>"
              f"<b>Package:</b> {meta.package_name or '—'}<br/>"
              f"<b>Version:</b> {meta.version_name or '—'} "
              f"({meta.version_code or '—'})<br/>"
              f"<b>SDK:</b> min {meta.min_sdk or '?'} / target {meta.target_sdk or '?'}",
              body)]],
        colWidths=[52 * mm, 116 * mm],
    )
    badge.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, 0), colors.HexColor(
            f"#{level_color[0]:02x}{level_color[1]:02x}{level_color[2]:02x}")),
        ("BACKGROUND", (1, 0), (1, 0), colors.HexColor("#F5F5F5")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (0, 0), (0, 0), "CENTER"),
        ("LEFTPADDING", (0, 0), (-1, -1), 9),
        ("RIGHTPADDING", (0, 0), (-1, -1), 9),
        ("TOPPADDING", (0, 0), (-1, -1), 9),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#E0E0E0")),
    ]))
    story.append(badge)
    story.append(Spacer(1, 8))

    # ---- executive summary --------------------------------------------
    story.append(Paragraph("Executive Summary", h_style))
    counts = result.severity_counts
    summary_tbl = Table(
        [[
            Paragraph(f"<b>{counts.get('CRITICAL', 0)}</b><br/>CRITICAL", body),
            Paragraph(f"<b>{counts.get('HIGH', 0)}</b><br/>HIGH", body),
            Paragraph(f"<b>{counts.get('MEDIUM', 0)}</b><br/>MEDIUM", body),
            Paragraph(f"<b>{counts.get('LOW', 0)}</b><br/>LOW", body),
            Paragraph(f"<b>{len(result.metadata.permissions)}</b><br/>PERMISSIONS", body),
            Paragraph(f"<b>{len(result.recommendations)}</b><br/>ACTIONS", body),
        ]],
        colWidths=[28 * mm] * 6,
    )
    summary_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, 0), colors.HexColor("#FFEBEE")),
        ("BACKGROUND", (1, 0), (1, 0), colors.HexColor("#FFF3E0")),
        ("BACKGROUND", (2, 0), (2, 0), colors.HexColor("#FFF8E1")),
        ("BACKGROUND", (3, 0), (3, 0), colors.HexColor("#FFFDE7")),
        ("BACKGROUND", (4, 0), (5, 0), colors.HexColor("#E8EAF6")),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#E0E0E0")),
        ("INNERGRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#EEEEEE")),
    ]))
    story.append(summary_tbl)
    story.append(Spacer(1, 6))
    story.append(Paragraph(risk.explanation, body))

    # ---- purpose -------------------------------------------------------
    if result.purpose and result.purpose.category:
        story.append(Paragraph("Declared Purpose &amp; Compatibility", h_style))
        unexpected = [
            c for c in result.purpose_compatibility
            if c.verdict == "UNEXPECTED"
        ]
        story.append(Paragraph(
            f"<b>Category:</b> {result.purpose.category} &nbsp;|&nbsp; "
            f"<b>Unexpected permissions:</b> {len(unexpected)} "
            f"of {len(result.metadata.permissions)}", body))
        if unexpected:
            for c in unexpected[:12]:
                story.append(Paragraph(
                    f"• <b>{c.permission}</b> — {c.rationale[:220]}", small))
            if len(unexpected) > 12:
                story.append(Paragraph(
                    f"…and {len(unexpected) - 12} more.", small))

    # ---- findings by priority ------------------------------------------
    story.append(Paragraph("Findings — Priority Order (critical first)", h_style))
    story.append(Paragraph(
        "<font color='#B71C1C'>■</font> CRITICAL &nbsp; "
        "<font color='#E65100'>■</font> HIGH &nbsp; "
        "<font color='#F9A825'>■</font> MEDIUM &nbsp; "
        "<font color='#FDD835'>■</font> LOW &nbsp; "
        "<font color='#43A047'>■</font> PASSED", small))
    story.append(Spacer(1, 4))

    rows, styles_cmds = [], []
    row_i = 0
    # header row
    rows.append([
        Paragraph("<b>Severity</b>", white_small),
        Paragraph("<b>Finding / Rule</b>", white_small),
        Paragraph("<b>Status</b>", white_small),
        Paragraph("<b>Evidence &amp; Action</b>", white_small),
    ])
    styles_cmds.append(("BACKGROUND", (0, 0), (-1, 0),
                        colors.HexColor("#1A237E")))
    row_i += 1

    for f in _sorted_findings(result):
        color_key = f.severity.value
        if f.assessment_status in (AssessmentStatus.PASS,
                                   AssessmentStatus.NOT_APPLICABLE):
            color_key = "PASS"
        rgb = _COLORS[color_key]
        hexc = f"#{rgb[0]:02x}{rgb[1]:02x}{rgb[2]:02x}"

        sev_label = f.severity.value
        if f.assessment_status == AssessmentStatus.PASS:
            sev_label = "PASS"

        fw = {"google_play": "Google Play", "owasp_informed": "OWASP",
              "org_policy": "Org Policy", "combination": "Combo",
              "permissionguard": "App-Analysis"}.get(f.source_framework,
                                                     f.source_framework)
        left = Paragraph(
            f"<b>{sev_label}</b><br/><font size=6.5 color='#546E7A'>{fw}</font>",
            body)
        mid = Paragraph(
            f"<b>{f.title}</b><br/>"
            f"<font size=6.8 color='#546E7A'>{f.rule_id} "
            f"· confidence {f.confidence.value}</font>", body)
        st = Paragraph(f.assessment_status.value.replace("_", " "), body)
        aff = ", ".join(f.affected_permissions[:4])
        if len(f.affected_permissions) > 4:
            aff += f" (+{len(f.affected_permissions) - 4})"
        ev = (f.evidence or "").replace("\n", " ")
        right_parts = [f"<b>Perms:</b> {aff}" if aff else ""]
        if ev:
            right_parts.append(f"<b>Evidence:</b> {ev[:300]}")
        if f.recommended_action:
            right_parts.append(
                f"<b>Action:</b> {' '.join(f.recommended_action.split())[:280]}")
        right = Paragraph("<br/>".join(p for p in right_parts if p), small)

        rows.append([left, mid, st, right])
        styles_cmds.append(("BACKGROUND", (0, row_i), (0, row_i),
                            colors.HexColor(hexc)))
        row_i += 1

    if len(rows) > 1:
        findings_tbl = Table(
            rows, colWidths=[24 * mm, 52 * mm, 24 * mm, 68 * mm],
            repeatRows=1,
        )
        base = [
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#E0E0E0")),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]
        # alternate row shading for readability
        for i in range(1, len(rows)):
            if i % 2 == 0:
                base.append(("BACKGROUND", (1, i), (-1, i),
                             colors.HexColor("#FAFAFA")))
        findings_tbl.setStyle(TableStyle(base + styles_cmds))
        story.append(findings_tbl)

    # ---- recommendations ------------------------------------------------
    if result.recommendations:
        story.append(Paragraph("Recommended Corrective Actions (prioritised)", h_style))
        for r in result.recommendations[:14]:
            aff = ", ".join(r.get("affected_permissions", [])[:4])
            story.append(Paragraph(
                f"<b>{r['order']}. [{r['action']}] {r['title']}</b>"
                + (f"<br/><font color='#B71C1C'>permanently:</font> {aff}"
                   if aff and r['action'] == 'REVOKE' else ""),
                body))
            if r.get("alternatives"):
                story.append(Paragraph(
                    f"&nbsp;&nbsp;&nbsp;→ Less-intrusive alternative: "
                    f"{'; '.join(r['alternatives'][:2])}", small))
            story.append(Spacer(1, 2))

    # ---- score breakdown -------------------------------------------------
    story.append(Paragraph("Risk Score Breakdown", h_style))
    story.append(Paragraph(f"<i>{risk.method}</i>", small))
    story.append(Spacer(1, 4))
    bd_rows = [[
        Paragraph("<b>Rule</b>", white_small),
        Paragraph("<b>Contribution</b>", white_small),
        Paragraph("<b>Points</b>", white_small),
        Paragraph("<b>Why</b>", white_small),
    ]]
    for b in risk.breakdown[:20]:
        bd_rows.append([
            Paragraph(b.rule_id, small),
            Paragraph(b.label[:90], small),
            Paragraph(f"<b>+{b.applied_points:.1f}</b>", small),
            Paragraph(b.reason[:150], small),
        ])
    bd_rows.append([
        Paragraph("<b>TOTAL</b>", body), Paragraph("", body),
        Paragraph(f"<b>{risk.score:.0f}/100 → {risk.level.value}</b>", body),
        Paragraph(f"raw {risk.thresholds.get('raw_total', '')}", small),
    ])
    bd = Table(bd_rows, colWidths=[32 * mm, 56 * mm, 26 * mm, 54 * mm],
               repeatRows=1)
    bd_style = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1A237E")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#E0E0E0")),
        ("BACKGROUND", (0, len(bd_rows) - 1), (-1, len(bd_rows) - 1),
         colors.HexColor("#E8EAF6")),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]
    bd.setStyle(TableStyle(bd_style))
    story.append(bd)

    # ---- optional MobSF supporting evidence (never scored) --------------
    _append_mobsf_pdf(story, result, h_style, body, small, white_small)

    # ---- metadata / sources / limitations -------------------------------
    story.append(Paragraph("Sources, Versions &amp; Limitations", h_style))
    versions = ", ".join(f"{k} {v}" for k, v in result.rule_versions.items())
    story.append(Paragraph(f"<b>Rule versions:</b> {versions}", small))
    story.append(Paragraph(
        "<b>Sources:</b> Google Play policy (support.google.com/googleplay/"
        "android-developer), OWASP MASVS/MASWE (mas.owasp.org), Android "
        "permission reference (developer.android.com), organisation policy "
        "file (config/orgpolicy.yaml).", small))
    story.append(Spacer(1, 4))
    for note in (result.metadata.extraction_notes or [])[:6]:
        story.append(Paragraph(f"• Extraction: {note}", small))
    story.append(Paragraph(
        "<b>Testing limitations:</b> This assessment is based on static "
        "analysis of the manifest, archive structure and (for deep scans) "
        "compiled-string indicators. It does not execute the application, "
        "does not observe runtime behaviour, and cannot verify in-app "
        "disclosures, the Play Data Safety form, or server-side data "
        "handling. Findings marked NEEDS_REVIEW or INSUFFICIENT_EVIDENCE "
        "require evidence outside the APK. Category-based necessity depends "
        "on the purpose you declared for the app.", small))

    # ---- disclaimer ------------------------------------------------------
    story.append(Spacer(1, 8))
    disc = Table(
        [[Paragraph(f"<b>DISCLAIMER</b><br/>{DISCLAIMER}", small)]],
        colWidths=[168 * mm],
    )
    disc.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FFF8E1")),
        ("BOX", (0, 0), (-1, -1), 0.8, colors.HexColor("#F9A825")),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    story.append(disc)

    doc.build(story)
    return path


def _append_mobsf_pdf(story, result: ScanResult, h_style, body, small, white_small) -> None:
    """PDF section only when MobSF / sample JSON was actually used.

    The PermGuard score in the header is unchanged. MobSF's own score is
    labelled separately so it cannot be mistaken for extra risk points.
    """
    from reportlab.lib import colors
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, Spacer, Table, TableStyle

    ev = result.supporting_evidence or {}
    if not ev.get("used"):
        return

    story.append(Paragraph(
        "Supporting Evidence (MobSF) — Optional external cross-check",
        h_style,
    ))
    story.append(Paragraph(
        "<b>Optional — external cross-check.</b> This section is supporting "
        "evidence only. It does <b>not</b> add, subtract, or modify the "
        "PermGuard score above (overlapping findings are never double-counted).",
        small,
    ))
    story.append(Spacer(1, 4))

    mobsf_score = ev.get("mobsf_score")
    score_txt = "—" if mobsf_score is None else str(mobsf_score)
    src = ev.get("source") or "live"
    story.append(Paragraph(
        f"<b>MobSF score</b> (shown as-is, not blended): {score_txt}"
        f" &nbsp;|&nbsp; source: {src}",
        body,
    ))

    dang = ev.get("dangerous_permissions") or []
    if dang:
        story.append(Paragraph(
            f"<b>Dangerous permissions (MobSF):</b> {len(dang)}", body))
        for p in dang[:12]:
            story.append(Paragraph(
                f"• {_xml(p.get('name'))} — { _xml(p.get('status')) }",
                small))

    issues = ev.get("manifest_issues") or []
    if issues:
        story.append(Paragraph(
            f"<b>Manifest issues (MobSF):</b> {len(issues)}", body))
        for item in issues[:8]:
            story.append(Paragraph(
                f"• [{_xml(item.get('severity'))}] {_xml(item.get('title'))}",
                small))

    exported = ev.get("exported_components") or []
    if exported:
        story.append(Paragraph(
            f"<b>Exported components (MobSF):</b> {len(exported)}", body))
        for item in exported[:8]:
            story.append(Paragraph(
                f"• {_xml(item.get('type'))} {_xml(item.get('name'))}",
                small))

    trackers = (ev.get("trackers") or {}).get("items") or []
    tcount = (ev.get("trackers") or {}).get("count", len(trackers))
    story.append(Paragraph(f"<b>Trackers (MobSF):</b> {tcount}", body))
    for t in trackers[:6]:
        story.append(Paragraph(f"• {_xml(t.get('name'))}", small))

    agree = ev.get("agreement") or []
    if agree:
        story.append(Spacer(1, 4))
        story.append(Paragraph(
            "Permission agreement — “confirmed by MobSF” is not extra risk",
            body,
        ))
        rows = [[
            Paragraph("<b>Permission</b>", white_small),
            Paragraph("<b>Agreement</b>", white_small),
            Paragraph("<b>PermGuard</b>", white_small),
            Paragraph("<b>MobSF</b>", white_small),
        ]]
        for row in agree[:20]:
            rows.append([
                Paragraph(_xml(row.get("permission")), small),
                Paragraph(_xml(row.get("agreement")), small),
                Paragraph(_xml(row.get("permguard")), small),
                Paragraph(_xml(row.get("mobsf")), small),
            ])
        tbl = Table(rows, colWidths=[70 * mm, 40 * mm, 28 * mm, 30 * mm],
                    repeatRows=1)
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#546E7A")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#E0E0E0")),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(tbl)

    dyn = ev.get("experimental_dynamic")
    if dyn:
        story.append(Spacer(1, 4))
        story.append(Paragraph(
            "<b>Experimental</b> dynamic analysis (does not affect the score).",
            body,
        ))
        if not dyn.get("ok"):
            story.append(Paragraph(
                f"Dynamic analysis did not complete: {_xml(dyn.get('error'))}",
                small,
            ))
        else:
            used = ", ".join(dyn.get("runtime_used") or []) or "—"
            only = ", ".join(dyn.get("declared_only") or []) or "—"
            story.append(Paragraph(f"Runtime-used: {used}", small))
            story.append(Paragraph(f"Declared only: {only}", small))


def _xml(value: Any) -> str:
    return (
        str(value or "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


# ---------------------------------------------------------------------------
# convenience
# ---------------------------------------------------------------------------

def export(result: ScanResult, kind: str, out_dir: str) -> str:
    """Write a report of the requested kind; returns the file path."""
    os.makedirs(out_dir, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    base = f"permguard_{result.scan_id}_{stamp}"

    if kind == "json":
        path = os.path.join(out_dir, base + ".json")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(to_json(result))
        return path
    if kind == "csv":
        path = os.path.join(out_dir, base + ".csv")
        with open(path, "w", encoding="utf-8", newline="") as fh:
            fh.write(to_csv(result))
        return path
    if kind == "pdf":
        return to_pdf(result, os.path.join(out_dir, base + ".pdf"))
    raise ValueError(f"Unknown report kind: {kind}")
