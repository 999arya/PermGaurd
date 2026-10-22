"""Scan pipeline — orchestrates extraction → analysis → scoring → output.

Stages:
  1. Validate upload (hostile-input guards)
  2. Extract (APK or structured report)
  3. Triage → decide scan depth (basic | deep)
  4. Classify permissions against the knowledge base
  5. Purpose analysis (user-declared category)
  6. Rule engines: Google Play policy, OWASP-informed, org policy,
     combinations, privilege escalation, kernel/root indicators
  7. Deterministic risk scoring with breakdown
  8. Prioritised recommendations

Everything is local: no network calls are made anywhere in this module.
"""
from __future__ import annotations

import os
import tempfile
import time
import uuid
from datetime import datetime, timezone
from typing import Optional

from .apkextractor import ExtractionError, extract_apk
from .combinationdetector import evaluate as eval_combinations
from .escalationdetector import evaluate as eval_escalation
from .inputparsers import InputParseError, parse_structured
from .knowledgebase import KnowledgeBase, load_knowledgebase
from .kernelrootdetector import evaluate as eval_kernel
from .models import (
    AssessmentStatus,
    Confidence,
    Finding,
    PurposeProfile,
    ScanResult,
    SensitivityTier,
    Severity,
)
from .orgpolicyengine import evaluate as eval_org_policy
from .owaspengine import evaluate as eval_owasp
from .permissionclassifier import classify_metadata, sensitivity_summary
from .policyengine import evaluate as eval_play_policy
from .purposeanalyzer import (
    OVERPRIVILEGE_KEY,
    UNDETERMINED,
    UNEXPECTED,
    assess_compatibility,
    build_purpose,
    compatibility_map,
    tier_severity,
    infer_category,
)
from .recommendationengine import build as build_recommendations
from .riskengine import score as score_risk
from .security import UploadValidationError, validate_upload


class ScanError(RuntimeError):
    """User-facing scan failure with a clear, non-fabricating message."""


# ---------------------------------------------------------------------------
# depth decision
# ---------------------------------------------------------------------------

def decide_depth(meta, kb: KnowledgeBase, requested: str) -> tuple[str, str]:
    """Return (depth, reason). requested: auto | basic | deep."""
    if requested == "deep":
        return "deep", "Deep scan requested explicitly by the user."
    if requested == "basic":
        return "basic", "Minimum scan requested explicitly by the user."

    # auto: triage signals
    sensitive = [
        p for p in meta.permissions
        if p.sensitivity in (SensitivityTier.HIGH, SensitivityTier.CRITICAL)
    ]
    cfg = (kb.appconfig or {}).get("scan", {}) or {}
    threshold = int(cfg.get("auto_deep_min_sensitivity_hits", 1))

    reasons: list[str] = []
    if sensitive and len(sensitive) >= threshold:
        reasons.append(
            f"{len(sensitive)} HIGH/CRITICAL-sensitivity permission(s) declared"
        )
    bg = "android.permission.ACCESS_BACKGROUND_LOCATION"
    if cfg.get("deep_on_background_access", True) and any(
        p.name == bg for p in meta.permissions
    ):
        reasons.append("background location requested")
    if cfg.get("deep_on_escalation_signals", True) and meta.debuggable:
        reasons.append("app is debuggable")
    if meta.elf_assets:
        reasons.append("executable payloads staged in assets/")

    if reasons:
        return "deep", "Auto triage escalated to DEEP scan: " + "; ".join(reasons) + "."
    return (
        "basic",
        "Auto triage kept a MINIMUM scan: no high-sensitivity or escalation "
        "signals detected in triage.",
    )


# ---------------------------------------------------------------------------
# purpose engine findings (category necessity -> findings)
# ---------------------------------------------------------------------------

def _purpose_findings(meta, purpose: Optional[PurposeProfile],
                      compat: list, kb: KnowledgeBase) -> list[Finding]:
    out: list[Finding] = []
    verdicts = compatibility_map(compat)
    purpose_known = bool(purpose and purpose.category)

    if not purpose_known:
        out.append(Finding(
            finding_id="",
            rule_id="PG-PURPOSE-000",
            source_framework="permissionguard",
            title="Application purpose not declared — necessity check unavailable",
            description=(
                "Excessive-permission detection needs the app's declared "
                "purpose. Supply the app category to compare requested "
                "permissions against what that kind of app normally needs."
            ),
            affected_permissions=[],
            evidence="No category supplied by the user.",
            severity=Severity.INFO,
            confidence=Confidence.HIGH,
            assessment_status=AssessmentStatus.INSUFFICIENT_EVIDENCE,
            recommended_action="Provide the app category/purpose and re-run the scan.",
            source_urls=[],
            limitations="Permissions are still classified, scored and checked against policy rules.",
            category="purpose",
        ))
        return out

    unexpected = [p for p in meta.permissions if verdicts.get(p.name) == UNEXPECTED]
    if not unexpected:
        out.append(Finding(
            finding_id="",
            rule_id="PG-PURPOSE-001",
            source_framework="permissionguard",
            title="All declared permissions are consistent with the app purpose",
            description=(
                f"Every declared permission maps to the expected or optional "
                f"set for a '{purpose.category}' application."
            ),
            affected_permissions=[],
            evidence=f"{len(meta.permissions)} permission(s) checked against category '{purpose.category}'.",
            severity=Severity.INFO,
            confidence=Confidence.HIGH,
            assessment_status=AssessmentStatus.PASS,
            recommended_action="No action required.",
            source_urls=[],
            limitations="Based on the user-declared category.",
            category="purpose",
        ))
        return out

    # group unexpected by sensitivity for readable findings
    for tier in (SensitivityTier.CRITICAL, SensitivityTier.HIGH,
                 SensitivityTier.MODERATE, SensitivityTier.LOW,
                 SensitivityTier.NONE):
        group = [p for p in unexpected if p.sensitivity == tier]
        if not group:
            continue
        sev = tier_severity(tier, len(group))
        names = [p.name for p in group]
        top = group[0]
        out.append(Finding(
            finding_id="",
            rule_id=f"PG-PURPOSE-{tier.name}",
            source_framework="permissionguard",
            title=(
                f"{len(names)} permission(s) not required by "
                f"'{purpose.category}' apps ({tier.value} sensitivity)"
            ),
            description=(
                f"Declared purpose is '{purpose.category}'. These permissions "
                "are outside that category's expected set — i.e. potentially "
                "excessive privileges.\n\n"
                f"{(top.excess_conditions[0] if top.excess_conditions else top.description)}"
            ),
            affected_permissions=names,
            evidence=(
                "Category expectation mismatch. Example — "
                f"{top.name}: {top.data_or_functionality or 'sensitive capability'}. "
                f"Rationale: {(compat and next((c.rationale for c in compat if c.permission == top.name), '')) or ''}"
            ),
            severity=sev,
            confidence=Confidence.HIGH,
            assessment_status=(
                AssessmentStatus.POTENTIAL_CONCERN
                if tier in (SensitivityTier.CRITICAL, SensitivityTier.HIGH)
                else AssessmentStatus.POTENTIAL_CONCERN
            ),
            recommended_action=(
                "Remove these permissions if the app has no corresponding "
                "feature; otherwise document the feature mapping and request "
                "only at the point of use."
            ),
            source_urls=["https://support.google.com/googleplay/android-developer/answer/16558241"],
            limitations=(
                "Necessity is judged against the user-declared category and "
                "our category profiles; a legitimate bespoke feature may not "
                "be covered."
            ),
            category="purpose",
            correlation_key=OVERPRIVILEGE_KEY,
        ))

    # unknown permissions worth flagging
    unknown = [p for p in meta.permissions if not p.known_to_android and not p.custom]
    if unknown:
        out.append(Finding(
            finding_id="",
            rule_id="PG-UNKNOWN-PERM",
            source_framework="permissionguard",
            title="Permission(s) not present in the knowledge base",
            description=(
                "These permissions are not in the Android permission knowledge "
                "base — they may be OEM/vendor-specific, newly introduced, or "
                "typosquat-style look-alikes of platform permissions."
            ),
            affected_permissions=[p.name for p in unknown],
            evidence=", ".join(p.name for p in unknown),
            severity=Severity.LOW,
            confidence=Confidence.MEDIUM,
            assessment_status=AssessmentStatus.NEEDS_REVIEW,
            recommended_action="Identify the permission's origin (OEM or app-defined) and classify manually.",
            source_urls=["https://developer.android.com/reference/android/Manifest.permission"],
            limitations="Knowledge base does not cover every vendor extension.",
            category="permission",
        ))
    return out


# ---------------------------------------------------------------------------
# main entry point
# ---------------------------------------------------------------------------

def run_scan(
    path: str,
    original_filename: str,
    purpose_category: Optional[str] = None,
    purpose_description: str = "",
    scan_mode: str = "auto",
    environment: str = "low",
    kb: Optional[KnowledgeBase] = None,
) -> ScanResult:
    """Run a full analysis on an uploaded file. Raises ScanError on failure."""
    started = time.time()
    scan_id = uuid.uuid4().hex[:12]
    kb = kb or load_knowledgebase()

    # -- validate & extract -----------------------------------------------
    # Privacy guarantee: the temp upload is removed whether validation
    # succeeds, fails, or the scan raises — no uploaded bytes survive.
    try:
        try:
            validated = validate_upload(path, original_filename)
        except UploadValidationError as exc:
            raise ScanError(str(exc)) from exc

        lower = validated.filename.lower()
        if lower.endswith(".apk") or lower.endswith(".aab"):
            # depth decision needs permissions first -> extract basic, then
            # re-run deep extraction if triage says so
            try:
                meta = extract_apk(path, validated.filename, deep=False,
                                   sha256=validated.sha256)
            except ExtractionError as exc:
                raise ScanError(str(exc)) from exc
            depth, depth_reason = decide_depth(meta, kb, scan_mode)
            if depth == "deep":
                try:
                    meta = extract_apk(path, validated.filename, deep=True,
                                       sha256=validated.sha256)
                except ExtractionError as exc:
                    meta.extraction_notes.append(
                        f"Deep extraction failed, results from basic pass kept: {exc}"
                    )
                    depth = "basic"
                    depth_reason = "Deep scan failed; basic results retained."
        else:
            try:
                with open(path, "rb") as fh:
                    raw = fh.read(8 * 1024 * 1024 + 1)
                text = raw.decode("utf-8", errors="replace")
                meta = parse_structured(validated.filename, text)
            except (InputParseError, UnicodeDecodeError) as exc:
                raise ScanError(str(exc)) from exc
            depth = "basic"
            depth_reason = "Structured permission report — no archive to deep-scan."
    finally:
        # privacy: delete the upload immediately after parsing
        if not (kb.appconfig.get("storage") or {}).get("keep_uploaded_files", False):
            _safe_unlink(path)

    meta.sha256 = validated.sha256
    meta.file_size = validated.size

    # -- classify ---------------------------------------------------------
    classify_metadata(meta, kb)

    # -- purpose ----------------------------------------------------------
    purpose: Optional[PurposeProfile] = None
    cat = (purpose_category or '').lower() if purpose_category else None
    if cat == 'auto':
        inferred, rationale, signals = infer_category(meta, kb)
        cat_to_use = inferred
        purpose = build_purpose(
            cat_to_use,
            app_name=meta.app_label,
            description=purpose_description or rationale,
            source='inferred' if inferred else 'user',
        )
    elif cat:
        purpose = build_purpose(
            cat,
            app_name=meta.app_label,
            description=purpose_description,
            source='user',
        )
    compat = assess_compatibility(meta, purpose, kb)

    # -- rule engines -----------------------------------------------------
    findings: list[Finding] = []
    findings.extend(_purpose_findings(meta, purpose, compat, kb))
    findings.extend(eval_play_policy(kb, meta, purpose, compat))
    findings.extend(eval_owasp(kb, meta, purpose, compat))
    findings.extend(eval_org_policy(kb, meta, purpose, compat))
    findings.extend(eval_combinations(kb, meta, purpose))
    findings.extend(eval_escalation(kb, meta))

    if depth == "deep":
        findings.extend(eval_kernel(kb, meta))
    else:
        # kernel/root checks require DEX scanning — record that honestly
        if meta.input_type == "apk":
            findings.append(Finding(
                finding_id="",
                rule_id="KR-DEPTH-NOTE",
                source_framework="permissionguard",
                title="Kernel/root string analysis not performed (minimum scan)",
                description=(
                    "Deep-scan DEX string analysis for root and kernel "
                    "indicators was skipped because triage selected a minimum "
                    "scan. Run a deep scan to include it."
                ),
                affected_permissions=[],
                evidence=depth_reason,
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                assessment_status=AssessmentStatus.NOT_APPLICABLE,
                recommended_action="Re-run with scan mode 'Deep' to enable kernel/root string analysis.",
                source_urls=[],
                limitations="This is a scope note, not a finding: kernel/root indicators were not examined in this scan, so their absence here means nothing.",
                category="kernel_root",
            ))

    # assign stable finding ids
    for i, f in enumerate(findings, 1):
        if not f.finding_id:
            f.finding_id = f"F{i:03d}"

    # -- score ------------------------------------------------------------
    risk = score_risk(kb, findings, meta, compat)

    # -- recommendations --------------------------------------------------
    recommendations = build_recommendations(kb, findings, compat, meta, risk.score)

    # -- assemble ---------------------------------------------------------
    result = ScanResult(
        scan_id=scan_id,
        metadata=meta,
        purpose=purpose,
        purpose_compatibility=compat,
        findings=findings,
        risk=risk,
        recommendations=recommendations,
        rule_versions=kb.versions,
        scan_mode=scan_mode,
        scan_depth_used=depth,
        scan_started_at=datetime.fromtimestamp(started, timezone.utc).isoformat(),
        scan_finished_at=datetime.now(timezone.utc).isoformat(),
    )
    result.metadata.extraction_notes.append(f"Scan depth: {depth} — {depth_reason}")
    if environment:
        result.metadata.extraction_notes.append(
            f"Declared scan environment: {environment}"
        )
    return result


def _safe_unlink(path: str) -> None:
    try:
        if path and os.path.isfile(path) and not path.startswith("/System"):
            os.unlink(path)
    except OSError:
        pass


def save_upload(data: bytes, filename: str, dest_dir: Optional[str] = None) -> str:
    """Persist an upload to a private temp location and return its path."""
    from .security import sanitize_filename
    dest_dir = dest_dir or os.path.join(tempfile.gettempdir(), "permguard_uploads")
    os.makedirs(dest_dir, exist_ok=True)
    safe = sanitize_filename(filename)
    path = os.path.join(dest_dir, f"{uuid.uuid4().hex[:8]}_{safe}")
    with open(path, "wb") as fh:
        fh.write(data)
    return path
