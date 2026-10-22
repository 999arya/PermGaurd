"""Deterministic risk-scoring engine (0-100).

Design guarantees (all tested):
  * TRANSPARENT  — every point is recorded in a breakdown with a reason
  * NO DOUBLE COUNTING — findings sharing a correlation_key contribute once
  * ANTI-BURYING — a CRITICAL finding forces at least the MEDIUM/HIGH band
  * CONFIGURABLE — weights & thresholds live in config/riskthresholds.yaml
  * HONEST — the score is a relative risk indicator, NOT a probability of
    malware and NOT an official compliance rating

Inputs: permission sensitivity baseline + weighted findings (severity x
confidence) across all engines, adjusted for available evidence.
"""
from __future__ import annotations

from typing import Optional

from .knowledgebase import KnowledgeBase
from .models import (
    AssessmentStatus,
    Confidence,
    Finding,
    PurposeCompatibility,
    RiskLevel,
    RiskReport,
    ScoreContribution,
    SensitivityTier,
    Severity,
)

_LEVEL_SCORE_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM,
                      Severity.HIGH, Severity.CRITICAL]

# statuses that should not consume score (they record absence of evidence)
_NON_SCORING = {
    AssessmentStatus.PASS,
    AssessmentStatus.NOT_APPLICABLE,
    AssessmentStatus.INSUFFICIENT_EVIDENCE,
}

_METHOD = (
    "Weighted accumulation: a sensitivity baseline (capped) plus one "
    "contribution per unique finding = severity weight x confidence "
    "multiplier. Contributions sharing a correlation key are counted once "
    "(highest wins). Score floors ensure a CRITICAL finding can never "
    "produce a LOW rating. Weights/thresholds are configurable in "
    "config/riskthresholds.yaml."
)


def score(
    kb: KnowledgeBase,
    findings: list[Finding],
    metadata,
    compat: list[PurposeCompatibility],
) -> RiskReport:
    cfg = kb.riskconfig or {}
    thresholds = cfg.get("thresholds", {}) or {}
    sev_weights: dict = cfg.get("severity_weights", {}) or {}
    conf_mult: dict = cfg.get("confidence_multiplier", {}) or {}
    baseline_cfg: dict = cfg.get("sensitivity_baseline", {}) or {}
    floors: dict = cfg.get("floors", {}) or {}

    low_max = float(thresholds.get("low_max", 29))
    medium_max = float(thresholds.get("medium_max", 59))

    breakdown: list[ScoreContribution] = []
    total = 0.0

    # ---- 1. sensitivity baseline (raw exposure) -------------------------
    baseline_cap = float(baseline_cfg.get("baseline_cap", 15.0))
    baseline_total = 0.0
    for perm in metadata.permissions:
        weight = float(baseline_cfg.get(perm.sensitivity.value, 0.0))
        if weight:
            baseline_total += weight
    baseline_applied = min(baseline_total, baseline_cap)
    if baseline_applied > 0:
        breakdown.append(ScoreContribution(
            finding_id="BASELINE",
            rule_id="SCORE-BASELINE",
            label="Permission sensitivity baseline",
            raw_points=round(baseline_total, 2),
            applied_points=round(baseline_applied, 2),
            severity=Severity.INFO,
            reason=(
                f"Sum of sensitivity weights for {len(metadata.permissions)} "
                f"declared permission(s), capped at {baseline_cap}."
            ),
        ))
        total += baseline_applied

    # ---- 2. finding contributions, deduplicated -------------------------
    dedup_enabled = bool((cfg.get("deduplication") or {}).get("enabled", True))
    best_by_key: dict[str, ScoreContribution] = {}
    plain_contribs: list[ScoreContribution] = []
    deduped_ids: list[str] = []

    for f in findings:
        if f.assessment_status in _NON_SCORING:
            continue
        raw_weight = float(sev_weights.get(f.severity.value, 0.0))
        if raw_weight <= 0:
            continue
        mult = float(conf_mult.get(f.confidence.value, 0.75))
        points = raw_weight * mult

        key = f.correlation_key or f"__unique__:{f.finding_id}"
        if dedup_enabled and f.correlation_key:
            existing = best_by_key.get(key)
            if existing is None:
                best_by_key[key] = ScoreContribution(
                    finding_id=f.finding_id,
                    rule_id=f.rule_id,
                    label=f.title,
                    raw_points=round(points, 2),
                    applied_points=round(points, 2),
                    severity=f.severity,
                    reason=(
                        f"{f.severity.value} severity x {f.confidence.value} "
                        f"confidence ({mult}); status {f.assessment_status.value}."
                    ),
                )
            else:
                # keep the higher contribution, record the duplicate
                if points > existing.applied_points:
                    deduped_ids.append(existing.label)
                    best_by_key[key] = ScoreContribution(
                        finding_id=f.finding_id,
                        rule_id=f.rule_id,
                        label=f.title,
                        raw_points=round(points, 2),
                        applied_points=round(points, 2),
                        severity=f.severity,
                        reason=(
                            f"{f.severity.value} x {f.confidence.value} "
                            f"(supersedes a correlated lower-weight finding)."
                        ),
                    )
                else:
                    deduped_ids.append(f.title)
        else:
            plain_contribs.append(ScoreContribution(
                finding_id=f.finding_id,
                rule_id=f.rule_id,
                label=f.title,
                raw_points=round(points, 2),
                applied_points=round(points, 2),
                severity=f.severity,
                reason=(
                    f"{f.severity.value} severity x {f.confidence.value} "
                    f"confidence ({mult}); status {f.assessment_status.value}."
                ),
            ))

    deduped = list(best_by_key.values()) + plain_contribs
    for contrib in deduped:
        breakdown.append(contrib)
        total += contrib.applied_points

    # ---- 3. clamp ------------------------------------------------------
    raw_total = total
    score_val = max(0.0, min(100.0, total))

    # ---- 4. floors (anti-burying) --------------------------------------
    capped_notes: list[str] = []
    severities_present = {
        f.severity for f in findings
        if f.assessment_status not in _NON_SCORING
    }
    crit_min = float(floors.get("critical_finding_min_score", 60.0))
    high_min = float(floors.get("high_finding_min_score", 30.0))

    if Severity.CRITICAL in severities_present and score_val < crit_min:
        capped_notes.append(
            f"Raised from {score_val:.0f} to {crit_min:.0f}: at least one "
            "CRITICAL finding must never classify as LOW."
        )
        score_val = crit_min
    elif Severity.HIGH in severities_present and score_val < high_min:
        capped_notes.append(
            f"Raised from {score_val:.0f} to {high_min:.0f}: at least one "
            "HIGH finding must never classify as LOW."
        )
        score_val = high_min

    score_val = max(0.0, min(100.0, score_val))

    # ---- 5. classify ---------------------------------------------------
    if score_val <= low_max:
        level = RiskLevel.LOW
    elif score_val <= medium_max:
        level = RiskLevel.MEDIUM
    else:
        level = RiskLevel.HIGH

    # ---- 6. explanation ------------------------------------------------
    explanation = _explain(score_val, level, findings, breakdown, capped_notes,
                           metadata, compat)

    return RiskReport(
        score=round(score_val, 1),
        level=level,
        breakdown=sorted(breakdown, key=lambda c: -c.applied_points),
        explanation=explanation,
        capped_findings=capped_notes,
        deduplicated_findings=sorted(set(deduped_ids))[:20],
        method=_METHOD,
        thresholds={"low_max": low_max, "medium_max": medium_max,
                    "raw_total": round(raw_total, 1)},
    )


def _explain(score_val, level, findings, breakdown, capped_notes, metadata,
             compat) -> str:
    scoring = [f for f in findings if f.assessment_status not in _NON_SCORING]
    parts: list[str] = []

    parts.append(
        f"Overall risk score {score_val:.0f}/100 ({level.value}). "
        f"{len(scoring)} scored finding(s) across "
        f"{len(metadata.permissions)} declared permission(s)."
    )

    top = [b for b in breakdown if b.applied_points > 0][:3]
    if top:
        contrib = "; ".join(
            f"'{b.label}' (+{b.applied_points:.1f})" for b in top
        )
        parts.append(f"Largest contributions: {contrib}.")

    # counts by severity
    counts: dict[str, int] = {}
    for f in scoring:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    if counts:
        order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        seg = ", ".join(f"{counts[s]} {s.lower()}" for s in order if s in counts)
        parts.append(f"Findings by severity: {seg}.")

    # purpose context
    unexpected = [c for c in compat if c.verdict == "UNEXPECTED"]
    if unexpected:
        parts.append(
            f"{len(unexpected)} permission(s) are not required by the declared "
            "purpose (over-privilege)."
        )

    if capped_notes:
        parts.append("Score floor applied: " + " ".join(capped_notes))

    parts.append(
        "The score is a relative risk indicator for prioritising review — it "
        "is not a probability of malware and not an official compliance rating."
    )
    return " ".join(parts)
