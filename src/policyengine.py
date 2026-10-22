"""Google Play policy engine.

Evaluates versioned policy rules (knowledgebase/googleplayrules.json) against
extracted APK metadata.

Status discipline (important for grading credibility):
  * A permission appearing in the manifest NEVER alone produces FAIL.
  * Checks needing evidence outside the APK return NEEDS_REVIEW or
    INSUFFICIENT_EVIDENCE.
  * FAIL is used only when the purpose is known and the rule's exact failure
    condition is satisfied.
"""
from __future__ import annotations

from typing import Any, Optional

from .knowledgebase import KnowledgeBase
from .models import (
    AssessmentStatus,
    Confidence,
    Finding,
    PurposeProfile,
    Severity,
)
from .purposeanalyzer import UNEXPECTED, compatibility_map

_FRAMEWORK = "google_play"


def _mk(rule: dict[str, Any], **kwargs) -> Finding:
    defaults = dict(
        finding_id="",
        rule_id=rule["rule_id"],
        source_framework=_FRAMEWORK,
        title=rule.get("title", rule["rule_id"]),
        description=rule.get("description", ""),
        evidence="",
        severity=Severity(rule.get("severity", "MEDIUM").upper()),
        confidence=Confidence.MEDIUM,
        assessment_status=AssessmentStatus.NEEDS_REVIEW,
        recommended_action=rule.get("remediation", ""),
        source_urls=[rule.get("source_url", "")] if rule.get("source_url") else [],
        limitations=rule.get("limitations", ""),
        category="policy",
        correlation_key=None,
    )
    defaults.update(kwargs)
    return Finding(**defaults)


def _triggered(rule: dict[str, Any], perm_names: set[str]) -> list[str]:
    """Return the triggering permissions for a rule."""
    hits: list[str] = []
    for cond in rule.get("trigger_conditions", []):
        if isinstance(cond, str) and cond.startswith("permission:"):
            name = cond.split(":", 1)[1]
            if name in perm_names:
                hits.append(name)
    return hits


def evaluate(
    kb: KnowledgeBase,
    meta,
    purpose: Optional[PurposeProfile],
    compat: list,
) -> list[Finding]:
    findings: list[Finding] = []
    rules = kb.play_rules.get("rules", []) if isinstance(kb.play_rules, dict) else []
    perm_names = {p.name for p in meta.permissions}
    verdicts = compatibility_map(compat)
    purpose_known = bool(purpose and purpose.category)
    category = (purpose.category if purpose else None) or ""

    for rule in rules:
        rid = rule.get("rule_id", "")
        # generic necessity rule handled by purpose engine + OWASP-PRIV-001
        if rid == "GP-PERM-001":
            continue

        hits = _triggered(rule, perm_names)
        if not hits and not rule.get("trigger_conditions"):
            continue
        if not hits:
            # rule not triggered by this app
            continue

        evidence = "Declared permissions: " + ", ".join(hits)

        if rid == "GP-LOC-001":
            findings.append(_evaluate_background_location(rule, hits, purpose_known, evidence))
        elif rid == "GP-SMS-001":
            findings.append(_evaluate_sms(rule, hits, purpose_known, category, evidence))
        elif rid == "GP-PHOTO-001":
            findings.append(_evaluate_media(rule, hits, purpose_known, category, evidence))
        elif rid == "GP-PKG-001":
            findings.append(_evaluate_query_all(rule, hits, purpose_known, category, evidence))
        elif rid == "GP-BG-001":
            findings.append(_evaluate_background(rule, hits, purpose_known, evidence))
        elif rid in ("GP-DISC-001", "GP-CHILD-001"):
            # disclosure/target-audience evidence lives outside the APK
            findings.append(_mk(
                rule,
                evidence=evidence + " (disclosure/declaration evidence is not in the APK)",
                assessment_status=AssessmentStatus.NEEDS_REVIEW,
                confidence=Confidence.MEDIUM,
            ))
        else:
            findings.append(_mk(
                rule,
                evidence=evidence,
                assessment_status=AssessmentStatus.NEEDS_REVIEW,
            ))

    return [f for f in findings if f is not None]


def _evaluate_background_location(rule, hits, purpose_known, evidence) -> Finding:
    if not purpose_known:
        return _mk(
            rule,
            evidence=evidence,
            assessment_status=AssessmentStatus.INSUFFICIENT_EVIDENCE,
            confidence=Confidence.HIGH,
        )
    # purpose known — purpose engine decides if a location feature exists
    # (handled through compat verdicts; here we escalate for manual review)
    return _mk(
        rule,
        evidence=evidence,
        assessment_status=AssessmentStatus.NEEDS_REVIEW,
        confidence=Confidence.HIGH,
        description=rule.get("description", "") + (
            " Background location is declared. Confirm the app has a "
            "core feature that requires location while not in use, and that "
            "a prominent in-app disclosure is shown before the system dialog."
        ),
    )


def _evaluate_sms(rule, hits, purpose_known, category, evidence) -> Finding:
    communicational = {"messaging", "dialer", "banking", "email"}
    if purpose_known and category not in communicational:
        return _mk(
            rule,
            evidence=evidence + f"; declared category '{category}' has no SMS/call-log core function",
            assessment_status=AssessmentStatus.FAIL,
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            description=rule.get("description", "") + (
                f" The declared purpose ('{category}') does not require "
                "SMS or call-log access, so the rule's failure condition is "
                "met for this evidence set."
            ),
            limitations=(
                "Judgement is based on the user-declared category. If the "
                "category was declared incorrectly, this status may change."
            ),
        )
    if purpose_known:
        return _mk(
            rule,
            evidence=evidence + f"; declared category '{category}'",
            assessment_status=AssessmentStatus.NEEDS_REVIEW,
            confidence=Confidence.MEDIUM,
        )
    return _mk(
        rule,
        evidence=evidence,
        assessment_status=AssessmentStatus.INSUFFICIENT_EVIDENCE,
        confidence=Confidence.HIGH,
    )


def _evaluate_media(rule, hits, purpose_known, category, evidence) -> Finding:
    narrow_ok = {"file_manager", "backup", "security"}
    if purpose_known and category in narrow_ok:
        return _mk(
            rule,
            evidence=evidence + f"; declared category '{category}' may legitimately need broad access",
            assessment_status=AssessmentStatus.NEEDS_REVIEW,
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
        )
    if purpose_known:
        return _mk(
            rule,
            evidence=evidence + f"; declared category '{category}'",
            assessment_status=AssessmentStatus.POTENTIAL_CONCERN,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
        )
    return _mk(
        rule,
        evidence=evidence,
        assessment_status=AssessmentStatus.NEEDS_REVIEW,
        confidence=Confidence.HIGH,
    )


def _evaluate_query_all(rule, hits, purpose_known, category, evidence) -> Finding:
    narrow_ok = {"security", "file_manager", "enterprise", "productivity"}
    if purpose_known and category not in narrow_ok:
        return _mk(
            rule,
            evidence=evidence + f"; declared category '{category}' does not need full package visibility",
            assessment_status=AssessmentStatus.POTENTIAL_CONCERN,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
        )
    if purpose_known:
        return _mk(
            rule,
            evidence=evidence + f"; declared category '{category}' (declaration still required)",
            assessment_status=AssessmentStatus.NEEDS_REVIEW,
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
        )
    return _mk(
        rule,
        evidence=evidence,
        assessment_status=AssessmentStatus.NEEDS_REVIEW,
        confidence=Confidence.HIGH,
    )


def _evaluate_background(rule, hits, purpose_known, evidence) -> Finding:
    if not purpose_known:
        return _mk(
            rule,
            evidence=evidence,
            assessment_status=AssessmentStatus.INSUFFICIENT_EVIDENCE,
        )
    return _mk(
        rule,
        evidence=evidence + "; purpose known — verify the background feature is genuine",
        assessment_status=AssessmentStatus.NEEDS_REVIEW,
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
    )
