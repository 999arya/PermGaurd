"""Recommendation engine — converts findings into prioritised actions.

Produces remediation items ordered by (severity, effort) so the user sees
the highest-impact fix first. Each recommendation states:
  * what to do (revoke / restrict / review / replace)
  * the less-intrusive alternative where one exists
  * the findings it resolves
"""
from __future__ import annotations

from typing import Any, Optional

from .knowledgebase import KnowledgeBase
from .models import (
    AssessmentStatus,
    Finding,
    PurposeCompatibility,
    Severity,
)

_ACTION_RANK = {
    "REVOKE": 0,
    "RESTRICT": 1,
    "REPLACE": 2,
    "REVIEW": 3,
    "DOCUMENT": 4,
}
_SEV_RANK = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def _action_for(f: Finding, compat_map: dict[str, str]) -> tuple[str, str]:
    """Decide (action_code, headline) for a finding."""
    cat = f.category
    rid = f.rule_id

    if rid in ("ESC-DEBUG-001",) or (cat == "org_policy" and f.assessment_status == AssessmentStatus.FAIL):
        return "REVOKE", "Remove the flagged permission/setting from the manifest"

    if rid in ("ESC-CUSTOMPERM-001",):
        return "REPLACE", "Upgrade the custom permission to signature protection level"

    if cat == "purpose" and f.affected_permissions:
        # unexpected permission for the declared purpose
        if f.recommended_action:
            return "REVOKE", "Remove the permission not required by the app's purpose"
        return "REVOKE", "Remove the unnecessary permission"

    if cat == "combination":
        return "REVIEW", f"Review the combination: {f.title}"

    if cat in ("escalation", "kernel_root"):
        return "REVIEW", f"Security review: {f.title}"

    if cat == "org_policy":
        status = f.assessment_status
        if status == AssessmentStatus.FAIL:
            return "REVOKE", "Remove the permission violating organisational policy"
        if status == AssessmentStatus.NEEDS_REVIEW:
            return "DOCUMENT", "Document justification for policy-listed permission"
        return "RESTRICT", "Restrict or remove the permission breaching org policy"

    if cat == "policy":
        return "DOCUMENT", "Prepare policy declaration / disclosure evidence"

    if rid.startswith("OWASP-PRIV-002"):
        return "REPLACE", "Switch to the less-intrusive alternative"

    if rid.startswith("OWASP"):
        return "REVIEW", f"Address: {f.title}"

    return "REVIEW", f"Review: {f.title}"


def build(
    kb: KnowledgeBase,
    findings: list[Finding],
    compat: list[PurposeCompatibility],
    metadata,
    risk_score: float,
) -> list[dict[str, Any]]:
    compat_map = {c.permission: c.verdict for c in compat}
    actionable = [
        f for f in findings
        if f.assessment_status not in (
            AssessmentStatus.PASS,
            AssessmentStatus.NOT_APPLICABLE,
            AssessmentStatus.INSUFFICIENT_EVIDENCE,
        )
    ]

    seen: set[str] = set()
    recs: list[dict[str, Any]] = []

    for f in actionable:
        action, headline = _action_for(f, compat_map)
        key = f"{action}:{f.rule_id}:{','.join(sorted(f.affected_permissions))}"
        if key in seen:
            continue
        seen.add(key)

        alt = _alternatives_for(f, kb, metadata)
        recs.append({
            "action": action,
            "priority": _SEV_RANK.get(f.severity, 4) * 10 + _ACTION_RANK.get(action, 3),
            "severity": f.severity.value,
            "title": headline,
            "detail": f.recommended_action or f.description,
            "alternatives": alt,
            "affected_permissions": f.affected_permissions,
            "finding_ref": {
                "rule_id": f.rule_id,
                "source_framework": f.source_framework,
                "status": f.assessment_status.value,
            },
            "resolves": f.finding_id or f.rule_id,
        })

    # manual-review requirements
    needs_review = [f for f in actionable
                    if f.assessment_status == AssessmentStatus.NEEDS_REVIEW]
    if needs_review:
        recs.append({
            "action": "REVIEW",
            "priority": 95,
            "severity": "INFO",
            "title": f"Manual evidence review required for {len(needs_review)} check(s)",
            "detail": (
                "These checks depend on evidence that is not present in the APK "
                "(Play Store listing, Data Safety form, in-app disclosures, "
                "runtime behaviour): "
                + "; ".join(sorted({f.rule_id for f in needs_review}))
            ),
            "alternatives": [],
            "affected_permissions": [],
            "finding_ref": {"rule_id": "MULTIPLE", "source_framework": "mixed",
                            "status": "NEEDS_REVIEW"},
            "resolves": "",
        })

    recs.sort(key=lambda r: r["priority"])
    for i, r in enumerate(recs, 1):
        r["order"] = i
    return recs


def _alternatives_for(f: Finding, kb: KnowledgeBase, metadata) -> list[str]:
    out: list[str] = []
    for name in f.affected_permissions:
        for p in metadata.permissions:
            if p.name == name and p.alternatives:
                out.extend(a for a in p.alternatives if a not in out)
    return out[:5]
