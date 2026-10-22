"""Suspicious permission-combination detector.

Flags co-occurrence patterns that deserve human review. These are INDICATORS
FOR FURTHER REVIEW — never proof of malware, surveillance or exfiltration.
Every finding lists what legitimate features could justify the combination
and what additional evidence would resolve it.
"""
from __future__ import annotations

from typing import Optional

from .knowledgebase import KnowledgeBase
from .models import (
    AssessmentStatus,
    Confidence,
    Finding,
    PurposeProfile,
    Severity,
)
from .purposeanalyzer import compatibility_map

_FRAMEWORK = "combination"
_SEV = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


def evaluate(kb: KnowledgeBase, meta, purpose: Optional[PurposeProfile]) -> list[Finding]:
    findings: list[Finding] = []
    combos = kb.combinations.get("combinations", []) if isinstance(kb.combinations, dict) else []
    declared = {p.name for p in meta.permissions}
    category = (purpose.category if purpose else None) or ""

    for rule in combos:
        rid = rule.get("rule_id", "COMBO-UNKNOWN")
        primary = [p for p in rule.get("permissions", []) if p in declared]
        if not primary:
            continue

        mode = rule.get("match_mode", "all")
        co = [p for p in rule.get("co_occurrence_any_of", []) if p in declared]

        triggered = False
        matched = list(primary)

        if mode == "all":
            if len(primary) == len(rule.get("permissions", [])) and primary:
                triggered = True
        elif mode == "one_plus_any":
            if primary and co:
                triggered = True
                matched = primary + co
        elif mode == "two_plus_of":
            if len(primary) >= 2:
                triggered = True
        else:
            triggered = bool(primary)

        if not triggered:
            continue

        # If the category legitimately expects this combo, downgrade rather
        # than drop — still visible, but not scored as strongly.
        expected_cats = rule.get("expected_categories", []) or []
        is_expected = category in expected_cats
        severity = _SEV.get(str(rule.get("severity", "MEDIUM")).upper(), Severity.MEDIUM)
        if is_expected:
            severity = Severity.MEDIUM if severity in (Severity.CRITICAL, Severity.HIGH) else Severity.LOW

        legit = rule.get("legitimate_justifiers", []) or []
        evidence_needed = rule.get("additional_evidence", "")

        if is_expected:
            status = AssessmentStatus.NEEDS_REVIEW
            confidence = Confidence.HIGH
            intro = (f"The combination is plausible for '{category}' apps but "
                     "still requires confirmation that the feature exists.")
        else:
            status = AssessmentStatus.POTENTIAL_CONCERN
            confidence = Confidence.MEDIUM
            intro = "This combination is an indicator for further review — not proof of malicious behaviour."

        findings.append(Finding(
            finding_id="",
            rule_id=rid,
            source_framework=_FRAMEWORK,
            title=rule.get("title", rid),
            description=(
                f"{intro} {rule.get('rationale', '')}\n\n"
                f"Why it deserves investigation: the permissions together "
                "expand what the app could collect beyond any single permission's "
                "stated purpose."
            ),
            affected_permissions=sorted(matched),
            evidence="Co-declared permissions: " + ", ".join(sorted(matched)),
            severity=severity,
            confidence=confidence,
            assessment_status=status,
            recommended_action=(
                rule.get("remediation", "")
                + ("\nLegitimate justifiers: " + "; ".join(legit) if legit else "")
                + (f"\nEvidence that would resolve this: {evidence_needed}" if evidence_needed else "")
            ).strip(),
            source_urls=["https://mas.owasp.org/MASVS/MASVS-PRIVACY/"],
            limitations=(
                "Combination findings are indicators for review. Co-occurrence "
                "in a manifest does not demonstrate that data flows between "
                "the permissions at runtime."
            ),
            category="combination",
            correlation_key=f"combo:{rid}",
        ))

    # generic: any two CRITICAL-sensitivity permissions together
    critical = [p.name for p in meta.permissions if p.sensitivity.value == "CRITICAL"]
    if len(critical) >= 2:
        findings.append(Finding(
            finding_id="",
            rule_id="COMBO-GEN-CRIT-001",
            source_framework=_FRAMEWORK,
            title="Multiple critical-sensitivity permissions in one app",
            description=(
                "Two or more permissions classified CRITICAL (highest privacy "
                "impact) are declared together. This multiplies the app's "
                "potential data-collection capability and deserves review."
            ),
            affected_permissions=sorted(critical),
            evidence="CRITICAL permissions: " + ", ".join(sorted(critical)),
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            assessment_status=AssessmentStatus.POTENTIAL_CONCERN,
            recommended_action=(
                "Confirm each critical permission maps to an advertised "
                "feature; remove the least-justified one first."
            ),
            source_urls=["https://mas.owasp.org/MASVS/MASVS-PRIVACY/"],
            limitations="Indicator only — not proof of data collection.",
            category="combination",
            correlation_key="combo:critical_cluster",
        ))

    return findings
