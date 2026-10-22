"""OWASP-informed engine.

Runs application-specific rules INFORMED BY OWASP MASVS-PRIVACY / MASWE-0066
guidance. Rules are honestly labelled: they are NOT official OWASP automated
tests and NOT MASTG executions. Where a formal MASVS requirement applies it is
cited by ID in the finding.
"""
from __future__ import annotations

from typing import Optional

from .knowledgebase import KnowledgeBase
from .models import (
    AssessmentStatus,
    Confidence,
    Finding,
    Permission,
    PurposeProfile,
    SensitivityTier,
    Severity,
)
from .purposeanalyzer import (
    OVERPRIVILEGE_KEY,
    UNDETERMINED,
    UNEXPECTED,
    compatibility_map,
)

_FRAMEWORK = "owasp_informed"


def evaluate(
    kb: KnowledgeBase,
    meta,
    purpose: Optional[PurposeProfile],
    compat: list,
) -> list[Finding]:
    findings: list[Finding] = []
    rules = {r["rule_id"]: r for r in kb.owasp_rules.get("rules", [])}
    verdicts = compatibility_map(compat)
    purpose_known = bool(purpose and purpose.category)

    dangerous = [p for p in meta.permissions if p.sensitivity.value in ("HIGH", "CRITICAL", "MODERATE")]

    # OWASP-PRIV-001: excessive permissions beyond declared functionality
    rule = rules.get("OWASP-PRIV-001")
    if rule:
        unexpected = [
            p for p in meta.permissions
            if verdicts.get(p.name) == UNEXPECTED
        ]
        if purpose_known and unexpected:
            names = [p.name for p in unexpected]
            findings.append(Finding(
                finding_id="",
                rule_id="OWASP-PRIV-001",
                source_framework=_FRAMEWORK,
                title=rule["title"],
                description=rule["description"],
                affected_permissions=names,
                evidence=(
                    f"Compared {len(meta.permissions)} declared permissions against "
                    f"the expected set for category '{purpose.category}'. "
                    f"Unexpected: {', '.join(names[:8])}"
                    + (" (+{} more)".format(len(names) - 8) if len(names) > 8 else "")
                ),
                severity=Severity(rule.get("severity", "MEDIUM").upper()),
                confidence=Confidence(rule.get("confidence", "MEDIUM").upper()),
                assessment_status=AssessmentStatus.POTENTIAL_CONCERN,
                recommended_action=rule.get("remediation", ""),
                source_urls=[rule.get("source_url", "")],
                limitations=rule.get("limitations", ""),
                category="owasp",
                correlation_key=OVERPRIVILEGE_KEY,
            ))
        elif not purpose_known:
            findings.append(Finding(
                finding_id="",
                rule_id="OWASP-PRIV-001",
                source_framework=_FRAMEWORK,
                title=rule["title"],
                description=rule["description"],
                affected_permissions=[],
                evidence="No declared purpose — necessity check could not be run.",
                severity=Severity.LOW,
                confidence=Confidence.LOW,
                assessment_status=AssessmentStatus.INSUFFICIENT_EVIDENCE,
                recommended_action="Supply the app category/purpose to enable necessity checking.",
                source_urls=[rule.get("source_url", "")],
                limitations=rule.get("limitations", ""),
                category="owasp",
            ))

    # OWASP-PRIV-002: less-intrusive alternative exists
    rule = rules.get("OWASP-PRIV-002")
    if rule:
        candidates = [
            p for p in meta.permissions
            if p.alternatives and verdicts.get(p.name) in (UNEXPECTED, "PLAUSIBLE")
        ]
        if candidates:
            names = [p.name for p in candidates[:6]]
            alt = candidates[0].alternatives[0]
            findings.append(Finding(
                finding_id="",
                rule_id="OWASP-PRIV-002",
                source_framework=_FRAMEWORK,
                title=rule["title"],
                description=rule["description"],
                affected_permissions=names,
                evidence=(
                    f"Documented less-intrusive alternatives exist for: "
                    f"{', '.join(names)}. Example: {candidates[0].name} -> {alt}"
                ),
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                assessment_status=AssessmentStatus.POTENTIAL_CONCERN,
                recommended_action=(
                    f"Adopt documented alternative: {alt} "
                    "(see permission knowledge base for full list)."
                ),
                source_urls=[rule.get("source_url", "")],
                limitations=rule.get("limitations", ""),
                category="owasp",
                correlation_key="purpose:alternative_exists",
            ))

    # OWASP-PRIV-003: missing justification for sensitive access
    rule = rules.get("OWASP-PRIV-003")
    if rule:
        sensitive_unjustified = [
            p for p in meta.permissions
            if p.sensitivity in (SensitivityTier.HIGH, SensitivityTier.CRITICAL)
            and verdicts.get(p.name) in (UNEXPECTED, UNDETERMINED)
        ]
        if sensitive_unjustified:
            names = [p.name for p in sensitive_unjustified]
            is_fail_path = purpose_known
            findings.append(Finding(
                finding_id="",
                rule_id="OWASP-PRIV-003",
                source_framework=_FRAMEWORK,
                title=rule["title"],
                description=rule["description"],
                affected_permissions=names,
                evidence=(
                    "High/critical sensitivity permissions without a traceable "
                    "user benefit: " + ", ".join(names)
                ),
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM if is_fail_path else Confidence.LOW,
                assessment_status=(
                    AssessmentStatus.POTENTIAL_CONCERN if is_fail_path
                    else AssessmentStatus.INSUFFICIENT_EVIDENCE
                ),
                recommended_action=rule.get("remediation", ""),
                source_urls=[rule.get("source_url", "")],
                limitations=rule.get("limitations", ""),
                category="owasp",
                correlation_key=OVERPRIVILEGE_KEY,
            ))

    # OWASP-PRIV-004: compounding combinations (delegated to combination
    # detector; here we only record the framework linkage when >1 critical)
    rule = rules.get("OWASP-ARCH-001")
    if rule:
        findings.extend(_arch_checks(meta, rule))

    return findings


def _arch_checks(meta, rule) -> list[Finding]:
    out: list[Finding] = []
    checks = [
        ("debuggable", meta.debuggable, Severity.HIGH,
         "Application is debuggable — a debug build shipped as release exposes code to inspection and injection."),
        ("usesCleartextTraffic", meta.uses_cleartext_traffic, Severity.MEDIUM,
         "Cleartext network traffic is permitted — data may travel unencrypted."),
        ("sharedUserId", meta.shared_user_id, Severity.HIGH,
         "The app runs under a shared Linux UID — it can share data with other apps holding the same UID."),
        ("testOnly", meta.test_only, Severity.MEDIUM,
         "The app is flagged android:testOnly — test builds must never be distributed."),
    ]
    for attr, value, severity, text in checks:
        if value is True:
            out.append(Finding(
                finding_id="",
                rule_id="OWASP-ARCH-001",
                source_framework=_FRAMEWORK,
                title=rule["title"],
                description=rule["description"],
                affected_permissions=[],
                evidence=f"manifest android:{attr} = true. {text}",
                severity=severity,
                confidence=Confidence.HIGH,
                assessment_status=AssessmentStatus.POTENTIAL_CONCERN,
                recommended_action=rule.get("remediation", ""),
                source_urls=[rule.get("source_url", "")],
                limitations=rule.get("limitations", ""),
                category="owasp",
                correlation_key=f"arch:{attr}",
            ))
    # allowBackup: informational (default true on Android)
    if meta.allow_backup is True:
        out.append(Finding(
            finding_id="",
            rule_id="OWASP-ARCH-001",
            source_framework=_FRAMEWORK,
            title=rule["title"],
            description=rule["description"],
            affected_permissions=[],
            evidence=("manifest android:allowBackup = true (default). App data "
                      "may be retrievable via adb backup on older devices."),
            severity=Severity.LOW,
            confidence=Confidence.MEDIUM,
            assessment_status=AssessmentStatus.POTENTIAL_CONCERN,
            recommended_action="Restrict backups with a backup rules file, or disable allowBackup for sensitive apps.",
            source_urls=[rule.get("source_url", "")],
            limitations=rule.get("limitations", ""),
            category="owasp",
            correlation_key="arch:allowBackup",
        ))
    return out
