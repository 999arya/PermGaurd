"""Organisational policy engine.

Evaluates the app against the editable organisation policy in
config/orgpolicy.yaml (deny-lists, review-lists, category allow-lists,
denied combinations, sensitivity caps).

Flags permissions that exceed a configurable organisational policy.
Findings are tagged source_framework:
"org_policy" so they remain clearly separate from Google Play and OWASP
results.
"""
from __future__ import annotations

from typing import Optional

from .knowledgebase import KnowledgeBase
from .models import (
    AssessmentStatus,
    Confidence,
    Finding,
    PurposeProfile,
    SensitivityTier,
    Severity,
)
from .purposeanalyzer import compatibility_map

_FRAMEWORK = "org_policy"
_TIER_ORDER = ["NONE", "LOW", "MODERATE", "HIGH", "CRITICAL"]


def _enabled(kb: KnowledgeBase) -> bool:
    policy = kb.orgpolicy if isinstance(kb.orgpolicy, dict) else {}
    if not policy.get("enabled", False):
        return False
    return bool(policy.get("policy"))


def evaluate(
    kb: KnowledgeBase,
    meta,
    purpose: Optional[PurposeProfile],
    compat: list,
) -> list[Finding]:
    if not _enabled(kb):
        return []

    policy = kb.orgpolicy.get("policy", {})
    findings: list[Finding] = []
    perms = {p.name: p for p in meta.permissions}
    perm_names = set(perms)
    verdicts = compatibility_map(compat)
    category = (purpose.category if purpose else None) or ""

    # ---- 1. deny-list ---------------------------------------------------
    denied = set(policy.get("denied_permissions", []))
    denied_hits = sorted(perm_names & denied)
    if denied_hits:
        findings.append(Finding(
            finding_id="",
            rule_id="ORG-DENY-001",
            source_framework=_FRAMEWORK,
            title="Permission banned by organisational policy",
            description=(
                f"Policy '{policy.get('name', 'org')}' bans these permissions "
                "outright — any presence is a violation regardless of app purpose."
            ),
            affected_permissions=denied_hits,
            evidence="Denied by org policy but declared: " + ", ".join(denied_hits),
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            assessment_status=AssessmentStatus.FAIL,
            recommended_action=(
                "Remove the banned permission(s) from the manifest, or file "
                "an exception request with your security team."
            ),
            source_urls=[],
            limitations="Based on the organisation's own configured policy file.",
            category="org_policy",
            correlation_key="org:denied_permissions",
        ))

    # ---- 2. review-list -------------------------------------------------
    review = set(policy.get("review_permissions", []))
    review_hits = sorted(perm_names & review)
    if review_hits:
        findings.append(Finding(
            finding_id="",
            rule_id="ORG-REVIEW-001",
            source_framework=_FRAMEWORK,
            title="Permission requires organisational review",
            description=(
                "These permissions are on the organisation's mandatory-review "
                "list and require documented justification before release."
            ),
            affected_permissions=review_hits,
            evidence="On org review list: " + ", ".join(review_hits),
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            assessment_status=AssessmentStatus.NEEDS_REVIEW,
            recommended_action=(
                "Document the business justification for each permission and "
                "have it approved by the policy owner."
            ),
            source_urls=[],
            limitations="Review outcome depends on evidence outside the APK.",
            category="org_policy",
            correlation_key="org:review_permissions",
        ))

    # ---- 3. category allow-lists ---------------------------------------
    allowed_by_cat: Optional[set[str]] = None
    cat_map = policy.get("category_allowed_permissions", {}) or {}
    if category and isinstance(cat_map, dict) and category in cat_map:
        allowed_by_cat = set(cat_map.get(category) or [])
        # an empty list means "no permissions permitted beyond the platform
        # defaults" -> flag only sensitive ones
        unexpected = []
        for p in meta.permissions:
            if p.name in allowed_by_cat:
                continue
            if p.sensitivity in (SensitivityTier.MODERATE, SensitivityTier.HIGH, SensitivityTier.CRITICAL):
                unexpected.append(p.name)
        if unexpected:
            unexpected.sort()
            findings.append(Finding(
                finding_id="",
                rule_id="ORG-CAT-001",
                source_framework=_FRAMEWORK,
                title="Permission outside the organisation's allow-list for this app category",
                description=(
                    f"Organisation policy defines an allow-list for "
                    f"'{category}' apps. These permissions fall outside it."
                ),
                affected_permissions=unexpected,
                evidence=(
                    f"Allowed: {sorted(allowed_by_cat) or '[]'}; "
                    f"outside allow-list: {', '.join(unexpected)}"
                ),
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                assessment_status=AssessmentStatus.POTENTIAL_CONCERN,
                recommended_action=(
                    "Remove the permissions, or ask the policy owner to extend "
                    "the category allow-list if the feature is genuinely needed."
                ),
                source_urls=[],
                limitations="Depends on the org's configured allow-list being current.",
                category="org_policy",
                correlation_key="org:category_allowlist",
            ))

    # ---- 4. sensitivity cap --------------------------------------------
    cap = str(policy.get("max_sensitivity_tier", "CRITICAL")).upper()
    if cap in _TIER_ORDER:
        cap_idx = _TIER_ORDER.index(cap)
        over = [p.name for p in meta.permissions
                if p.name in perms and p.sensitivity.value in _TIER_ORDER
                and _TIER_ORDER.index(p.sensitivity.value) > cap_idx]
        # ignore expected-for-category ones unless they exceed the cap anyway
        if over:
            over.sort()
            findings.append(Finding(
                finding_id="",
                rule_id="ORG-CAP-001",
                source_framework=_FRAMEWORK,
                title="Sensitivity exceeds the organisation's maximum tier",
                description=(
                    f"Organisation allows up to '{cap}' sensitivity; these "
                    "permissions rank higher."
                ),
                affected_permissions=over,
                evidence=f"Cap: {cap}; over-cap permissions: {', '.join(over)}",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                assessment_status=AssessmentStatus.POTENTIAL_CONCERN,
                recommended_action="Request a policy exception or remove/replace the over-cap permission.",
                source_urls=[],
                limitations="Sensitivity tiers are PermissionGuard classifications.",
                category="org_policy",
                correlation_key="org:sensitivity_cap",
            ))

    # ---- 5. denied combinations ----------------------------------------
    combo_rules = policy.get("denied_combinations", []) or []
    for i, combo in enumerate(combo_rules, 1):
        if not isinstance(combo, (list, tuple)):
            continue
        members = [c for c in combo if c in perm_names]
        if len(members) >= 2:
            findings.append(Finding(
                finding_id="",
                rule_id=f"ORG-COMBO-{i:03d}",
                source_framework=_FRAMEWORK,
                title="Permission combination blocked by organisational policy",
                description=(
                    "The organisation forbids this permission combination "
                    "without a documented exception."
                ),
                affected_permissions=sorted(members),
                evidence="Co-occurring in manifest: " + ", ".join(sorted(members)),
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                assessment_status=AssessmentStatus.FAIL,
                recommended_action="Remove one permission of the pair, or obtain a documented exception.",
                source_urls=[],
                limitations="Combination presence does not prove data flows between them.",
                category="org_policy",
                correlation_key=f"org:combo:{i}",
            ))

    # ---- 6. background location policy ----------------------------------
    if policy.get("allow_background_location") is False \
            and "android.permission.ACCESS_BACKGROUND_LOCATION" in perm_names:
        findings.append(Finding(
            finding_id="",
            rule_id="ORG-BG-001",
            source_framework=_FRAMEWORK,
            title="Background location forbidden by organisational policy",
            description="Organisation policy sets allow_background_location: false.",
            affected_permissions=["android.permission.ACCESS_BACKGROUND_LOCATION"],
            evidence="ACCESS_BACKGROUND_LOCATION declared while policy forbids it.",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            assessment_status=AssessmentStatus.FAIL,
            recommended_action="Remove ACCESS_BACKGROUND_LOCATION; use foreground-only or geofencing.",
            source_urls=[],
            limitations="Violation is judged against the organisation's own configured policy, not a platform rule.",
            category="org_policy",
            correlation_key="org:bg_location",
        ))

    return findings
