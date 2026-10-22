"""Purpose analysis — does each permission fit the app's declared purpose?

The purpose comes from the user (category picker / description at upload) or
is inferred from package name, label and manifest signals. Purpose is NEVER
derived from the permission list itself (that would be circular reasoning).

Verdicts per permission:
    JUSTIFIED      expected for the declared category
    PLAUSIBLE      listed as optional/adjacent for the category
    UNEXPECTED     not needed by the declared category -> candidate for
                   "excessive permission" findings
    UNDETERMINED   no purpose available -> cannot judge necessity
"""
from __future__ import annotations

import re
from typing import Optional

from .knowledgebase import KnowledgeBase, all_categories, category_entry
from .models import (
    ApkMetadata,
    Permission,
    PurposeCompatibility,
    PurposeProfile,
    SensitivityTier,
    Severity,
)

# Verdict ordering used downstream
JUSTIFIED = "JUSTIFIED"
PLAUSIBLE = "PLAUSIBLE"
UNEXPECTED = "UNEXPECTED"
UNDETERMINED = "UNDETERMINED"


# ---------------------------------------------------------------------------
# purpose inference (used only to PRE-FILL the user's choice; the user must
# still confirm — inference never overrides an explicit selection)
# ---------------------------------------------------------------------------

def infer_category(meta: ApkMetadata, kb: KnowledgeBase) -> tuple[Optional[str], str, list[str]]:
    """Infer a likely category from non-permission signals.

    Returns (category_key_or_None, rationale, signals_used).
    Deliberately does NOT look at the permission list.
    """
    signals: list[str] = []
    haystack_parts: list[str] = []

    if meta.app_label:
        haystack_parts.append(meta.app_label)
        signals.append(f"label: {meta.app_label!r}")
    if meta.package_name:
        haystack_parts.append(meta.package_name.replace(".", " ").replace("_", " "))
        signals.append(f"package: {meta.package_name}")

    # launcher activity names carry category words
    for comp in meta.components:
        if comp.type == "activity" and comp.actions and any(
            a.endswith("MAIN") for a in comp.actions
        ):
            haystack_parts.append(comp.name or "")
    if meta.components:
        signals.append(f"{len(meta.components)} components inspected")

    haystack = " ".join(haystack_parts).lower()
    if not haystack.strip():
        return None, "No package name, label or components to infer from.", signals

    keywords = kb.categories.get("keywords", {}) if isinstance(kb.categories, dict) else {}
    best_key: Optional[str] = None
    best_score = 0
    for key, words in keywords.items():
        score = sum(1 for w in words if w and w in haystack)
        if score > best_score:
            best_score = score
            best_key = key

    if best_key and best_score >= 1:
        return (
            best_key,
            f"Category inferred from {len(signals)} metadata signal(s) "
            f"(matched '{best_key}'). CONFIRM or change it before analysis.",
            signals,
        )
    return (
        None,
        "No reliable category signal found — please select the app category.",
        signals,
    )


def build_purpose(
    category: Optional[str],
    app_name: Optional[str] = None,
    description: str = "",
    features: Optional[list[str]] = None,
    source: str = "user",
) -> PurposeProfile:
    return PurposeProfile(
        app_name=app_name,
        category=(category or "").lower() if (category or "").lower() != "auto" else None,
        description=description,
        features=list(features or []),
        source=source,
    )


# ---------------------------------------------------------------------------
# per-permission compatibility
# ---------------------------------------------------------------------------

def assess_compatibility(
    meta: ApkMetadata,
    purpose: Optional[PurposeProfile],
    kb: KnowledgeBase,
) -> list[PurposeCompatibility]:
    """Return one compatibility verdict per declared permission."""
    results: list[PurposeCompatibility] = []

    category = (purpose.category if purpose else None) or None
    entry = category_entry(kb, category) if category else None

    if not entry:
        # No usable purpose -> cannot judge necessity. Report honestly.
        for perm in meta.permissions:
            results.append(
                PurposeCompatibility(
                    permission=perm.name,
                    expected_for_purpose=False,
                    verdict=UNDETERMINED,
                    rationale=(
                        "No declared app purpose/category — necessity cannot "
                        "be determined from the manifest alone."
                    ),
                )
            )
        return results

    expected: set[str] = set(entry.get("expected_permissions", []))
    optional: set[str] = set(entry.get("optional_permissions", []))

    # user-declared expected access always counts as justified
    user_expected = set(purpose.expected_sensitive_access or [])

    for perm in meta.permissions:
        if perm.name in user_expected:
            results.append(
                PurposeCompatibility(
                    permission=perm.name,
                    expected_for_purpose=True,
                    verdict=JUSTIFIED,
                    rationale="Declared by the user as expected access for this app.",
                )
            )
            continue

        if perm.name in expected:
            results.append(
                PurposeCompatibility(
                    permission=perm.name,
                    expected_for_purpose=True,
                    verdict=JUSTIFIED,
                    rationale=(
                        f"Expected for category '{entry.get('label', category)}'. "
                        f"{entry.get('rationale', '')}"
                    ).strip(),
                )
            )
            continue

        if perm.name in optional:
            results.append(
                PurposeCompatibility(
                    permission=perm.name,
                    expected_for_purpose=True,
                    verdict=PLAUSIBLE,
                    rationale=(
                        f"Optional for this category — legitimate only if the "
                        f"feature is actually present (category note: "
                        f"{entry.get('rationale', '')})"
                    ).strip(),
                    alternative_available=_alt_for(perm),
                )
            )
            continue

        # unexpected
        if perm.sensitivity in (SensitivityTier.HIGH, SensitivityTier.CRITICAL):
            rationale = (
                f"Not required by '{entry.get('label', category)}' apps and "
                f"classified {perm.sensitivity.value} sensitivity "
                f"({perm.data_or_functionality or 'sensitive data'}). "
                f"Classic over-privilege for this category."
            )
        else:
            rationale = (
                f"Not part of the expected permission set for "
                f"'{entry.get('label', category)}'."
            )
            if perm.excess_conditions:
                rationale += f" Excess condition: {perm.excess_conditions[0]}"

        results.append(
            PurposeCompatibility(
                permission=perm.name,
                expected_for_purpose=False,
                verdict=UNEXPECTED,
                rationale=rationale,
                alternative_available=_alt_for(perm),
            )
        )
    return results


def _alt_for(perm: Permission) -> Optional[str]:
    return perm.alternatives[0] if perm.alternatives else None


# Shared correlation key: "this permission is unnecessary for the declared
# purpose" is ONE root cause. The purpose engine, OWASP-PRIV-001 and
# OWASP-PRIV-003 all describe it from different angles — the scoring engine
# counts it once (highest contribution wins) so frameworks never stack.
OVERPRIVILEGE_KEY = "root:purpose_overprivilege"


def tier_severity(tier: SensitivityTier, count: int) -> Severity:
    """Severity for a group of unexpected permissions.

    Widespread over-privilege (3+ critical-tier permissions) is CRITICAL;
    one or two high/critical permissions is HIGH (serious but not the worst
    case); moderate/low scale down accordingly.
    """
    if tier == SensitivityTier.CRITICAL and count >= 3:
        return Severity.CRITICAL
    if tier in (SensitivityTier.CRITICAL, SensitivityTier.HIGH):
        return Severity.HIGH
    if tier == SensitivityTier.MODERATE:
        return Severity.MEDIUM
    if tier == SensitivityTier.LOW:
        return Severity.LOW
    return Severity.INFO


def compatibility_map(results: list[PurposeCompatibility]) -> dict[str, str]:
    return {r.permission: r.verdict for r in results}


def expected_feature_hints(purpose: Optional[PurposeProfile], kb: KnowledgeBase) -> list[str]:
    if not purpose:
        return []
    entry = category_entry(kb, purpose.category or "")
    if not entry:
        return []
    return list(entry.get("suggested_features", []))


def category_label(kb: KnowledgeBase, key: Optional[str]) -> Optional[str]:
    entry = category_entry(kb, key or "")
    return entry.get("label") if entry else None


def list_categories(kb: KnowledgeBase) -> dict[str, str]:
    """Return {key: label} for the UI category picker."""
    out: dict[str, str] = {}
    for key, entry in all_categories(kb).items():
        if isinstance(entry, dict):
            out[key] = entry.get("label", key)
    return out
