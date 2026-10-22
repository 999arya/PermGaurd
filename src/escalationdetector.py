"""Privilege-escalation surface detector (static, manifest-based).

Identifies manifest configurations that an attacker could abuse to gain
capabilities the app's users did not intend to grant — exported components
without permission gates, shared UIDs, weak custom permissions, debuggable
releases, overlay/cleartext settings, and intent-hijack surfaces.

All findings are STATIC INDICATORS from manifest evidence. They do not
prove exploitation is possible; each states the evidence and what to verify.
"""
from __future__ import annotations

from typing import Optional

from .knowledgebase import KnowledgeBase
from .models import (
    AssessmentStatus,
    Confidence,
    Finding,
    ProtectionLevel,
    Severity,
)

_FRAMEWORK = "permissionguard"

# Components that are safe-ish to export when protected
_PROTECTED_DEFAULT_ACTIONS = {
    "android.intent.action.MAIN",
    "android.intent.action.VIEW",
    "android.intent.action.EDIT",
    "android.intent.action.SEND",
    "android.intent.action.SENDTO",
    "android.intent.action.PICK",
    "android.intent.action.GET_CONTENT",
    "android.media.action.IMAGE_CAPTURE",
    "android.speech.action.RECOGNIZE_SPEECH",
}


def evaluate(kb: KnowledgeBase, meta) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(_exported_components(meta))
    findings.extend(_exported_provider(meta))
    findings.extend(_shared_user(meta))
    findings.extend(_weak_custom_permissions(meta))
    findings.extend(_debuggable(meta))
    findings.extend(_cleartext(meta))
    findings.extend(_task_affinity(meta))
    findings.extend(_exported_services_receivers(meta))
    return findings


# ---------------------------------------------------------------------------
def _exported_components(meta) -> list[Finding]:
    """Exported activities without a permission gate."""
    out: list[Finding] = []
    risky = []
    for c in meta.components:
        if c.type not in ("activity", "activity-alias"):
            continue
        if not c.exported:
            continue
        if c.permission:
            continue  # gated
        # an activity with only benign launch actions is usually fine
        actions = set(c.actions)
        if actions and actions <= _PROTECTED_DEFAULT_ACTIONS:
            continue
        if not actions and not c.intent_filters:
            # explicitly exported with no filters -> deliberate export
            risky.append((c, "explicitly exported with no intent filter"))
        else:
            risky.append((c, "exported with non-standard intent filters"))

    if risky:
        names = [f"{c.name} ({why})" for c, why in risky[:8]]
        out.append(Finding(
            finding_id="",
            rule_id="ESC-EXPORT-001",
            source_framework=_FRAMEWORK,
            title="Exported activities lack a permission gate",
            description=(
                "Exported activities can be launched by any app on the device. "
                "If such an activity performs privileged actions or accepts "
                "untrusted extras, another app can drive it — an intra-device "
                "privilege-escalation surface."
            ),
            affected_permissions=[],
            evidence="; ".join(names),
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            assessment_status=AssessmentStatus.POTENTIAL_CONCERN,
            recommended_action=(
                "Set android:exported=\"false\" unless external invocation is "
                "required; if it must be exported, add android:permission or "
                "signature-level permission, and validate all Intent extras."
            ),
            source_urls=[
                "https://developer.android.com/guide/components/intent-filters",
                "https://developer.android.com/privacy-and-security/security-recommendations#protected-components",
            ],
            limitations="Static analysis cannot determine whether the activity's code validates input.",
            category="escalation",
            correlation_key="esc:exported_activity",
        ))
    return out


def _exported_provider(meta) -> list[Finding]:
    out: list[Finding] = []
    providers = [c for c in meta.components if c.type == "provider"]
    at_risk = []
    for p in providers:
        if not p.exported:
            continue
        unprotected = (
            not p.permission
            and not p.grant_uri_permissions  # still risky if true w/o perms
        ) or (p.grant_uri_permissions is True and not p.permission)
        if p.exported and not p.permission:
            at_risk.append(p)

    if at_risk:
        names = [p.name for p in at_risk[:6]]
        out.append(Finding(
            finding_id="",
            rule_id="ESC-PROV-001",
            source_framework=_FRAMEWORK,
            title="Exported content provider without a read/write permission",
            description=(
                "An exported provider without a permission gate may let other "
                "apps query (and possibly modify) its data. Providers backed by "
                "databases or files are a classic local data-theft vector."
            ),
            affected_permissions=[],
            evidence="Unprotected exported providers: " + ", ".join(names),
            severity=Severity.CRITICAL,
            confidence=Confidence.MEDIUM,
            assessment_status=AssessmentStatus.POTENTIAL_CONCERN,
            recommended_action=(
                "Set exported=false, or enforce a signature-level permission; "
                "if URI grants are needed, use grantUriPermissions with "
                "narrow path permissions and never expose sensitive tables."
            ),
            source_urls=[
                "https://developer.android.com/guide/topics/providers/content-provider-basics",
                "https://developer.android.com/privacy-and-security/security-recommendations#protected-components",
            ],
            limitations="Whether the provider actually exposes sensitive rows requires code/data review.",
            category="escalation",
            correlation_key="esc:exported_provider",
        ))
    return out


def _exported_services_receivers(meta) -> list[Finding]:
    out: list[Finding] = []
    bad = [
        c for c in meta.components
        if c.type in ("service", "receiver") and c.exported and not c.permission
    ]
    if bad:
        names = [f"{c.name} [{c.type}]" for c in bad[:6]]
        out.append(Finding(
            finding_id="",
            rule_id="ESC-SVC-001",
            source_framework=_FRAMEWORK,
            title="Exported services/receivers without permission protection",
            description=(
                "Other apps can bind to these services or send broadcasts to "
                "these receivers. A service that performs privileged operations "
                "on command becomes a local escalation vector."
            ),
            affected_permissions=[],
            evidence="; ".join(names),
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            assessment_status=AssessmentStatus.POTENTIAL_CONCERN,
            recommended_action=(
                "Add android:permission (signature level where possible) or set "
                "exported=false; verify the receiver ignores unexpected actions."
            ),
            source_urls=["https://developer.android.com/privacy-and-security/security-recommendations#protected-components"],
            limitations="Static evidence only.",
            category="escalation",
            correlation_key="esc:exported_service_receiver",
        ))
    return out


def _shared_user(meta) -> list[Finding]:
    out: list[Finding] = []
    if meta.shared_user_id:
        is_system = "android.uid.system" in (meta.shared_user_id or "")
        out.append(Finding(
            finding_id="",
            rule_id="ESC-SHAREDUID-001",
            source_framework=_FRAMEWORK,
            title="Application runs under a shared Linux user ID",
            description=(
                "android:sharedUserId makes this app share a Unix UID with "
                "other apps installed under the same user ID — they can access "
                "each other's private data and file permissions."
                + (" Requesting android.uid.system would require platform "
                   "signing; if achieved with a non-platform key this is a "
                   "severe misconfiguration." if is_system else "")
            ),
            affected_permissions=[],
            evidence=f"sharedUserId = {meta.shared_user_id}",
            severity=Severity.CRITICAL if is_system else Severity.HIGH,
            confidence=Confidence.HIGH,
            assessment_status=AssessmentStatus.POTENTIAL_CONCERN,
            recommended_action=(
                "Remove sharedUserId (it cannot be changed after first release) "
                "and use ContentProvider/IPC with explicit permissions instead."
            ),
            source_urls=["https://developer.android.com/training/articles/perms.html#shareduserid"],
            limitations="Whether other apps actually share this UID depends on what else is installed.",
            category="escalation",
            correlation_key="esc:shared_uid",
        ))
    return out


def _weak_custom_permissions(meta) -> list[Finding]:
    out: list[Finding] = []
    weak = [
        cp for cp in meta.custom_permissions
        if str(cp.get("protection_level", "normal")).lower() in ("normal", "unknown", "")
    ]
    if weak:
        names = [cp.get("name", "?") for cp in weak]
        out.append(Finding(
            finding_id="",
            rule_id="ESC-CUSTOMPERM-001",
            source_framework=_FRAMEWORK,
            title="Custom permission defined with a weak protection level",
            description=(
                "The app defines its own permission using protectionLevel "
                "'normal' (or omits it). Normal permissions are granted "
                "automatically at install — ANY app can hold this permission, "
                "so anything it guards is effectively public."
            ),
            affected_permissions=names,
            evidence="; ".join(
                f"{cp.get('name')} -> {cp.get('protection_level_raw')}"
                for cp in weak
            ),
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            assessment_status=AssessmentStatus.POTENTIAL_CONCERN,
            recommended_action=(
                "Use protectionLevel=\"signature\" (or \"signature|privileged\") "
                "so only apps signed with the same key can obtain it."
            ),
            source_urls=["https://developer.android.com/guide/topics/permissions/defining"],
            limitations="Whether anything sensitive is actually guarded requires code review.",
            category="escalation",
            correlation_key="esc:weak_custom_permission",
        ))
    return out


def _debuggable(meta) -> list[Finding]:
    if meta.debuggable is not True:
        return []
    return [Finding(
        finding_id="",
        rule_id="ESC-DEBUG-001",
        source_framework=_FRAMEWORK,
        title="Application is debuggable",
        description=(
            "android:debuggable=true allows run-as, JDWP debugging and "
            "arbitrary inspection/modification of the app's private data by "
            "anything with adb access — a direct privilege-escalation enabler "
            "on shared or compromised devices."
        ),
        affected_permissions=[],
        evidence="manifest android:debuggable = true",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        assessment_status=AssessmentStatus.FAIL,
        recommended_action=(
            "Set android:debuggable=\"false\" in release builds (default is "
            "false; explicitly disable debuggable in build.gradle release block)."
        ),
        source_urls=["https://developer.android.com/guide/topics/manifest/application-element#debuggable"],
        limitations="Manifest attribute confirmed present; whether a debugger is actually attached at runtime cannot be determined from static analysis.",
        category="escalation",
        correlation_key="esc:debuggable",
    )]


def _cleartext(meta) -> list[Finding]:
    if meta.uses_cleartext_traffic is not True:
        return []
    return [Finding(
        finding_id="",
        rule_id="ESC-CLEARTEXT-001",
        source_framework=_FRAMEWORK,
        title="Cleartext network traffic permitted",
        description=(
            "android:usesCleartextTraffic=true allows unencrypted HTTP. On a "
            "hostile network this exposes session tokens and data to "
            "interception — a confidentiality failure that complements "
            "privilege abuse."
        ),
        affected_permissions=["android.permission.INTERNET"],
        evidence="manifest android:usesCleartextTraffic = true"
                 + (f"; networkSecurityConfig={meta.network_security_config}" if meta.network_security_config else ""),
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        assessment_status=AssessmentStatus.POTENTIAL_CONCERN,
        recommended_action="Disable cleartext traffic and ship a network security config enforcing TLS.",
        source_urls=["https://developer.android.com/privacy-and-security/security-config"],
        limitations="A custom network security config may still permit specific domains.",
        category="escalation",
        correlation_key="esc:cleartext",
    )]


def _task_affinity(meta) -> list[Finding]:
    out: list[Finding] = []
    for c in meta.components:
        if c.type != "activity":
            continue
        if c.task_affinity and c.exported and not c.permission:
            out.append(Finding(
                finding_id="",
                rule_id="ESC-TASKAFF-001",
                source_framework=_FRAMEWORK,
                title="Exported activity with a custom taskAffinity (task hijack risk)",
                description=(
                    "A custom taskAffinity on an exported activity can allow "
                    "another app to back-stack-hijack this activity's task and "
                    "present a spoofed flow to the user (activity hijacking)."
                ),
                affected_permissions=[],
                evidence=f"{c.name} exported=true taskAffinity={c.task_affinity}",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                assessment_status=AssessmentStatus.POTENTIAL_CONCERN,
                recommended_action="Set taskAffinity=\"\" or exported=false; consider allowTaskReparenting=false.",
                source_urls=["https://developer.android.com/guide/components/activities/tasks-and-back-stack"],
                limitations="Exploitation depends on the launch flow and OS version.",
                category="escalation",
                correlation_key=f"esc:taskaff:{c.name}",
            ))
            break  # one representative finding is enough
    return out
