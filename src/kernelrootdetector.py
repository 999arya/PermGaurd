"""Kernel / root-access indicator detector.

Looks for STATIC EVIDENCE that an app interacts with root, kernel or
system-level facilities:

  * DEX strings: su/Magisk/Superuser references, su binary paths, exploit and
    CVE markers, /proc and /sys write paths, chmod/mount/remount commands,
    SELinux probing, kernel-memory device paths
  * Staged ELF binaries inside assets/ (possible exploit payloads)
  * Suspicious native libraries

Every result is an INDICATOR from static strings — never proof that the
code path executes, that the app roots a device, or that it exploits a
kernel vulnerability. Two legitimate patterns produce these strings and are
handled explicitly:
  * root-DETECTION libraries (apps checking if a device is rooted to warn the
    user or refuse banking features) — a security feature, not a threat
  * superuser-REQUESTING apps (custom ROM utilities) — expected of that niche

The differentiator is which indicators co-occur: detection strings alone are
LOW severity; detection + acquisition/escalation strings together escalate.
"""
from __future__ import annotations

from typing import Optional

from .knowledgebase import KnowledgeBase
from .models import (
    AssessmentStatus,
    Confidence,
    Finding,
    Severity,
)

_FRAMEWORK = "permissionguard"

# Indicator groups (rule ids from dexscanner INDICATOR_PATTERNS)
_DETECTION_IDS = {"DEX-ROOT-001", "DEX-ROOT-002", "DEX-ROOT-003", "DEX-SU-001"}
_EXPLOIT_IDS = {"DEX-KERNEL-001", "DEX-KERNEL-002", "DEX-KERNEL-003"}
_EXEC_IDS = {"DEX-EXEC-001", "DEX-EXEC-002"}
_SELINUX_ID = "DEX-SELINUX-001"
_PATH_IDS = {"DEX-FILE-001", "DEX-PRIV-001", "DEX-NET-001"}


def evaluate(kb: KnowledgeBase, meta) -> list[Finding]:
    out: list[Finding] = []
    parsed = _parse_indicators(meta.dex_string_findings)
    ids_present = {i["rule_id"] for i in parsed}

    out.extend(_elf_assets(meta))
    out.extend(_kernel_exploit_evidence(parsed, ids_present))
    out.extend(_root_reference(parsed, ids_present))
    out.extend(_exec_pattern(parsed, ids_present))
    out.extend(_selinux(parsed, ids_present))
    out.extend(_file_system_paths(parsed, ids_present))
    return out


def _parse_indicators(lines: list[str]) -> list[dict]:
    """Lines look like: [DEX-SU-001] label: evidence"""
    out: list[dict] = []
    for line in lines:
        if not line.startswith("["):
            continue
        try:
            rid = line[1:line.index("]")]
            rest = line[line.index("]") + 1:].strip()
            if ": " in rest:
                label, evidence = rest.split(": ", 1)
            else:
                label, evidence = rest, rest
            out.append({"rule_id": rid, "label": label, "evidence": evidence})
        except (ValueError, IndexError):
            continue
    return out


def _group(parsed: list[dict], ids: set[str], limit: int = 5) -> str:
    hits = [p for p in parsed if p["rule_id"] in ids]
    parts = [f"{p['evidence'][:120]}" for p in hits[:limit]]
    more = f" (+{len(hits) - limit} more)" if len(hits) > limit else ""
    return "; ".join(parts) + more


# ---------------------------------------------------------------------------

def _elf_assets(meta) -> list[Finding]:
    """Raw ELF binaries staged in assets/ — possible staged exploit/upgrade."""
    if not meta.elf_assets:
        return []
    names = [e for e in meta.elf_assets if not e.endswith("(suspicious extension)")]
    ext = [e for e in meta.elf_assets if e.endswith("(suspicious extension)")]
    if not names and not ext:
        return []
    return [Finding(
        finding_id="",
        rule_id="KR-ASSET-ELF-001",
        source_framework=_FRAMEWORK,
        title="Executable/ELF payloads bundled inside assets/",
        description=(
            "The APK ships raw ELF binaries (or executable-looking files) in "
            "its assets. While legitimate for self-extracting native helpers, "
            "staging executables in assets is a common way to deliver "
            "kernel exploits or post-root payloads that run after privilege "
            "escalation. The binary cannot be executed by the OS directly from "
            "assets — it must first be written to an executable location."
        ),
        affected_permissions=[],
        evidence="assets entries: " + ", ".join(meta.elf_assets[:6]),
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        assessment_status=AssessmentStatus.NEEDS_REVIEW,
        recommended_action=(
            "Verify each bundled binary's provenance and purpose. If not "
            "required, remove them. Security tools should flag asset-loaded "
            "executables in review."
        ),
        source_urls=["https://mas.owasp.org/MASTG/"],
        limitations=(
            "Static inspection only — the file could be a benign helper "
            "(e.g. a bundled busybox for its own sandbox). Its presence is "
            "not proof of exploitation."
        ),
        category="kernel_root",
        correlation_key="kr:elf_assets",
    )]


def _kernel_exploit_evidence(parsed, ids) -> list[Finding]:
    hits = [p for p in parsed if p["rule_id"] in _EXPLOIT_IDS]
    if not hits:
        return []
    cve_hits = [p for p in hits if p["rule_id"] == "DEX-KERNEL-001"]
    sev = Severity.CRITICAL if cve_hits else Severity.HIGH
    return [Finding(
        finding_id="",
        rule_id="KR-KERNEL-001",
        source_framework=_FRAMEWORK,
        title="Kernel/exploit-related strings present in application code",
        description=(
            "The app's compiled code contains strings associated with kernel "
            "interfaces, CVE identifiers, or known exploit technique names. "
            "Apps may legitimately REFERENCE CVEs in a root/compromise "
            "detection routine, but the same strings can also indicate staged "
            "exploitation. The distinction requires code review."
        ),
        affected_permissions=[],
        evidence=_group(parsed, _EXPLOIT_IDS),
        severity=sev,
        confidence=Confidence.MEDIUM,
        assessment_status=AssessmentStatus.NEEDS_REVIEW,
        recommended_action=(
            "Inspect the surrounding code: is this root/compromise DETECTION "
            "(defensive) or an exploitation routine? If defensive, document it; "
            "otherwise remove."
        ),
        source_urls=["https://mas.owasp.org/MASTG/"],
        limitations=(
            "String presence is not proof that an exploit runs. Root-detection "
            "and security-audit code contains the same strings. Requires manual "
            "code review to classify."
        ),
        category="kernel_root",
        correlation_key="kr:kernel_strings",
    )]


def _root_reference(parsed, ids) -> list[Finding]:
    hits = [p for p in parsed if p["rule_id"] in _DETECTION_IDS]
    if not hits:
        return []

    # Distinguish: does the app ALSO show acquisition/exploitation behaviour?
    has_exec = bool([p for p in parsed if p["rule_id"] in _EXEC_IDS])
    has_kernel = bool([p for p in parsed if p["rule_id"] in _EXPLOIT_IDS])
    has_elf = False  # handled separately but reinforces context

    if has_kernel or has_exec:
        sev = Severity.HIGH
        status = AssessmentStatus.NEEDS_REVIEW
        intro = (
            "Root-related strings co-occur with process-execution or "
            "kernel-interface strings — this pattern needs review: it could be "
            "a root-detection routine (defensive) or an attempt to obtain/"
            "exercise elevated privileges."
        )
        conf = Confidence.MEDIUM
    else:
        sev = Severity.LOW
        status = AssessmentStatus.POTENTIAL_CONCERN
        intro = (
            "Root/superuser references were found without accompanying "
            "execution or kernel-interface strings — most consistent with "
            "root-DETECTION (an app warning users their device is rooted), "
            "which is a security feature, not a threat."
        )
        conf = Confidence.MEDIUM

    return [Finding(
        finding_id="",
        rule_id="KR-ROOT-001",
        source_framework=_FRAMEWORK,
        title="Root / superuser related strings detected",
        description=(
            f"{intro} Either way it should be documented: security-sensitive "
            "apps commonly verify device integrity before processing data."
        ),
        affected_permissions=[],
        evidence=_group(parsed, _DETECTION_IDS),
        severity=sev,
        confidence=conf,
        assessment_status=status,
        recommended_action=(
            "Confirm whether this is a root-detection check (defensive — "
            "document it) or privilege acquisition (escalate to security "
            "review)."
        ),
        source_urls=["https://mas.owasp.org/MASTG/"],
        limitations=(
            "Static strings cannot distinguish detection from acquisition "
            "without code review. Root detection is a legitimate, common "
            "security control."
        ),
        category="kernel_root",
        correlation_key="kr:root_strings",
    )]


def _exec_pattern(parsed, ids) -> list[Finding]:
    hits = [p for p in parsed if p["rule_id"] in _EXEC_IDS]
    if not hits:
        return []
    chmod = [p for p in parsed if p["rule_id"] == "DEX-EXEC-002"]
    sev = Severity.HIGH if chmod else Severity.MEDIUM
    return [Finding(
        finding_id="",
        rule_id="KR-EXEC-001",
        source_framework=_FRAMEWORK,
        title="Process execution with file-permission manipulation patterns",
        description=(
            "The code executes external processes and/or contains chmod/chown/"
            "remount-style commands. Combined with su references this is the "
            "standard post-escalation pattern (make a dropped binary executable "
            "and run it). Legitimate uses exist (bundled CLI helpers in "
            "device-admin/enterprise apps) but the pattern must be justified."
        ),
        affected_permissions=[],
        evidence=_group(parsed, _EXEC_IDS),
        severity=sev,
        confidence=Confidence.MEDIUM,
        assessment_status=AssessmentStatus.NEEDS_REVIEW,
        recommended_action=(
            "Review what commands are executed and with what privileges. "
            "Replace shell exec with Android APIs where possible; never "
            "download-and-exec binaries."
        ),
        source_urls=["https://mas.owasp.org/MASTG/"],
        limitations="Runtime.exec may be used for benign helpers; static evidence only.",
        category="kernel_root",
        correlation_key="kr:exec_strings",
    )]


def _selinux(parsed, ids) -> list[Finding]:
    hits = [p for p in parsed if p["rule_id"] == _SELINUX_ID]
    if not hits:
        return []
    disabling = [p for p in hits if "setenforce" in p["evidence"].lower()]
    sev = Severity.HIGH if disabling else Severity.MEDIUM
    return [Finding(
        finding_id="",
        rule_id="KR-SELINUX-001",
        source_framework=_FRAMEWORK,
        title="SELinux probing or disabling patterns",
        description=(
            "The code reads or writes SELinux state. 'setenforce 0' attempts "
            "to disable the kernel's mandatory access control — a strong "
            "escalation indicator. Read-only checks (getenconf) are typical of "
            "device-integrity detection."
        ),
        affected_permissions=[],
        evidence=_group(parsed, {_SELINUX_ID}),
        severity=sev,
        confidence=Confidence.MEDIUM,
        assessment_status=AssessmentStatus.NEEDS_REVIEW,
        recommended_action="Remove any attempt to modify SELinux state; read-only integrity checks are acceptable.",
        source_urls=["https://mas.owasp.org/MASTG/"],
        limitations="Static evidence; cannot confirm the call executes.",
        category="kernel_root",
        correlation_key="kr:selinux",
    )]


def _file_system_paths(parsed, ids) -> list[Finding]:
    hits = [p for p in parsed if p["rule_id"] in _PATH_IDS]
    if not hits:
        return []
    mem = [p for p in hits if p["rule_id"] == "DEX-KERNEL-003"]
    return [Finding(
        finding_id="",
        rule_id="KR-PATH-001",
        source_framework=_FRAMEWORK,
        title="Sensitive system path access patterns",
        description=(
            "Strings referencing /proc, /data/system or ADB/settings interfaces "
            "appear in the code. These paths expose process/kernel state or "
            "privileged configuration; writing to them requires elevated "
            "privileges. Read-only use may be benign diagnostics."
        ),
        affected_permissions=[],
        evidence=_group(parsed, _PATH_IDS),
        severity=Severity.MEDIUM,
        confidence=Confidence.LOW,
        assessment_status=AssessmentStatus.NEEDS_REVIEW,
        recommended_action="Confirm reads only where possible; remove any writes to system paths.",
        source_urls=["https://mas.owasp.org/MASTG/"],
        limitations="Common in legitimate diagnostics and analytics SDKs; low confidence without code context.",
        category="kernel_root",
        correlation_key="kr:system_paths",
    )]
