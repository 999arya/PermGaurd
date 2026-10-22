"""Core data models for PermissionGuard AI.

All internal data flows through validated Pydantic models so that extraction,
analysis, scoring, and reporting share one consistent schema.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class AssessmentStatus(str, Enum):
    """Status of an individual finding.

    FAIL is reserved for cases where evidence supports the exact failure
    condition of a rule. Most manifest-only observations cannot reach FAIL.
    """
    PASS = "PASS"
    POTENTIAL_CONCERN = "POTENTIAL_CONCERN"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    FAIL = "FAIL"


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Confidence(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class ProtectionLevel(str, Enum):
    """Android's *official* protection level for a permission."""
    NORMAL = "normal"
    DANGEROUS = "dangerous"
    SIGNATURE = "signature"
    SIGNATURE_OR_SYSTEM = "signatureOrSystem"
    INTERNAL = "internal"
    UNKNOWN = "unknown"


class SensitivityTier(str, Enum):
    """PermissionGuard's own privacy-risk tier (distinct from Android's
    official protection level)."""
    NONE = "NONE"
    LOW = "LOW"
    MODERATE = "MODERATE"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RuntimeCategory(str, Enum):
    """How the permission is granted, for modern target SDKs."""
    INSTALL_TIME = "install-time"
    RUNTIME = "runtime"
    SPECIAL = "special"
    SIGNATURE = "signature"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Permissions
# ---------------------------------------------------------------------------

class Permission(BaseModel):
    """A permission declared in the analyzed application's manifest."""
    name: str
    source: str = "manifest"  # manifest | user_report | inferred
    custom: bool = False
    protection_level: ProtectionLevel = ProtectionLevel.UNKNOWN
    declaring_package: Optional[str] = None
    # filled by classifier:
    description: str = ""
    sensitivity: SensitivityTier = SensitivityTier.NONE
    runtime_category: RuntimeCategory = RuntimeCategory.UNKNOWN
    data_or_functionality: str = ""
    legitimate_uses: list[str] = Field(default_factory=list)
    excess_conditions: list[str] = Field(default_factory=list)
    alternatives: list[str] = Field(default_factory=list)
    doc_urls: list[str] = Field(default_factory=list)
    notes: str = ""
    known_to_android: bool = True


class Component(BaseModel):
    """An application component declared in the manifest."""
    type: str  # activity | service | receiver | provider | application
    name: str
    exported: Optional[bool] = None  # None = not explicitly declared
    permission: Optional[str] = None
    intent_filters: int = 0
    actions: list[str] = Field(default_factory=list)
    authorities: Optional[str] = None
    grant_uri_permissions: Optional[bool] = None
    process: Optional[str] = None
    enabled: Optional[bool] = None
    direct_boot_aware: Optional[bool] = None
    task_affinity: Optional[str] = None


# ---------------------------------------------------------------------------
# Application metadata
# ---------------------------------------------------------------------------

class SignatureInfo(BaseModel):
    scheme: str  # v1 (JAR) | v2 | v3 | v4 | unknown
    present: bool = True
    details: str = ""


class ApkMetadata(BaseModel):
    """Everything extracted from an APK (or alternative input report)."""
    input_type: str = "apk"  # apk | manifest_xml | json_report | csv_report
    filename: str = ""
    file_size: int = 0
    sha256: str = ""
    package_name: Optional[str] = None
    version_name: Optional[str] = None
    version_code: Optional[str] = None
    min_sdk: Optional[int] = None
    target_sdk: Optional[int] = None
    compile_sdk: Optional[int] = None
    app_label: Optional[str] = None
    permissions: list[Permission] = Field(default_factory=list)
    components: list[Component] = Field(default_factory=list)
    custom_permissions: list[dict[str, Any]] = Field(default_factory=list)
    shared_user_id: Optional[str] = None
    shared_library: Optional[str] = None
    debuggable: Optional[bool] = None
    allow_backup: Optional[bool] = None
    uses_cleartext_traffic: Optional[bool] = None
    network_security_config: Optional[str] = None
    test_only: Optional[bool] = None
    extract_native_libs: Optional[bool] = None
    native_libraries: list[str] = Field(default_factory=list)
    asset_entries: list[str] = Field(default_factory=list)
    elf_assets: list[str] = Field(default_factory=list)
    dex_string_findings: list[str] = Field(default_factory=list)
    dex_string_count: int = 0
    signature_schemes: list[SignatureInfo] = Field(default_factory=list)
    extraction_notes: list[str] = Field(default_factory=list)
    extraction_tool: str = "builtin-axml"
    extracted_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


# ---------------------------------------------------------------------------
# Purpose
# ---------------------------------------------------------------------------

class PurposeProfile(BaseModel):
    """User-supplied (or inferred) description of what the app is for."""
    app_name: Optional[str] = None
    category: Optional[str] = None  # key into appcategories knowledge base
    description: str = ""
    features: list[str] = Field(default_factory=list)
    intended_users: str = ""
    expected_sensitive_access: list[str] = Field(default_factory=list)
    source: str = "user"  # user | inferred | none


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

class Finding(BaseModel):
    finding_id: str
    rule_id: str
    source_framework: str  # google_play | owasp_informed | org_policy | permissionguard | android_doc
    title: str
    description: str
    affected_permissions: list[str] = Field(default_factory=list)
    evidence: str = ""
    severity: Severity = Severity.INFO
    confidence: Confidence = Confidence.MEDIUM
    assessment_status: AssessmentStatus = AssessmentStatus.NEEDS_REVIEW
    score_contribution: float = 0.0
    recommended_action: str = ""
    source_urls: list[str] = Field(default_factory=list)
    limitations: str = ""
    category: str = "general"
    correlation_key: Optional[str] = None  # used to avoid double counting


class PurposeCompatibility(BaseModel):
    """Per-permission justification assessment."""
    permission: str
    expected_for_purpose: bool
    verdict: str  # JUSTIFIED | PLAUSIBLE | UNEXPECTED | UNDETERMINED
    rationale: str = ""
    alternative_available: Optional[str] = None


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

class ScoreContribution(BaseModel):
    finding_id: str
    rule_id: str
    label: str
    raw_points: float
    applied_points: float
    severity: Severity
    reason: str = ""


class RiskReport(BaseModel):
    score: float = 0.0  # 0-100
    level: RiskLevel = RiskLevel.LOW
    breakdown: list[ScoreContribution] = Field(default_factory=list)
    explanation: str = ""
    capped_findings: list[str] = Field(default_factory=list)
    deduplicated_findings: list[str] = Field(default_factory=list)
    method: str = ""
    thresholds: dict[str, float] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Full scan result
# ---------------------------------------------------------------------------

class ScanResult(BaseModel):
    scan_id: str
    metadata: ApkMetadata
    purpose: Optional[PurposeProfile] = None
    purpose_compatibility: list[PurposeCompatibility] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    risk: RiskReport = Field(default_factory=RiskReport)
    recommendations: list[dict[str, Any]] = Field(default_factory=list)
    rule_versions: dict[str, str] = Field(default_factory=dict)
    scan_mode: str = "auto"          # auto | basic | deep
    scan_depth_used: str = "basic"    # basic | deep
    scan_started_at: str = ""
    scan_finished_at: str = ""
    # Optional MobSF (or sample JSON) supporting evidence. Never scored.
    supporting_evidence: Optional[dict[str, Any]] = None
    cached: bool = False
    disclaimer: str = (
        "This report is an automated, evidence-based assessment. It is not an "
        "official Google Play compliance determination, an OWASP certification, "
        "or proof that an application is malicious. Manifest analysis alone "
        "cannot establish actual runtime behaviour."
    )

    @property
    def severity_counts(self) -> dict[str, int]:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.findings:
            if f.assessment_status in (
                AssessmentStatus.PASS,
                AssessmentStatus.NOT_APPLICABLE,
            ):
                continue
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        return counts
