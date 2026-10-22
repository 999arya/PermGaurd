"""Parse a decoded AndroidManifest tree into PermissionGuard models.

Turns an ``ElementTree`` (from :mod:`src.axmldecoder` or a text XML file)
into :class:`~src.models.ApkMetadata` with permissions, components and the
manifest attributes relevant to permission/privacy analysis.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Optional

from .models import ApkMetadata, Component, Permission, ProtectionLevel

# Android boolean attribute convention: an absent attribute on <application>
# defaults to true for allowBackup, false for debuggable/testOnly.
_TRUE = {"true", "1", "0x1", "yes"}
_FALSE = {"false", "0", "0x0", "no"}


class ManifestParseError(ValueError):
    """Raised when a manifest cannot be parsed into usable structure."""


def _local(tag: str) -> str:
    """Return local name ignoring any XML namespace."""
    if "}" in tag:
        return tag.rsplit("}", 1)[1]
    if ":" in tag:
        return tag.split(":", 1)[1]
    return tag


def _bool_attr(elem: ET.Element, name: str, default: Optional[bool]) -> Optional[bool]:
    for key, value in elem.attrib.items():
        if _local(key) == name:
            v = value.strip().lower()
            if v in _TRUE:
                return True
            if v in _FALSE:
                return False
            return default
    return default


def _str_attr(elem: ET.Element, name: str) -> Optional[str]:
    for key, value in elem.attrib.items():
        if _local(key) == name:
            return value
    return None


def _int_attr(elem: ET.Element, name: str) -> Optional[int]:
    raw = _str_attr(elem, name)
    if raw is None:
        return None
    try:
        if raw.lower().startswith("0x"):
            return int(raw, 16)
        return int(raw)
    except ValueError:
        m = re.search(r"\d+", raw)
        return int(m.group()) if m else None


def _parse_protection_level(raw: Optional[str]) -> ProtectionLevel:
    if raw is None:
        return ProtectionLevel.UNKNOWN
    value = raw.strip().lower()
    # protection levels can be combined with '|' e.g. "signature|privileged"
    base = value.split("|")[0].strip()
    mapping = {
        "normal": ProtectionLevel.NORMAL,
        "dangerous": ProtectionLevel.DANGEROUS,
        "signature": ProtectionLevel.SIGNATURE,
        "signatureorsystem": ProtectionLevel.SIGNATURE_OR_SYSTEM,
        "signature_or_system": ProtectionLevel.SIGNATURE_OR_SYSTEM,
        "internal": ProtectionLevel.INTERNAL,
    }
    if base in mapping:
        return mapping[base]
    # combined forms containing a known token
    if "signatureorsystem" in value or "signature_or_system" in value:
        return ProtectionLevel.SIGNATURE_OR_SYSTEM
    if "signature" in value:
        return ProtectionLevel.SIGNATURE
    if "dangerous" in value:
        return ProtectionLevel.DANGEROUS
    if "normal" in value:
        return ProtectionLevel.NORMAL
    return ProtectionLevel.UNKNOWN


def parse_manifest(root: ET.Element, into: Optional[ApkMetadata] = None) -> ApkMetadata:
    """Convert a decoded ``<manifest>`` element into an :class:`ApkMetadata`."""
    if _local(root.tag) != "manifest":
        raise ManifestParseError(
            f"root element is <{_local(root.tag)}>, expected <manifest>"
        )

    meta = into or ApkMetadata()
    meta.package_name = _str_attr(root, "package")
    meta.version_name = _str_attr(root, "versionName")
    vc = _str_attr(root, "versionCode")
    if vc:
        # versionCode may be a resource ref like "@integer/xyz"
        meta.version_code = vc
    sdk_u = _str_attr(root, "sharedUserId")
    if sdk_u:
        meta.shared_user_id = sdk_u

    permissions: list[Permission] = []
    custom_perms: list[dict] = []
    components: list[Component] = []

    app_elem: Optional[ET.Element] = None

    for child in root:
        tag = _local(child.tag)

        if tag == "uses-sdk":
            min_sdk = _int_attr(child, "minSdkVersion")
            target_sdk = _int_attr(child, "targetSdkVersion")
            if min_sdk is not None:
                meta.min_sdk = min_sdk
            if target_sdk is not None:
                meta.target_sdk = target_sdk

        elif tag == "uses-permission" or tag == "uses-permission-sdk-23":
            name = _str_attr(child, "name")
            if name:
                permissions.append(Permission(name=name))

        elif tag == "permission":
            # custom permission defined by this app
            name = _str_attr(child, "name")
            if name:
                raw_level = _str_attr(child, "protectionLevel")
                custom_perms.append(
                    {
                        "name": name,
                        "protection_level_raw": raw_level or "normal",
                        "protection_level": _parse_protection_level(raw_level).value,
                        "label": _str_attr(child, "label"),
                        "description": _str_attr(child, "description"),
                    }
                )

        elif tag == "permission-group":
            pass  # grouping metadata, not needed for analysis

        elif tag == "application":
            app_elem = child

    if app_elem is None:
        # Manifest with permissions but no <application>: still usable.
        meta.permissions = _dedupe(permissions)
        meta.custom_permissions = custom_perms
        return meta

    meta.app_label = _str_attr(app_elem, "label")
    meta.debuggable = _bool_attr(app_elem, "debuggable", False)
    meta.allow_backup = _bool_attr(app_elem, "allowBackup", True)
    meta.test_only = _bool_attr(app_elem, "testOnly", False)
    meta.uses_cleartext_traffic = _bool_attr(app_elem, "usesCleartextTraffic", False)
    meta.extract_native_libs = _bool_attr(app_elem, "extractNativeLibs", None)
    meta.network_security_config = _str_attr(app_elem, "networkSecurityConfig")
    meta.shared_library = _str_attr(app_elem, "sharedLibrary")

    for comp in app_elem:
        ctype = _local(comp.tag)
        if ctype not in ("activity", "activity-alias", "service", "receiver", "provider"):
            continue
        norm_type = "activity" if ctype == "activity-alias" else ctype
        name = _str_attr(comp, "name") or ""
        exported = _bool_attr(comp, "exported", None)
        permission = _str_attr(comp, "permission")
        actions: list[str] = []
        for sub in comp:
            if _local(sub.tag) == "intent-filter":
                for act in sub:
                    if _local(act.tag) == "action":
                        an = _str_attr(act, "name")
                        if an:
                            actions.append(an)
        filters = sum(1 for s in comp if _local(s.tag) == "intent-filter")

        # Android rule: a component with an intent-filter defaults to
        # exported=true when android:exported is absent.
        if exported is None and filters > 0:
            exported = True

        component = Component(
            type=norm_type,
            name=name,
            exported=exported,
            permission=permission,
            intent_filters=filters,
            actions=actions,
            authorities=_str_attr(comp, "authorities"),
            grant_uri_permissions=_bool_attr(comp, "grantUriPermissions", None),
            process=_str_attr(comp, "process"),
            enabled=_bool_attr(comp, "enabled", None),
            direct_boot_aware=_bool_attr(comp, "directBootAware", None),
            task_affinity=_str_attr(comp, "taskAffinity"),
        )
        components.append(component)

    meta.permissions = _dedupe(permissions)
    meta.custom_permissions = custom_perms
    meta.components = components
    return meta


def _dedupe(perms: list[Permission]) -> list[Permission]:
    seen: set[str] = set()
    out: list[Permission] = []
    for p in perms:
        if p.name in seen:
            continue
        seen.add(p.name)
        out.append(p)
    return out


def parse_manifest_text(text: str) -> ApkMetadata:
    """Parse plain-text XML (alternative input mode)."""
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ManifestParseError(f"invalid XML: {exc}") from exc
    return parse_manifest(root)
