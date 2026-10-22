"""Lightweight DEX string scanner (pure standard library).

Reads the DEX string table directly so we can look for permission-relevant
runtime indicators (root/su/Magisk references, suspicious exec patterns,
exploit/CVE markers, write-to-system paths) without any external tooling.

This is *static string evidence only* — the presence of a string does not
prove the code path is ever executed. Every result is reported as an
indicator, never as observed runtime behaviour.
"""
from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field

DEX_MAGIC = b"dex\n"

# Patterns worth surfacing for permission/privilege analysis.
# Each is (rule_id, compiled_regex, human label).
INDICATOR_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    ("DEX-SU-001", re.compile(r"(?<![\w/])(su|superuser|superuser\.apk)(?![\w])", re.I),
     "superuser / su reference"),
    ("DEX-SU-002", re.compile(r"/system/xbin/su|/system/bin/su|/sbin/su|/su/bin/su"),
     "su binary path"),
    ("DEX-ROOT-001", re.compile(r"magisk|koushiksu|supersu|topjohnwu|kingo?root|frida-server|riru|zygisk", re.I),
     "root/hook framework reference"),
    ("DEX-ROOT-002", re.compile(r"test-keys|ro\.debuggable\s*=\s*1|ro\.secure\s*=\s*0|getprop\s+ro\.build\.tags", re.I),
     "root-detection / build property probing"),
    ("DEX-ROOT-003", re.compile(r"busybox|/system/app/Superuser|daemonsu|which\s+su", re.I),
     "root helper reference"),
    ("DEX-KERNEL-001", re.compile(r"\bcve-\d{4}-\d{4,7}\b", re.I),
     "CVE identifier string (possible exploit reference)"),
    ("DEX-KERNEL-002", re.compile(r"dirtycow|dirty.?pipe|kernel.?exploit|perf_event_open|pwn|escalat", re.I),
     "known-exploit / privilege-escalation marker"),
    ("DEX-KERNEL-003", re.compile(r"/proc/kmsg|/proc/kallsyms|/proc/sys|/dev/kmem|/dev/mem|/proc/self/mem", re.I),
     "direct kernel/device access path"),
    ("DEX-EXEC-001", re.compile(r"Runtime\.getRuntime\(\)\.exec|java/lang/Runtime;->exec"),
     "runtime process execution"),
    ("DEX-EXEC-002", re.compile(r"\bchmod\s|/system/bin/chown|\bmount\s+-o\s+remount|busybox\s+mount", re.I),
     "file-permission / remount command"),
    ("DEX-FILE-001", re.compile(r"/data/data/[\w.]+/(databases|shared_prefs)|/data/system/", re.I),
     "private/system data path access"),
    ("DEX-NET-001", re.compile(r"setprop\s+net\.dns|/etc/hosts|iptables|ip6tables", re.I),
     "network stack manipulation"),
    ("DEX-SELINUX-001", re.compile(r"getenforce|setenforce\s+0|/sys/fs/selinux", re.I),
     "SELinux probing or disabling"),
    ("DEX-PRIV-001", re.compile(r"adb\s+shell|content\s+call|settings\s+put\s+global", re.I),
     "ADB / settings privilege command"),
    ("DEX-CRYPTO-001", re.compile(r"AES/ECB|DES/ECB|DESede|RC4|ARCFOUR|ssl\.TrustAll|ALLOW_ALL_HOSTNAME", re.I),
     "weak cryptography / trust-all TLS marker"),
    ("DEX-SECRET-001", re.compile(r"(?i)(api[_-]?key|secret[_-]?key|private[_-]?key)\s*[=:]\s*[\"'][A-Za-z0-9_\-]{16,}[\"']"),
     "possible hardcoded credential"),
    ("DEX-SMS-001", re.compile(r"SmsManager|sendTextMessage|getDefault\(\)\.sendTextMessage"),
     "SMS sending API usage"),
    ("DEX-CONTACTS-001", re.compile(r"ContactsContract|ManagedQuery.*contacts", re.I),
     "contacts provider access"),
    ("DEX-LOCATION-001", re.compile(r"getLastKnownLocation|requestLocationUpdates|FusedLocationProvider", re.I),
     "location API usage"),
    ("DEX-MIC-001", re.compile(r"MediaRecorder|AudioRecord|setAudioSource", re.I),
     "audio recording API usage"),
    ("DEX-CAMERA-001", re.compile(r"Camera\.open|Camera2|CameraManager", re.I),
     "camera API usage"),
]

DEX_STRING_LIMIT = 400_000


@dataclass
class DexScanResult:
    total_strings: int = 0
    indicators: list[dict] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def _uleb128(buf: bytes, off: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        if off >= len(buf):
            raise ValueError("ULEB128 out of bounds")
        b = buf[off]
        off += 1
        result |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            break
        shift += 7
        if shift > 35:
            raise ValueError("ULEB128 too long")
    return result, off


def read_dex_strings(data: bytes, limit: int = DEX_STRING_LIMIT) -> list[str]:
    """Extract strings from a DEX file's string table (bounded)."""
    if len(data) < 0x70 or data[:4] != DEX_MAGIC:
        raise ValueError("not a DEX file")

    string_ids_size = struct.unpack_from("<I", data, 0x38)[0]
    string_ids_off = struct.unpack_from("<I", data, 0x3C)[0]

    strings: list[str] = []
    for i in range(min(string_ids_size, limit)):
        sid_off = string_ids_off + i * 4
        if sid_off + 4 > len(data):
            break
        str_data_off = struct.unpack_from("<I", data, sid_off)[0]
        if str_data_off >= len(data):
            continue
        try:
            utf16_size, pos = _uleb128(data, str_data_off)
        except ValueError:
            continue
        if utf16_size == 0:
            strings.append("")
            continue
        # MUTF-8 string: read until NUL
        end = pos
        nul = data.find(b"\x00", end, min(end + 8192, len(data)))
        if nul == -1:
            nul = min(pos + 4096, len(data))
        raw = data[pos:nul]
        try:
            strings.append(raw.decode("utf-8", errors="replace"))
        except Exception:  # pragma: no cover
            strings.append(raw.decode("latin-1", errors="replace"))
    return strings


def scan_dex(data: bytes, limit: int = DEX_STRING_LIMIT) -> DexScanResult:
    """Scan one DEX payload for permission-relevant indicator strings."""
    result = DexScanResult()
    try:
        strings = read_dex_strings(data, limit)
    except ValueError as exc:
        result.notes.append(f"DEX unreadable: {exc}")
        return result

    result.total_strings = len(strings)
    if result.total_strings >= limit:
        result.notes.append(
            f"string table truncated at {limit} strings (parsing limit)"
        )

    seen: set[str] = set()
    for text in strings:
        if not text or len(text) > 4096:
            continue
        for rule_id, pattern, label in INDICATOR_PATTERNS:
            if pattern.search(text):
                key = f"{rule_id}:{text[:120]}"
                if key in seen:
                    continue
                seen.add(key)
                snippet = text if len(text) <= 160 else text[:157] + "..."
                result.indicators.append(
                    {"rule_id": rule_id, "label": label, "evidence": snippet}
                )
                if len(result.indicators) >= 400:
                    result.notes.append("indicator list capped at 400 entries")
                    return result
    return result
