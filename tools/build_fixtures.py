"""Build synthetic test APK fixtures WITHOUT the Android SDK.

Writes real, parseable APKs: a ZIP containing a genuine binary
AndroidManifest.xml (encoded by a minimal AXML writer) and a small DEX.
Used by tests and the demo fixture set.

All fixtures are clearly labelled SYNTHETIC — they are not real
applications and contain no executable behaviour beyond a stub DEX header.

Run:  python tools/build_fixtures.py
"""
from __future__ import annotations

import io
import struct
import zipfile
import os
import sys

# ---------------------------------------------------------------------------
# Minimal AXML (ResXMLTree) writer
# ---------------------------------------------------------------------------

RES_XML_CHUNK = 0x0003
RES_STRING_POOL_CHUNK = 0x0001
RES_XML_START_NAMESPACE_CHUNK = 0x0100
RES_XML_END_NAMESPACE_CHUNK = 0x0101
RES_XML_START_ELEMENT_CHUNK = 0x0102
RES_XML_END_ELEMENT_CHUNK = 0x0103

UTF8_FLAG = 0x00000100
TYPE_STRING = 0x03
TYPE_INT_DEC = 0x10
TYPE_INT_BOOLEAN = 0x12
ANDROID_NS = "http://schemas.android.com/apk/res/android"


class AxmlWriter:
    """Encode a simple element/attribute tree as Android binary XML."""

    def __init__(self) -> None:
        self._strings: list[str] = []
        self._index: dict[str, int] = {}
        self._elements: list[tuple] = []  # flat list of events
        self._ns_prefix = "android"
        self._ns_uri = ANDROID_NS
        # ensure common strings exist
        for s in ("android", ANDROID_NS, "http://schemas.android.com/apk/res/auto"):
            self.intern(s)

    def intern(self, s: str) -> int:
        if s in self._index:
            return self._index[s]
        idx = len(self._strings)
        self._strings.append(s)
        self._index[s] = idx
        return idx

    # tree building -------------------------------------------------------
    def start(self, name: str, attrs: list[tuple[str, str, object]]) -> None:
        self._elements.append(("start", name, attrs))

    def end(self, name: str) -> None:
        self._elements.append(("end", name, []))

    # encoding ------------------------------------------------------------
    def _encode_string_pool(self) -> bytes:
        strs = self._strings
        offsets = []
        data = bytearray()
        for s in strs:
            offsets.append(len(data))
            encoded = s.encode("utf-8")
            # char length prefix
            char_len = len(s)
            if char_len > 0x7F:
                data.append(0x80 | ((char_len >> 8) & 0x7F))
                data.append(char_len & 0xFF)
            else:
                data.append(char_len)
            # byte length prefix
            byte_len = len(encoded)
            if byte_len > 0x7F:
                data.append(0x80 | ((byte_len >> 8) & 0x7F))
                data.append(byte_len & 0xFF)
            else:
                data.append(byte_len)
            data += encoded
            data.append(0x00)  # NUL
        # 4-byte align
        while len(data) % 4:
            data.append(0x00)

        header_size = 28   # 8-byte chunk header + 5 uint32 fields
        strings_start = header_size + 4 * len(offsets)
        fields = struct.pack("<IIIII", len(offsets), 0, UTF8_FLAG, strings_start, 0)
        offset_bytes = b"".join(struct.pack("<I", o) for o in offsets)
        # size = full chunk: header(8) + fields(20) + offsets + data
        chunk_size = header_size + 4 * len(offsets) + len(data)
        header = struct.pack("<HHI", RES_STRING_POOL_CHUNK, header_size, chunk_size)
        return bytes(header) + fields + offset_bytes + bytes(data)

    def _chunk_header(self, ctype: int, hdr_size: int, size: int) -> bytes:
        return struct.pack("<HHI", ctype, hdr_size, size)

    def encode(self) -> bytes:
        # Pass 1: intern every element/attribute name BEFORE snapshotting the
        # string pool, so all indices referenced by chunks exist in the pool.
        for ev, name, attrs in self._elements:
            self.intern(name)
            for a_attr in attrs:
                if len(a_attr) == 3:
                    a_name, a_ns, _a_val = a_attr
                else:
                    a_name, _a_val = a_attr
                    a_ns = "android"
                self.intern(a_name)
                # string attribute values also live in the pool
                if not isinstance(_a_val, (bool, int)):
                    self.intern(str(_a_val))

        pool = self._encode_string_pool()

        chunks = bytearray()
        chunks += self._ns_chunk(RES_XML_START_NAMESPACE_CHUNK)

        for ev, name, attrs in self._elements:
            if ev == "start":
                chunks += self._start_chunk(name, attrs)
            else:
                chunks += self._end_chunk(name)

        chunks += self._ns_chunk(RES_XML_END_NAMESPACE_CHUNK)

        # full file = xml header (8) + pool + element chunks
        total = 8 + len(pool) + len(chunks)
        header = self._chunk_header(RES_XML_CHUNK, 8, total)
        return bytes(header) + pool + bytes(chunks)

    def _ns_chunk(self, ctype: int) -> bytes:
        size = 24
        hdr = self._chunk_header(ctype, 16, size)
        node = struct.pack("<II", 1, 0xFFFFFFFF)  # line, comment
        body = struct.pack("<II", self.intern(self._ns_prefix), self.intern(self._ns_uri))
        return hdr + node + body

    def _start_chunk(self, name: str, attrs: list[tuple[str, str, object]]) -> bytes:
        # attribute extension
        ext = bytearray()
        ext += struct.pack("<II", 0xFFFFFFFF, self.intern(name))  # ns, name
        ext += struct.pack("<HHHHHH", 20, 20, len(attrs), 0, 0, 0)  # attrStart..style
        for a_attr in attrs:
            if len(a_attr) == 3:
                a_name, a_ns, a_val = a_attr
            else:
                a_name, a_val = a_attr
                a_ns = "android"
            # Real AXML stores the BARE local name; the namespace is carried
            # in the separate ns field (prefixing is only for text XML).
            ns_idx = self.intern(self._ns_uri) if a_ns == "android" else 0xFFFFFFFF
            name_idx = self.intern(a_name)
            if isinstance(a_val, bool):
                vtype = TYPE_INT_BOOLEAN
                vdata = 0xFFFFFFFF if a_val else 0x00000000
                raw = 0xFFFFFFFF
            elif isinstance(a_val, int):
                vtype = TYPE_INT_DEC
                vdata = a_val & 0xFFFFFFFF
                raw = 0xFFFFFFFF
            else:
                vtype = TYPE_STRING
                raw = self.intern(str(a_val))
                vdata = raw
            ext += struct.pack("<III", ns_idx, name_idx, raw)
            ext += struct.pack("<HBBI", 8, 0, vtype, vdata)

        node = struct.pack("<II", 1, 0xFFFFFFFF)  # line, comment
        hdr_size = 16   # 8-byte chunk header + 8-byte node (line/comment)
        size = hdr_size + len(ext)
        hdr = self._chunk_header(RES_XML_START_ELEMENT_CHUNK, hdr_size, size)
        return bytes(hdr) + node + bytes(ext)

    def _end_chunk(self, name: str) -> bytes:
        node = struct.pack("<II", 1, 0xFFFFFFFF)
        ext = struct.pack("<II", 0xFFFFFFFF, self.intern(name))
        hdr = self._chunk_header(RES_XML_END_ELEMENT_CHUNK, 16, 16 + len(ext))
        return hdr + node + ext


def build_manifest_xml(package: str,
                       version_name: str,
                       version_code: int,
                       min_sdk: int,
                       target_sdk: int,
                       permissions: list[str],
                       application_attrs: list[tuple[str, str, object]],
                       extra_elements: list | None = None) -> bytes:
    w = AxmlWriter()
    w.start("manifest", [
        ("package", None, package),
        ("versionName", None, version_name),
        ("versionCode", None, version_code),
    ])
    w.start("uses-sdk", [
        ("minSdkVersion", None, min_sdk),
        ("targetSdkVersion", None, target_sdk),
    ])
    w.end("uses-sdk")

    for perm in permissions:
        # split dotted names for realism? manifest uses full dotted string
        w.start("uses-permission", [("name", None, perm)])
        w.end("uses-permission")

    w.start("application", application_attrs)
    # launcher activity
    w.start("activity", [("name", ".MainActivity"), ("exported", "true")])
    w.start("intent-filter", [])
    w.start("action", [("name", "android.intent.action.MAIN")])
    w.end("action")
    w.start("category", [("name", "android.intent.category.LAUNCHER")])
    w.end("category")
    w.end("intent-filter")
    w.end("activity")

    for el in (extra_elements or []):
        w.start(el.get("tag", "activity"), el.get("attrs", []))
        w.end(el.get("tag", "activity"))

    w.end("application")
    w.end("manifest")
    return w.encode()


def minimal_dex() -> bytes:
    """A tiny, structurally valid-enough DEX with a couple of strings."""
    # Not a runnable DEX — only the header + string table shape our scanner
    # reads. Clearly synthetic.
    header_size = 0x70
    strings = [
        "Lcom/example/app/MainActivity;",
        "<init>",
        "http://schemas.android.com/apk/res/android",
        "com.example.synthetic",
    ]
    # string data section
    data = bytearray()
    offsets = []
    for s in strings:
        offsets.append(header_size + len(data))
        b = s.encode("utf-8")
        # uleb128 utf16_size (approximate = char count)
        n = len(s)
        while True:
            if n < 0x80:
                data.append(n)
                break
            data.append(0x80 | (n & 0x7F))
            n >>= 7
        data += b + b"\x00"

    string_ids_off = header_size
    string_ids_size = len(strings)
    data_off = string_ids_off + 4 * string_ids_size

    header = bytearray(header_size)
    header[0:8] = b"dex\n035\x00"
    struct.pack_into("<I", header, 0x38, string_ids_size)
    struct.pack_into("<I", header, 0x3C, string_ids_off)
    struct.pack_into("<I", header, 0x40, 0)   # type_ids_size
    struct.pack_into("<I", header, 0x44, 0)
    total = data_off + len(data)
    struct.pack_into("<I", header, 0x20, total)

    # buffer must include header + string-id table + data
    out = bytearray(header)
    out += bytearray(4 * string_ids_size)
    # absolute file offsets for each string's data
    for i, off in enumerate(offsets):
        # offsets were stored as header_size + position_in_data
        struct.pack_into("<I", out, string_ids_off + i * 4, data_off + (off - header_size))
    out += data
    return bytes(out)


def dex_with_indicators() -> bytes:
    """DEX whose strings contain root/escalation indicators for tests."""
    header_size = 0x70
    strings = [
        "Lcom/example/torch/MainActivity;",
        "/system/xbin/su",
        "magisk",
        "Runtime.getRuntime().exec",
        "/proc/kallsyms",
        "chmod 755",
        "getenforce",
        "cve-2016-5195",
        "Lcom/example/torch/TorchService;",
        "setprop",
    ]
    data = bytearray()
    offsets = []
    for s in strings:
        offsets.append(len(data))
        b = s.encode("utf-8")
        n = len(s)
        while True:
            if n < 0x80:
                data.append(n)
                break
            data.append(0x80 | (n & 0x7F))
            n >>= 7
        data += b + b"\x00"

    string_ids_off = header_size
    string_ids_size = len(strings)
    data_off = string_ids_off + 4 * string_ids_size

    header = bytearray(header_size)
    header[0:8] = b"dex\n035\x00"
    struct.pack_into("<I", header, 0x38, string_ids_size)
    struct.pack_into("<I", header, 0x3C, string_ids_off)
    total = data_off + len(data)
    struct.pack_into("<I", header, 0x20, total)
    struct.pack_into("<I", header, 0x70 - 4, data_off)

    out = bytearray(header)
    out += bytearray(4 * string_ids_size)   # string-id table space
    for i, off in enumerate(offsets):
        struct.pack_into("<I", out, string_ids_off + i * 4, data_off + off)
    out += data
    return bytes(out)


def build_apk(path: str,
              package: str,
              version_name: str,
              version_code: int,
              min_sdk: int,
              target_sdk: int,
              permissions: list[str],
              application_attrs: list[tuple[str, str, object]],
              extra_elements: list | None = None,
              dex: bytes | None = None,
              extra_files: dict[str, bytes] | None = None) -> str:
    manifest = build_manifest_xml(
        package, version_name, version_code, min_sdk, target_sdk,
        permissions, application_attrs, extra_elements
    )
    dex = dex if dex is not None else minimal_dex()

    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", manifest)
        zf.writestr("classes.dex", dex)
        zf.writestr("META-INF/MANIFEST.MF",
                    "Manifest-Version: 1.0\r\nCreated-By: PermissionGuard fixtures\r\n\r\n")
        zf.writestr("res/values/strings.xml",
                    '<?xml version="1.0" encoding="utf-8"?>\n<resources/>\n')
        for name, blob in (extra_files or {}).items():
            zf.writestr(name, blob)
    return path


# ---------------------------------------------------------------------------
# The five synthetic fixtures (labelled SYNTHETIC in their metadata)
# ---------------------------------------------------------------------------

FIXTURES = {
    # 1. Calculator — minimal, no sensitive permissions -> LOW
    "calculator": dict(
        package="com.synthetic.calculator",
        version_name="1.0-synthetic",
        version_code=1,
        min_sdk=26,
        target_sdk=34,
        permissions=[
            "android.permission.VIBRATE",
        ],
        application_attrs=[
            ("label", "Synthetic Calculator"),
            ("allowBackup", "true"),
            ("debuggable", "false"),
        ],
        dex=minimal_dex(),
        expected_risk="LOW",
        expected_verdicts={"android.permission.VIBRATE": "JUSTIFIED"},
    ),
    # 2. Navigation — location justified -> LOW/MEDIUM
    "navigation": dict(
        package="com.synthetic.navigation",
        version_name="2.1-synthetic",
        version_code=21,
        min_sdk=26,
        target_sdk=34,
        permissions=[
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.INTERNET",
            "android.permission.ACCESS_NETWORK_STATE",
            "android.permission.VIBRATE",
            "android.permission.WAKE_LOCK",
            "android.permission.FOREGROUND_SERVICE",
        ],
        application_attrs=[
            ("label", "Synthetic Navigator"),
            ("allowBackup", "false"),
            ("debuggable", "false"),
        ],
        dex=minimal_dex(),
        expected_risk="LOW",
        expected_verdicts={
            "android.permission.ACCESS_FINE_LOCATION": "JUSTIFIED",
            "android.permission.INTERNET": "JUSTIFIED",
        },
    ),
    # 3. Voice recorder — mic justified -> LOW/MEDIUM
    "voice_recorder": dict(
        package="com.synthetic.voicerecorder",
        version_name="3.0-synthetic",
        version_code=30,
        min_sdk=26,
        target_sdk=34,
        permissions=[
            "android.permission.RECORD_AUDIO",
            "android.permission.FOREGROUND_SERVICE",
            "android.permission.POST_NOTIFICATIONS",
            "android.permission.WAKE_LOCK",
        ],
        application_attrs=[
            ("label", "Synthetic Voice Recorder"),
            ("allowBackup", "false"),
            ("debuggable", "false"),
        ],
        dex=minimal_dex(),
        expected_risk="LOW",
        expected_verdicts={"android.permission.RECORD_AUDIO": "JUSTIFIED"},
    ),
    # 4. Photo editor — media access + ONE unexplained extra (mic) -> MEDIUM
    "photo_editor": dict(
        package="com.synthetic.photoeditor",
        version_name="5.2-synthetic",
        version_code=52,
        min_sdk=26,
        target_sdk=34,
        permissions=[
            "android.permission.READ_MEDIA_IMAGES",
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO",   # <-- unexplained extra
            "android.permission.INTERNET",
        ],
        application_attrs=[
            ("label", "Synthetic Photo Editor"),
            ("allowBackup", "false"),
            ("debuggable", "false"),
        ],
        dex=minimal_dex(),
        expected_risk="MEDIUM",
        expected_findings=["PG-PURPOSE-CRITICAL"],   # rule id uses tier name;
        #                                                     severity is HIGH (1 unexpected)
        expected_verdicts={
            "android.permission.READ_MEDIA_IMAGES": "JUSTIFIED",
            "android.permission.RECORD_AUDIO": "UNEXPECTED",
        },
    ),
    # 5. Shopping — realistic, near-minimal permission set -> MEDIUM (~40)
    "shopping": dict(
        package="com.synthetic.shop",
        version_name="1.0-synthetic",
        version_code=10,
        min_sdk=26,
        target_sdk=34,
        permissions=[
            "android.permission.INTERNET",               # core: browsing / checkout
            "android.permission.ACCESS_NETWORK_STATE",   # optional: connectivity checks
            "android.permission.POST_NOTIFICATIONS",      # optional: order alerts
            "android.permission.CAMERA",                  # optional: barcode / cheque scan
            "android.permission.READ_MEDIA_IMAGES",       # optional: pick product photo
            "android.permission.ACCESS_FINE_LOCATION",    # optional: delivery estimate
            "android.permission.ACCESS_COARSE_LOCATION",  # optional: city-level location
        ],
        application_attrs=[
            ("label", "Synthetic Shop"),
            ("allowBackup", "false"),
            ("debuggable", "false"),
        ],
        dex=minimal_dex(),
        expected_risk="MEDIUM",
        expected_verdicts={
            "android.permission.INTERNET": "JUSTIFIED",
            "android.permission.ACCESS_NETWORK_STATE": "JUSTIFIED",
            "android.permission.POST_NOTIFICATIONS": "JUSTIFIED",
            "android.permission.CAMERA": "JUSTIFIED",
            "android.permission.READ_MEDIA_IMAGES": "PLAUSIBLE",
            "android.permission.ACCESS_FINE_LOCATION": "PLAUSIBLE",
            "android.permission.ACCESS_COARSE_LOCATION": "PLAUSIBLE",
        },
    ),
    # 6. Flashlight — deliberately over-privileged -> HIGH
    "flashlight_overprivileged": dict(
        package="com.synthetic.flashlight",
        version_name="9.9-synthetic",
        version_code=99,
        min_sdk=24,
        target_sdk=33,
        permissions=[
            "android.permission.CAMERA",                 # expected (LED)
            "android.permission.READ_CONTACTS",          # excess
            "android.permission.ACCESS_FINE_LOCATION",   # excess
            "android.permission.ACCESS_BACKGROUND_LOCATION",  # excess
            "android.permission.READ_SMS",               # excess (org-denied)
            "android.permission.INTERNET",               # excess channel
            "android.permission.READ_CALL_LOG",          # excess (org-denied)
            "android.permission.RECORD_AUDIO",           # excess
            "android.permission.RECEIVE_BOOT_COMPLETED", # persistence
        ],
        application_attrs=[
            ("label", "Synthetic Flashlight"),
            ("allowBackup", "true"),
            ("debuggable", "true"),                      # escalation signal
            ("usesCleartextTraffic", "true"),
        ],
        extra_elements=[
            {"tag": "service",
             "attrs": [("name", ".StealthService"), ("exported", "true")]},
            {"tag": "receiver",
             "attrs": [("name", ".BootReceiver"), ("exported", "true")]},
        ],
        dex=dex_with_indicators(),     # root/escalation strings for deep scan
        extra_files={"assets/helper": b"\x7fELF\x02\x01\x01" + b"\x00" * 40},
        expected_risk="HIGH",
        expected_findings=["PG-PURPOSE-CRITICAL", "ORG-DENY-001", "ESC-DEBUG-001"],
        expected_verdicts={
            # reviewed ground truth: a flashlight needs only CAMERA (LED);
            # every other declared permission is over-privilege
            "android.permission.CAMERA": "JUSTIFIED",
            "android.permission.READ_CONTACTS": "UNEXPECTED",
            "android.permission.READ_SMS": "UNEXPECTED",
            "android.permission.READ_CALL_LOG": "UNEXPECTED",
            "android.permission.ACCESS_FINE_LOCATION": "UNEXPECTED",
            "android.permission.ACCESS_BACKGROUND_LOCATION": "UNEXPECTED",
            "android.permission.RECORD_AUDIO": "UNEXPECTED",
            "android.permission.INTERNET": "UNEXPECTED",
            "android.permission.RECEIVE_BOOT_COMPLETED": "UNEXPECTED",
        },
    ),
}


def main(out_dir: str) -> None:
    built = []
    for key, spec in FIXTURES.items():
        path = os.path.join(out_dir, f"{key}.apk")
        build_apk(
            path=path,
            package=spec["package"],
            version_name=spec["version_name"],
            version_code=spec["version_code"],
            min_sdk=spec["min_sdk"],
            target_sdk=spec["target_sdk"],
            permissions=spec["permissions"],
            application_attrs=spec["application_attrs"],
            extra_elements=spec.get("extra_elements"),
            dex=spec.get("dex"),
            extra_files=spec.get("extra_files"),
        )
        built.append(path)
        print(f"built {path} ({os.path.getsize(path)} bytes)")

    # expectations file (used by tests + evaluation harness)
    import json
    expectations = {}
    for key, spec in FIXTURES.items():
        expectations[key] = {
            "file": f"{key}.apk",
            "synthetic": True,
            "package": spec["package"],
            "expected_risk": spec["expected_risk"],
            "expected_findings": spec.get("expected_findings", []),
            "expected_verdicts": spec.get("expected_verdicts", {}),
            "permissions": spec["permissions"],
            "justification": _justification(key),
        }
    epath = os.path.join(out_dir, "expectations.json")
    with open(epath, "w", encoding="utf-8") as fh:
        json.dump(expectations, fh, indent=2)
    print(f"built {epath}")


def _justification(key: str) -> str:
    return {
        "calculator": "Local computation only — VIBRATE is normal-tier and expected. No sensitive permission should appear; risk must be LOW.",
        "navigation": "Location IS the core input of navigation, and INTERNET/WAKE_LOCK/FOREGROUND_SERVICE support it. All are category-expected, so no over-privilege finding is expected; risk must be LOW.",
        "voice_recorder": "RECORD_AUDIO is the defining capability of a recorder; foreground service + notification keep it user-visible. All expected; risk must be LOW.",
        "photo_editor": "READ_MEDIA_IMAGES + CAMERA are expected for editing. RECORD_AUDIO (microphone) has no photo-editing function — must be flagged UNEXPECTED with HIGH sensitivity -> purpose finding expected; risk must be MEDIUM.",
        "shopping": "A realistic shopping app: INTERNET + network-state + notifications are core; CAMERA (barcode/cheque), READ_MEDIA_IMAGES (product photo) and coarse/fine location (delivery estimate) are all optional-but-plausible for this category. No permission is UNEXPECTED — verdicts are JUSTIFIED/PLAUSIBLE — but the file+network combo and disclosure checks keep the score in the MEDIUM band (~40).",
        "flashlight_overprivileged": "Deliberately over-privileged: a flashlight needs only CAMERA (LED control). Contacts, SMS, call log, fine+background location, microphone, internet and boot-receiver are all over-privilege for this category; SMS/call log violate the default org policy deny-list; debuggable=true triggers the escalation check; DEX strings trigger kernel/root deep-scan checks; a staged ELF asset is present. Risk must be HIGH.",
    }.get(key, "")


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "data", "sampleapps"
    )
    main(target)
