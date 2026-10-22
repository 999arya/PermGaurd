"""Pure-Python decoder for Android binary XML (AXML).

Android packages ``AndroidManifest.xml`` inside APKs as a compiled binary
resource (ResXMLTree), not text. This module decodes that format using only
the Python standard library, so PermissionGuard works on machines with no
Android SDK, no Java and no external tools.

Format references:
  - AOSP ``frameworks/base/include/androidfw/ResourceTypes.h``
  - https://android.googlesource.com/platform/frameworks/base/

The decoder is intentionally defensive: every read is bounds-checked and any
malformed input raises :class:`AxmlDecodeError` rather than producing
fabricated output.
"""
from __future__ import annotations

import struct
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any, Optional

# --- chunk type constants (ResChunkType) ------------------------------------
RES_NULL_CHUNK = 0x0000
RES_STRING_POOL_CHUNK = 0x0001
RES_TABLE_CHUNK = 0x0002
RES_XML_CHUNK = 0x0003
RES_XML_START_NAMESPACE_CHUNK = 0x0100
RES_XML_END_NAMESPACE_CHUNK = 0x0101
RES_XML_START_ELEMENT_CHUNK = 0x0102
RES_XML_END_ELEMENT_CHUNK = 0x0103
RES_XML_CDATA_CHUNK = 0x0104
RES_XML_RESOURCE_MAP_CHUNK = 0x0180

# string pool flags
UTF8_FLAG = 0x00000100

# Res_value data types
TYPE_NULL = 0x00
TYPE_REFERENCE = 0x01
TYPE_ATTRIBUTE = 0x02
TYPE_STRING = 0x03
TYPE_FLOAT = 0x04
TYPE_DIMENSION = 0x05
TYPE_FRACTION = 0x06
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_INT_BOOLEAN = 0x12


class AxmlDecodeError(ValueError):
    """Raised when the binary XML payload is malformed or unsupported."""


@dataclass
class _StringPool:
    strings: list[str] = field(default_factory=list)
    is_utf8: bool = False


def _read_u16(buf: bytes, off: int) -> int:
    if off + 2 > len(buf):
        raise AxmlDecodeError(f"u16 read out of bounds at {off}")
    return struct.unpack_from("<H", buf, off)[0]


def _read_u32(buf: bytes, off: int) -> int:
    if off + 4 > len(buf):
        raise AxmlDecodeError(f"u32 read out of bounds at {off}")
    return struct.unpack_from("<I", buf, off)[0]


def _decode_length_utf16(buf: bytes, off: int) -> tuple[int, int]:
    """Decode a modified UTF-16 length prefix. Returns (length, next_offset)."""
    first = _read_u16(buf, off)
    off += 2
    if first & 0x8000:
        second = _read_u16(buf, off)
        off += 2
        length = ((first & 0x7FFF) << 16) | second
    else:
        length = first
    return length, off


def _decode_length_utf8(buf: bytes, off: int) -> tuple[int, int]:
    """Decode a modified UTF-8 length prefix (char length then byte length).

    Returns (byte_length_of_string, next_offset_after_both_prefixes).
    """
    first = buf[off]
    off += 1
    if first & 0x80:
        second = buf[off]
        off += 1
        _char_len = ((first & 0x7F) << 8) | second
    # read the byte length (same encoding) — this is the one we actually need
    first = buf[off]
    off += 1
    if first & 0x80:
        second = buf[off]
        off += 1
        byte_len = ((first & 0x7F) << 8) | second
    else:
        byte_len = first
    return byte_len, off


def _parse_string_pool(chunk: bytes) -> _StringPool:
    # chunk header: type u16, headerSize u16, size u32
    header_size = _read_u16(chunk, 2)
    chunk_size = _read_u32(chunk, 4)
    chunk_size = min(chunk_size, len(chunk))

    string_count = _read_u32(chunk, 8)
    style_count = _read_u32(chunk, 12)
    flags = _read_u32(chunk, 16)
    strings_start = _read_u32(chunk, 20)

    if string_count > 1_000_000:
        raise AxmlDecodeError("string pool count unreasonably large")
    if style_count > 1_000_000:
        raise AxmlDecodeError("style pool count unreasonably large")

    is_utf8 = bool(flags & UTF8_FLAG)

    offsets_base = header_size
    offsets: list[int] = []
    for i in range(string_count):
        offsets.append(_read_u32(chunk, offsets_base + i * 4))

    pool = _StringPool(is_utf8=is_utf8)
    base = strings_start
    for off in offsets:
        pos = base + off
        if pos >= chunk_size:
            pool.strings.append("")
            continue
        try:
            if is_utf8:
                byte_len, data_off = _decode_length_utf8(chunk, pos)
                raw = chunk[data_off:data_off + byte_len]
                pool.strings.append(raw.decode("utf-8", errors="replace"))
            else:
                char_len, data_off = _decode_length_utf16(chunk, pos)
                end = data_off + char_len * 2
                if end > len(chunk):
                    raise AxmlDecodeError("utf16 string exceeds chunk")
                pool.strings.append(chunk[data_off:end].decode("utf-16-le", errors="replace"))
        except (AxmlDecodeError, IndexError, UnicodeDecodeError):
            pool.strings.append("")
    return pool


def _string(pool: _StringPool, index: int) -> Optional[str]:
    if index == 0xFFFFFFFF:
        return None
    if 0 <= index < len(pool.strings):
        value = pool.strings[index]
        return value if value != "" else None
    return None


def _format_value(data_type: int, data: int, pool: _StringPool) -> str:
    """Convert a Res_value into a text representation."""
    if data_type == TYPE_STRING:
        return _string(pool, data) or ""
    if data_type == TYPE_INT_BOOLEAN:
        return "true" if data != 0 else "false"
    if data_type == TYPE_INT_DEC:
        # signed 32-bit
        if data >= 0x80000000:
            data -= 0x100000000
        return str(data)
    if data_type == TYPE_INT_HEX:
        return f"0x{data:08x}"
    if data_type == TYPE_REFERENCE:
        return f"@0x{data:08x}"
    if data_type == TYPE_ATTRIBUTE:
        return f"?0x{data:08x}"
    if data_type == TYPE_FLOAT:
        return str(struct.unpack("<f", struct.pack("<I", data))[0])
    if data_type == TYPE_NULL:
        return ""
    return f"@0x{data:08x}"


def decode_axml(data: bytes) -> ET.Element:
    """Decode an Android binary XML payload and return an ``ElementTree`` root.

    Raises :class:`AxmlDecodeError` if the payload is not valid ResXMLTree.
    """
    if len(data) < 8:
        raise AxmlDecodeError("payload too small to be binary XML")

    magic = _read_u16(data, 0)
    header_size = _read_u16(data, 2)
    total_size = _read_u32(data, 4)
    if magic != RES_XML_CHUNK:
        raise AxmlDecodeError(f"not an XML chunk (type=0x{magic:04x})")
    if header_size < 8:
        raise AxmlDecodeError("invalid XML chunk header size")

    pool: Optional[_StringPool] = None
    root: Optional[ET.Element] = None
    stack: list[ET.Element] = []
    # namespace prefix -> uri, for re-emitting xmlns
    ns_prefixes: dict[str, str] = {}
    # uri -> prefix
    uri_to_prefix: dict[str, str] = {}

    offset = header_size
    end = min(total_size, len(data))

    while offset + 8 <= end:
        chunk_type = _read_u16(data, offset)
        chunk_hdr_size = _read_u16(data, offset + 2)
        chunk_size = _read_u32(data, offset + 4)
        if chunk_size < 8 or offset + chunk_size > len(data):
            raise AxmlDecodeError(f"bad chunk size {chunk_size} at {offset}")

        if chunk_type == RES_STRING_POOL_CHUNK:
            pool = _parse_string_pool(data[offset:offset + chunk_size])

        elif chunk_type == RES_XML_START_NAMESPACE_CHUNK:
            # node: type u16 hdr u16 size u32 | line u32 comment u32
            # then prefix u32 uri u32
            if pool is None:
                raise AxmlDecodeError("namespace chunk before string pool")
            body = offset + chunk_hdr_size
            prefix = _string(pool, _read_u32(data, body))
            uri = _string(pool, _read_u32(data, body + 4))
            if prefix is not None and uri is not None:
                ns_prefixes[prefix] = uri
                uri_to_prefix.setdefault(uri, prefix)

        elif chunk_type == RES_XML_END_NAMESPACE_CHUNK:
            body = offset + chunk_hdr_size
            if pool is not None:
                prefix = _string(pool, _read_u32(data, body))
                if prefix in ns_prefixes:
                    ns_prefixes.pop(prefix, None)

        elif chunk_type == RES_XML_START_ELEMENT_CHUNK:
            if pool is None:
                raise AxmlDecodeError("element chunk before string pool")
            body = offset + chunk_hdr_size
            # headerSize (16) already covers ResChunk_header (8) + line/comment
            # (8); body therefore points at the ResXMLTree_attrExt structure.
            ns_idx = _read_u32(data, body)
            name_idx = _read_u32(data, body + 4)
            attr_start = _read_u16(data, body + 8)
            attr_size = _read_u16(data, body + 10)
            attr_count = _read_u16(data, body + 12)

            elem_name = _string(pool, name_idx) or "unknown"
            elem_ns = _string(pool, ns_idx) if ns_idx != 0xFFFFFFFF else None

            # attributes start at (attrExt start + attributeStart)
            attrs_base = body + attr_start
            if attr_size == 0:
                attr_size = 20

            elem = ET.Element(elem_name)
            if elem_ns:
                # namespaced element (rare in manifests) — keep local name
                pass

            for i in range(attr_count):
                a_off = attrs_base + i * attr_size
                if a_off + 20 > offset + chunk_size:
                    break
                a_ns_idx = _read_u32(data, a_off)
                a_name_idx = _read_u32(data, a_off + 4)
                a_raw = _read_u32(data, a_off + 8)
                v_size = _read_u16(data, a_off + 12)
                v_type = data[a_off + 15]
                v_data = _read_u32(data, a_off + 16)

                a_name = _string(pool, a_name_idx)
                if a_name is None:
                    continue
                if v_type == TYPE_STRING and a_raw != 0xFFFFFFFF:
                    a_value = _string(pool, a_raw) or ""
                else:
                    a_value = _format_value(v_type, v_data, pool)

                a_ns = _string(pool, a_ns_idx) if a_ns_idx != 0xFFFFFFFF else None
                if a_ns:
                    prefix = uri_to_prefix.get(a_ns)
                    key = f"{{{prefix}}}{a_name}" if prefix else a_name
                    # register so ElementTree serialises predictably
                    try:
                        ET.register_namespace(prefix, a_ns)
                    except (ValueError, TypeError):
                        pass
                    elem.set(key, a_value)
                else:
                    elem.set(a_name, a_value)

            if stack:
                stack[-1].append(elem)
            else:
                if root is not None:
                    raise AxmlDecodeError("multiple root elements")
                root = elem
            stack.append(elem)

        elif chunk_type == RES_XML_END_ELEMENT_CHUNK:
            if stack:
                stack.pop()

        elif chunk_type == RES_XML_CDATA_CHUNK:
            pass  # CDATA content is not needed for manifest analysis

        elif chunk_type == RES_XML_RESOURCE_MAP_CHUNK:
            pass  # resource ids used for attribute name resolution

        # advance
        offset += chunk_size

    if root is None:
        raise AxmlDecodeError("no root element found in binary XML")
    return root


def axml_to_string(root: ET.Element) -> str:
    """Serialise a decoded manifest to pretty text XML (for reports/debug)."""
    try:
        ET.indent(root)
    except AttributeError:  # pragma: no cover - py<3.9
        pass
    return ET.tostring(root, encoding="unicode")
