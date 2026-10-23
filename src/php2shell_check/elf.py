"""Read zif_system / zval_ptr_dtor offsets from libphp.so."""
from __future__ import annotations

import shutil
import struct
import subprocess
import tempfile
from pathlib import Path

SHT_SYMTAB = 2
SHT_DYNSYM = 11
PT_LOAD = 1


class ElfError(RuntimeError):
    pass


def symbol_offsets(path: Path, wanted: set[str]) -> dict[str, int]:
    data = path.read_bytes()
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        raise ElfError("not a little-endian ELF64 file: %s" % path)

    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)
    e_shentsize, e_shnum = struct.unpack_from("<HH", data, 0x3A)

    loads: list[int] = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type = struct.unpack_from("<I", data, off)[0]
        p_vaddr = struct.unpack_from("<Q", data, off + 16)[0]
        p_memsz = struct.unpack_from("<Q", data, off + 40)[0]
        if p_type == PT_LOAD and p_memsz:
            loads.append(p_vaddr)
    if not loads:
        raise ElfError("no PT_LOAD segment")
    bias = min(loads)

    sections = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh_name, sh_type = struct.unpack_from("<II", data, off)
        sh_offset, sh_size = struct.unpack_from("<QQ", data, off + 24)
        sh_link = struct.unpack_from("<I", data, off + 40)[0]
        sh_entsize = struct.unpack_from("<Q", data, off + 56)[0]
        sections.append({
            "type": sh_type, "offset": sh_offset, "size": sh_size,
            "link": sh_link, "entsize": sh_entsize,
        })

    found: dict[str, int] = {}
    for section in sections:
        if section["type"] not in (SHT_SYMTAB, SHT_DYNSYM):
            continue
        link = section["link"]
        if link >= len(sections):
            continue
        strtab = sections[link]
        entsize = section["entsize"] or 24
        count = section["size"] // entsize
        for i in range(count):
            off = section["offset"] + i * entsize
            st_name = struct.unpack_from("<I", data, off)[0]
            st_value = struct.unpack_from("<Q", data, off + 8)[0]
            if not st_name or not st_value:
                continue
            name_off = strtab["offset"] + st_name
            end = data.find(b"\x00", name_off)
            if end < 0:
                continue
            name = data[name_off:end].decode("ascii", "replace")
            if name in wanted and name not in found:
                found[name] = st_value - bias

    missing = wanted - found.keys()
    if missing:
        raise ElfError("symbols not found: " + ", ".join(sorted(missing)))
    return found


def copy_libphp(container: str, dest: Path,
                candidates: tuple[str, ...] = (
                    "/usr/lib/apache2/modules/libphp.so",
                    "/usr/local/lib/libphp.so",
                )) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    last_error = ""
    for remote in candidates:
        result = subprocess.run(
            ["docker", "cp", f"{container}:{remote}", str(dest)],
            capture_output=True, text=True,
        )
        if result.returncode == 0:
            return dest
        last_error = result.stderr.strip()
    raise ElfError("cannot copy libphp.so from %s: %s" % (container, last_error))


def offsets_from_container(container: str) -> dict[str, int]:
    with tempfile.TemporaryDirectory(prefix="p2s-elf-") as tmp:
        path = copy_libphp(container, Path(tmp) / "libphp.so")
        return symbol_offsets(path, {"zif_system", "zval_ptr_dtor"})
