# Small ELF reader: needed libraries, soname and whether the file has an interpreter.
# Every offset and size is checked against the file length, so a broken or
# hostile file ends in ElfError instead of a crash or a long loop.
import struct

MAX_PHDRS = 4096
MAX_DYNAMIC = 8192
MAX_NEEDED = 256
MAX_NAME = 256

PT_LOAD, PT_DYNAMIC, PT_INTERP = 1, 2, 3
DT_NULL, DT_NEEDED, DT_STRTAB, DT_SONAME = 0, 1, 5, 14


class ElfError(Exception):
    pass


def _read_at(handle, size, offset, length):
    if offset < 0 or length < 0 or offset + length > size:
        raise ElfError("offset outside the file")
    handle.seek(offset)
    data = handle.read(length)
    if len(data) != length:
        raise ElfError("short read")
    return data


def _c_string(handle, size, offset):
    data = _read_at(handle, size, offset, min(MAX_NAME, size - offset))
    end = data.find(b"\0")
    if end < 0:
        raise ElfError("unterminated string")
    return data[:end].decode("utf-8", "replace")


def read_elf(handle, size):
    """Return {needed, soname, has_interp} or None when the file is not ELF."""
    if size < 64 or _read_at(handle, size, 0, 4) != b"\x7fELF":
        return None
    header = _read_at(handle, size, 0, 64)
    if header[4] != 2 or header[5] != 1:
        raise ElfError("only 64-bit little-endian ELF is supported")
    phoff, = struct.unpack_from("<Q", header, 32)
    phentsize, phnum = struct.unpack_from("<HH", header, 54)
    if phnum > MAX_PHDRS or (phnum and phentsize < 56):
        raise ElfError("bad program header table")
    loads, dynamic, has_interp = [], None, False
    for index in range(phnum):
        raw = _read_at(handle, size, phoff + index * phentsize, 56)
        ptype, _flags, offset, vaddr, _paddr, filesz, _memsz, _align = struct.unpack("<IIQQQQQQ", raw)
        if ptype == PT_LOAD:
            loads.append((vaddr, offset, filesz))
        elif ptype == PT_DYNAMIC:
            dynamic = (offset, filesz)
        elif ptype == PT_INTERP:
            has_interp = True
    result = {"needed": [], "soname": None, "has_interp": has_interp}
    if dynamic is None:
        return result
    offset, length = dynamic
    if length // 16 > MAX_DYNAMIC:
        raise ElfError("dynamic section too big")
    raw = _read_at(handle, size, offset, length - length % 16)
    needed_offsets, soname_offset, strtab = [], None, None
    for pos in range(0, len(raw), 16):
        tag, value = struct.unpack_from("<qQ", raw, pos)
        if tag == DT_NULL:
            break
        if tag == DT_NEEDED:
            if len(needed_offsets) >= MAX_NEEDED:
                raise ElfError("too many needed libraries")
            needed_offsets.append(value)
        elif tag == DT_SONAME:
            soname_offset = value
        elif tag == DT_STRTAB:
            strtab = value
    if strtab is None:
        return result
    # DT_STRTAB is a virtual address; find the segment that holds it
    base = next((off + strtab - va for va, off, fsz in loads if va <= strtab < va + fsz), None)
    if base is None:
        raise ElfError("string table is not in a loaded segment")
    result["needed"] = [_c_string(handle, size, base + o) for o in needed_offsets]
    if soname_offset is not None:
        result["soname"] = _c_string(handle, size, base + soname_offset)
    return result
