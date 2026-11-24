# Read-only reader for qnx6 file systems (the partitions made by mkqnx6fsimg / diskimage).
# Plain Python, no mounting. Every read stays inside the partition; sizes and counts are capped.
# Layout (checked on images from mkqnx6fsimg 8.0.6): 8 KiB boot block, superblock at 0x2000,
# data block n at (n * blocksize + 0x3000), 128-byte inodes held in a file of their own,
# 32-byte directory entries, long names in a separate "longfile" file.
import posixpath
import stat
import struct

MAGIC = 0x68191122
SUPER_AT = 0x2000
DATA_AT = 0x3000
MAX_ENTRIES = 20_000
MAX_DEPTH = 32
NO_BLOCK = 0xFFFFFFFF


class Qnx6Error(Exception):
    pass


def is_qnx6(handle, offset=0):
    handle.seek(offset + SUPER_AT)
    return handle.read(4) == struct.pack("<I", MAGIC)


class Qnx6:
    def __init__(self, handle, offset, size):
        self.f, self.offset, self.size = handle, offset, size
        head = self._raw(SUPER_AT, 0x200)
        if len(head) < 0x200 or struct.unpack_from("<I", head)[0] != MAGIC:
            raise Qnx6Error("no qnx6 superblock")
        self.bs = struct.unpack_from("<I", head, 48)[0]
        if self.bs not in (512, 1024, 2048, 4096, 8192, 16384, 32768, 65536):
            raise Qnx6Error(f"unsupported block size {self.bs}")
        self.num_inodes = struct.unpack_from("<I", head, 52)[0]
        self.inodes = self._node(head, 72)
        self.longfile = self._node(head, 232)

    @staticmethod
    def _node(buf, at):
        size = struct.unpack_from("<Q", buf, at)[0]
        ptrs = struct.unpack_from("<16I", buf, at + 8)
        return {"size": size, "ptrs": ptrs, "levels": buf[at + 72]}

    def _raw(self, at, n):
        if at < 0 or at + n > self.size:
            raise Qnx6Error("read outside the partition")
        self.f.seek(self.offset + at)
        return self.f.read(n)

    def _block(self, number):
        return self._raw(number * self.bs + DATA_AT, self.bs)

    def _phys(self, node, index):
        """Physical block of logical block `index` of a file (None for a hole)."""
        per = self.bs // 4
        levels = node["levels"]
        if levels > 3:
            raise Qnx6Error("too many block levels")
        span = per ** levels
        number = node["ptrs"][index // span] if index // span < 16 else NO_BLOCK
        index %= span
        for _ in range(levels):
            if number == NO_BLOCK:
                return None
            span //= per
            number = struct.unpack_from("<I", self._block(number), (index // span) * 4)[0]
            index %= span
        return None if number == NO_BLOCK else number

    def read(self, node, limit):
        """Content of a file node, at most `limit` bytes (the file is cut at its size)."""
        want = min(node["size"], limit)
        out = bytearray()
        for index in range((want + self.bs - 1) // self.bs):
            number = self._phys(node, index)
            out += self._block(number) if number is not None else bytes(self.bs)
        return bytes(out[:want])

    def inode(self, number):
        if not 1 <= number <= self.num_inodes:
            raise Qnx6Error("inode number out of range")
        node = self.inodes
        at = (number - 1) * 128
        index, rest = divmod(at, self.bs)
        block = self._phys(node, index)
        if block is None:
            raise Qnx6Error("inode in a hole")
        raw = self._block(block)[rest:rest + 128]
        size, = struct.unpack_from("<Q", raw)
        mode, = struct.unpack_from("<H", raw, 32)
        return {"size": size, "mode": mode, "ptrs": struct.unpack_from("<16I", raw, 36), "levels": raw[100]}

    def _long_name(self, number):
        shift = self.bs.bit_length() - 1 - 9
        block = self._phys(self.longfile, number >> shift)
        if block is None:
            raise Qnx6Error("long name in a hole")
        at = (number & ((1 << shift) - 1)) * 512
        raw = self._block(block)[at:at + 512]
        length, = struct.unpack_from("<H", raw)
        if length > 510:
            raise Qnx6Error("bad long name")
        return raw[2:2 + length]

    def _entries(self, node):
        data = self.read(node, 16 * 1024 * 1024)
        for at in range(0, len(data) - 31, 32):
            number, length = struct.unpack_from("<IB", data, at)
            if number == 0:
                continue
            if length == 0xFF:
                name = self._long_name(struct.unpack_from("<I", data, at + 8)[0])
            else:
                name = data[at + 5:at + 5 + min(length, 27)]
            yield number, name

    def walk(self):
        """Yield (path, kind, size, inode node) for every entry; kind is file, dir or link.
        Raises Qnx6Error for anything it cannot follow."""
        stack, seen, count = [("", 1, 0)], set(), 0
        while stack:
            base, number, depth = stack.pop()
            if number in seen or depth > MAX_DEPTH:
                raise Qnx6Error("directory loop or too deep")
            seen.add(number)
            for child, raw in self._entries(self.inode(number)):
                name = raw.decode("utf-8", "replace")
                if name in (".", "..") or "/" in name or "\0" in name or not name:
                    continue
                count += 1
                if count > MAX_ENTRIES:
                    raise Qnx6Error("too many entries")
                node = self.inode(child)
                kind = {stat.S_IFREG: "file", stat.S_IFDIR: "dir", stat.S_IFLNK: "link"}.get(stat.S_IFMT(node["mode"]), "other")
                path = posixpath.join(base, name)
                yield path, kind, node["size"], node
                if kind == "dir":
                    stack.append((path, child, depth + 1))


def partitions(handle, disk_size):
    """MBR partition table: list of (type, start byte, size bytes) for used entries."""
    handle.seek(0)
    sector = handle.read(512)
    if len(sector) < 512 or sector[510:512] != b"\x55\xaa":
        raise Qnx6Error("no partition table in the disk image")
    found = []
    for i in range(4):
        entry = sector[446 + 16 * i:462 + 16 * i]
        kind, start, count = entry[4], *struct.unpack_from("<II", entry, 8)
        if kind and count and (start + count) * 512 <= disk_size:
            found.append((kind, start * 512, count * 512))
    return found
