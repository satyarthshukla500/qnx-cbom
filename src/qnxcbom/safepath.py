# Opens files named by untrusted input only when they stay inside chosen folders.
# Roots come from the command line or $QNX_TARGET, never from the build list.
import os
import stat

MAX_FILE_BYTES = 64 * 1024 * 1024


class Roots:
    def __init__(self, folders):
        self.folders = []
        for folder in folders:
            real = os.path.realpath(folder)
            if os.path.isdir(real) and real not in self.folders:
                self.folders.append(real)

    def inside(self, real_path: str) -> bool:
        return any(real_path == r or real_path.startswith(r + os.sep) for r in self.folders)

    def resolve(self, src: str):
        """Return (real_path, reason). real_path is None when the file cannot be used.

        reason is "missing", "outside", "not-file" or "too-big" in that case.
        """
        if "\0" in src:
            return None, "outside"
        candidates = [src] if os.path.isabs(src) else [os.path.join(r, src) for r in self.folders]
        reason = "missing"
        for candidate in candidates:
            real = os.path.realpath(candidate)
            if not os.path.lexists(candidate):
                continue
            if not self.inside(real):
                reason = "outside"
                continue
            try:
                info = os.stat(real)
            except OSError:
                continue
            if not stat.S_ISREG(info.st_mode):
                reason = "not-file"
                continue
            if info.st_size > MAX_FILE_BYTES:
                return None, "too-big"
            return real, ""
        return None, reason


def open_regular(path: str):
    """Open a regular file for reading. A link or special file put in place after the
    earlier checks is refused (O_NOFOLLOW, no blocking open, fstat on the open file)."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE_BYTES:
            raise OSError("not a regular file of acceptable size")
    except OSError:
        os.close(fd)
        raise
    return os.fdopen(fd, "rb")


def read_limited(path: str, limit: int = MAX_FILE_BYTES) -> bytes:
    """Read a regular file, at most `limit` bytes."""
    with open_regular(path) as handle:
        return handle.read(limit)
