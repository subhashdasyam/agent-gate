"""Small OS helpers shared by setup, state storage, and command guards."""
import contextlib
import errno
import os
import shlex
import time

try:
    import fcntl
except ImportError:  # Windows
    fcntl = None
try:
    import msvcrt
except ImportError:  # POSIX
    msvcrt = None


def command(argv, windows=None):
    """Render arguments for POSIX shells or native Windows PowerShell, never CMD."""
    windows = os.name == "nt" if windows is None else windows
    if windows:
        return "& " + " ".join("'" + str(arg).replace("'", "''") + "'" for arg in argv)
    return shlex.join([str(arg) for arg in argv])


@contextlib.contextmanager
def file_lock(path, timeout=5):
    """Lock a stable sidecar, so atomic JSON replacement cannot break the lock."""
    if fcntl is None and msvcrt is None:
        raise RuntimeError("No supported file-lock backend. Refusing unlocked state.")
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    with os.fdopen(fd, "r+b") as fh:
        if os.fstat(fh.fileno()).st_size == 0:
            fh.write(b"\0")
            fh.flush()
        until = time.monotonic() + timeout
        while True:
            try:
                fh.seek(0)
                if fcntl is not None:
                    fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
                else:
                    msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
                break
            except OSError as exc:
                if exc.errno not in (errno.EACCES, errno.EAGAIN, errno.EDEADLK):
                    raise
                if time.monotonic() >= until:
                    raise TimeoutError("State lock is busy. No action was authorized.") from exc
                time.sleep(0.02)
        try:
            yield
        finally:
            fh.seek(0)
            if fcntl is not None:
                fcntl.flock(fh, fcntl.LOCK_UN)
            else:
                msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
