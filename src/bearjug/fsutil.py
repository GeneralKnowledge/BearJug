"""Durable, private file operations shared by the shipper and the collector.

Guarantee: a file written with :func:`write_private` is either the old version
or the complete new one after a process crash *or* a power loss, provided the
filesystem honours ``fsync`` (ext4, xfs and btrfs do with their default
mount options). The data is synced before the rename, and the directory is
synced after it, so the rename itself survives a power cut.

Modes are always set explicitly with ``fchmod``/``chmod``, never left to the
umask.
"""

from __future__ import annotations

import os
from pathlib import Path


def fsync_dir(path: Path) -> None:
    """Make renames, creations and deletions in ``path`` durable."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_private(path: Path, data: bytes | str, *, exclusive: bool = False, mode: int = 0o600) -> None:
    """Atomically and durably write a file (0600 unless ``mode`` says
    otherwise). With ``exclusive``, refuse to replace an existing file."""
    if isinstance(data, str):
        data = data.encode()
    if exclusive and path.exists():
        raise FileExistsError(path)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    if exclusive:
        os.link(tmp, path)  # fails if path appeared meanwhile
        tmp.unlink()
    else:
        os.replace(tmp, path)
    fsync_dir(path.parent)


def private_dir(path: Path) -> Path:
    """Create a directory only its owner can enter, durably."""
    existed = path.is_dir()
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    if not existed:
        fsync_dir(path.parent)
    return path
