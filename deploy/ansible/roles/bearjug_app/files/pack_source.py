"""Pack the BearJug source into a reproducible tarball.

Run on the machine running Ansible. The same source always gives the same
bytes (sorted entries, fixed owner and times, no caches or build output), so
Ansible copies and reinstalls only when the code actually changed.

    python3 pack_source.py REPO_ROOT OUTPUT.tar
"""

from __future__ import annotations

import io
import sys
import tarfile
from pathlib import Path

INCLUDE = ["src", "pyproject.toml", "README.md", "LICENSE", "NOTICE"]
SKIP_PARTS = {"__pycache__", "build"}


def wanted(path: Path) -> bool:
    return not any(p in SKIP_PARTS or p.endswith((".egg-info", ".pyc")) for p in path.parts)


def entries(root: Path) -> list[Path]:
    found = []
    for name in INCLUDE:
        top = root / name
        if top.is_dir():
            found += [p for p in top.rglob("*") if p.is_file() and wanted(p.relative_to(root))]
        elif top.is_file():
            found.append(top)
        else:
            raise SystemExit(f"missing {top}")
    return sorted(found, key=lambda p: p.relative_to(root).as_posix())


def pack(root: Path, out: Path) -> None:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for path in entries(root):
            data = path.read_bytes()
            info = tarfile.TarInfo(path.relative_to(root).as_posix())
            info.size = len(data)
            info.mode = 0o644
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = "root"
            tar.addfile(info, io.BytesIO(data))
    data = buf.getvalue()
    out.parent.mkdir(parents=True, exist_ok=True)
    if not out.exists() or out.read_bytes() != data:
        out.write_bytes(data)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: pack_source.py REPO_ROOT OUTPUT.tar")
    pack(Path(sys.argv[1]).resolve(), Path(sys.argv[2]))
