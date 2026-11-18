"""Apply the BearJug overlay to a pinned Cowrie checkout.

Run at image build time, against the Cowrie commit pinned in the Dockerfile:

    python3 apply.py /path/to/cowrie-checkout

Every upstream file the overlay touches is checked against the SHA-256 of
the version that was reviewed. If Cowrie is bumped and any of them changed,
the build fails here, so nobody can upgrade Cowrie without re-reviewing what
the overlay replaces. The same goes for a patch whose anchor text is missing
or appears more than once.

What the overlay does:

* replaces the five tools that make real outbound connections (``wget``,
  ``curl``, ``ftpget``, ``tftp``, ``nc``) with simulated versions that never
  open a socket and record what was attempted;
* replaces ``free``, which reads the host's ``/proc/meminfo``;
* replaces SSH ``direct-tcpip`` forwarding with a handler that records the
  request and always refuses it, and registers it whatever the config says;
* deletes the FoxIO-licensed JA4+ code (``cowrie/vendor/ja4`` and
  ``cowrie/core/fingerprint.py``) and the SSH proxy backend
  (``cowrie/ssh_proxy``), the only code that used it besides the replaced
  forwarding module;
* refuses to start with any backend other than the emulated shell (no proxy,
  pool or LLM backend);
* removes the fallback to Cowrie's example user database: without a
  ``userdb.txt`` nobody can log in.

The network boundary, not this overlay, is the safety guarantee. The overlay
is there for realism and clean evidence.
"""

from __future__ import annotations

import hashlib
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
FILES = HERE / "files"

# Upstream files at the pinned commit (cowrie v3.1.7, 8e36327f), by SHA-256.
REVIEWED = {
    "src/cowrie/commands/wget.py": "6aaae2cac75a6d8a131de63c087f9b5eeb3731f9146b9d4480bb3e79924af060",
    "src/cowrie/commands/curl.py": "d4e53f5bfc75eee50a3c69a6ca9998fa41631276ff373353dcacd8ff4d709417",
    "src/cowrie/commands/ftpget.py": "04d9c840b067da0d65098aaccba35a7380c8b74275148a9806650b2d9aa46492",
    "src/cowrie/commands/tftp.py": "b98d1b9b5f1920df6f69bf415a3863a153d02b5ca650494662443b286ee46de5",
    "src/cowrie/commands/nc.py": "6a007c1cdb35a876adb8b42c7567528e2f7cec8bc5a65f55a1e7e908b541e6a2",
    "src/cowrie/commands/free.py": "49c5abe53c58cc3a28d2719ce47f8c8dc7dbe4e4681bad84aa1e266d8ac3c8b7",
    "src/cowrie/ssh/forwarding.py": "3ad8e1ec99dd70023c7f69cbb491f4e3a278aaeda126ac2dd62878f6580cbf0c",
    "src/cowrie/shell/avatar.py": "2c0cc093395f23d53b9d213c5eacf1aecf7e4dd4f868218640b5f65509d52077",
    "src/cowrie/core/auth.py": "a2ac757aa652f4445336b0feeefc94bb703a18c1e3fede230575587172923849",
    "src/cowrie/core/fingerprint.py": "e5ba4761021920c8a0108d9396cb9c8e31de7105bb3a134ad1966a8fa4d74ca4",
    "src/twisted/plugins/cowrie_plugin.py": "2174dbe8e7ab25a4f4ca9bf9cf876d41b5552632ffca6e78c237c34c39247032",
    "src/cowrie/ssh/factory.py": "565589c51dfd9884f1da73d838e981329869d85f4355f04a4f40bd5912f5f58b",
}

# Upstream file -> BearJug replacement (under files/).
REPLACE = {
    "src/cowrie/commands/wget.py": "src/cowrie/commands/wget.py",
    "src/cowrie/commands/curl.py": "src/cowrie/commands/curl.py",
    "src/cowrie/commands/ftpget.py": "src/cowrie/commands/ftpget.py",
    "src/cowrie/commands/tftp.py": "src/cowrie/commands/tftp.py",
    "src/cowrie/commands/nc.py": "src/cowrie/commands/nc.py",
    "src/cowrie/commands/free.py": "src/cowrie/commands/free.py",
    "src/cowrie/ssh/forwarding.py": "src/cowrie/ssh/forwarding.py",
}

# New files with no upstream counterpart.
ADD = ["src/cowrie/commands/_bearjug_outbound.py"]

DELETE = ["src/cowrie/vendor/ja4", "src/cowrie/core/fingerprint.py", "src/cowrie/ssh_proxy"]

# setuptools-scm writes this when Cowrie is pip-installed from git; the image
# runs Cowrie from its source tree instead, so the overlay writes it.
COWRIE_VERSION = "3.1.7"
VERSION_FILE = "src/cowrie/_version.py"

# (file, anchor, replacement): the anchor must occur exactly once.
PATCHES = [
    (
        "src/cowrie/ssh/factory.py",
        """from cowrie.ssh_proxy import server_transport as proxyTransport
from cowrie.ssh_proxy.userauth import ProxySSHAuthServer
""",
        "",
    ),
    (
        "src/cowrie/ssh/factory.py",
        """            b"ssh-userauth": (
                ProxySSHAuthServer
                if self.backend == "proxy"
                else HoneyPotSSHUserAuthServer
            ),
""",
        """            b"ssh-userauth": HoneyPotSSHUserAuthServer,
""",
    ),
    (
        "src/cowrie/ssh/factory.py",
        """        if self.backend == "proxy":
            t = proxyTransport.FrontendSSHTransport()
        else:
            t = shellTransport.HoneyPotSSHTransport()
""",
        """        if self.backend != "shell":
            raise ValueError("BearJug: only the emulated shell backend is allowed")
        t = shellTransport.HoneyPotSSHTransport()
""",
    ),
    (
        "src/cowrie/shell/avatar.py",
        """        # SSH forwarding disabled only when option is explicitly set
        if CowrieConfig.getboolean("ssh", "forwarding", fallback=True):
            self.channelLookup[b"direct-tcpip"] = (
                forwarding.cowrieOpenConnectForwardingClient
            )
""",
        """        # BearJug: direct-tcpip requests are always recorded and always
        # refused (see cowrie/ssh/forwarding.py), whatever the config says.
        self.channelLookup[b"direct-tcpip"] = (
            forwarding.cowrieOpenConnectForwardingClient
        )
""",
    ),
    (
        "src/cowrie/core/auth.py",
        """        else:
            try:
                dblines = (
                    read_data_bytes("etc", "userdb.example")
                    .decode("ascii")
                    .splitlines()
                )
            except FileNotFoundError:
                self._log.info(
                    "Could not read etc/userdb.txt, default database activated"
                )
                dblines = _USERDB_DEFAULTS
""",
        """        else:
            # BearJug: fail closed. No compiled userdb.txt means nobody can
            # log in, never Cowrie's permissive example database.
            self._log.error("BearJug: no etc/userdb.txt; every login is refused")
            dblines = []
""",
    ),
    (
        "src/twisted/plugins/cowrie_plugin.py",
        """        backend_type: str = CowrieConfig.get("honeypot", "backend", fallback="shell")
""",
        """        backend_type: str = CowrieConfig.get("honeypot", "backend", fallback="shell")
        if backend_type != "shell" or self.pool_only:
            raise SystemExit("BearJug: only the emulated shell backend is allowed")
""",
    ),
    (
        "src/twisted/plugins/cowrie_plugin.py",
        """    def pool_ready(self) -> None:
        backend: str = CowrieConfig.get("honeypot", "backend", fallback="shell")
""",
        """    def pool_ready(self) -> None:
        backend: str = CowrieConfig.get("honeypot", "backend", fallback="shell")
        if backend != "shell":
            raise SystemExit("BearJug: only the emulated shell backend is allowed")
""",
    ),
]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def apply(root: Path) -> None:
    problems = []
    for rel, expected in REVIEWED.items():
        path = root / rel
        if not path.is_file():
            problems.append(f"{rel}: missing")
        elif sha256(path) != expected:
            problems.append(f"{rel}: differs from the reviewed version")
    if problems:
        raise SystemExit("overlay refused, upstream Cowrie changed:\n  " + "\n  ".join(problems))

    for rel, anchor, replacement in PATCHES:
        path = root / rel
        text = path.read_text()
        count = text.count(anchor)
        if count != 1:
            raise SystemExit(f"overlay refused: patch anchor found {count} times in {rel}")
        path.write_text(text.replace(anchor, replacement))

    for rel, src in REPLACE.items():
        shutil.copyfile(FILES / src, root / rel)
    for rel in ADD:
        target = root / rel
        if target.exists():
            raise SystemExit(f"overlay refused: {rel} already exists upstream")
        shutil.copyfile(FILES / rel, target)
    for rel in DELETE:
        path = root / rel
        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink()

    (root / VERSION_FILE).write_text(
        f'__version__ = version = "{COWRIE_VERSION}"\n__version_tuple__ = version_tuple = {tuple(int(x) for x in COWRIE_VERSION.split("."))!r}\n'
    )

    leftovers = [str(p.relative_to(root)) for p in (root / "src").rglob("*.py") if "FoxIO" in p.read_text(errors="replace")]
    if leftovers:
        raise SystemExit("overlay refused: FoxIO-licensed code still present: " + ", ".join(leftovers))
    print("BearJug overlay applied")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: apply.py COWRIE_CHECKOUT")
    apply(Path(sys.argv[1]))
