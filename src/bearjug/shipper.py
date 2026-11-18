"""The shipper: reads Cowrie's output and sends it to the collector.

The spool is Cowrie's own output, mounted read-only into the shipper:

* JSON log directory: ``cowrie.json`` and its daily rotations. Each complete
  line becomes one ``cowrie.event`` record. A line without its newline yet is
  left for the next pass.
* TTY log directory: Cowrie renames a TTY log to a 64-hex name when the session
  closes. Only those names are shipped, so a recording is never sent half
  written. Each becomes a ``tty.log`` record.
* Download directory: Cowrie stores downloads and uploads under the SHA-256 of
  their bytes. Each becomes an ``upload`` record, and the file name is sent as
  the claimed digest, so the collector checks the bytes against what Cowrie
  recorded when it captured them.

Security rules this module keeps (design section 2.3):

* It treats every byte as opaque. It splits the JSON log on newlines and hashes
  files; it never parses, executes or interprets attacker content.
* It only makes outbound requests to one collector URL. It never listens.
* It reads the spool without following symlinks and only accepts regular files
  with the names above, so a compromised honeypot can't point it elsewhere.
* It holds only its own sensor key, never evidence or password keys.

Its own state (log offsets, files already shipped) lives outside the spool.
Losing it only causes resends, which the collector recognises as duplicates.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
import ssl
import stat
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import wire
from .schema.evidence import EvidenceKind

log = logging.getLogger("bearjug.shipper")

JSON_LOG_NAME = re.compile(r"^cowrie\.json(\.[0-9][0-9_-]*)?$")
HASH_NAME = re.compile(r"^[0-9a-f]{64}$")
MAX_LINE_BYTES = 1024 * 1024
DEFAULT_MAX_FILE_BYTES = 32 * 1024 * 1024


class ShipError(Exception):
    """The collector can't take evidence right now; stop and retry later."""


class Rejected(Exception):
    """The collector permanently refused one piece of evidence."""


@dataclass
class Config:
    sensor_id: str
    key: bytes
    collector_url: str
    log_dir: Path | None = None
    tty_dir: Path | None = None
    download_dir: Path | None = None
    state_path: Path = Path("shipper-state.json")
    ca_file: str | None = None
    insecure_http: bool = False
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES
    timeout: float = 30.0


@dataclass
class State:
    offsets: dict[str, int] = field(default_factory=dict)
    """Byte offset shipped so far per JSON log, keyed by ``device:inode`` so
    daily rotation (a rename) keeps its place."""
    shipped: set[str] = field(default_factory=set)
    """``kind:name`` of TTY logs and downloads already accepted or rejected."""

    @classmethod
    def load(cls, path: Path) -> State:
        try:
            raw = json.loads(path.read_text())
        except FileNotFoundError:
            return cls()
        return cls(offsets={str(k): int(v) for k, v in raw["offsets"].items()}, shipped=set(raw["shipped"]))

    def save(self, path: Path) -> None:
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(json.dumps({"offsets": self.offsets, "shipped": sorted(self.shipped)}))
        os.replace(tmp, path)


def _open_regular(path: Path) -> tuple[int, os.stat_result]:
    """Open a spool file read-only without following a symlink."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        os.close(fd)
        raise OSError(f"{path} is not a regular file")
    return fd, st


def _mtime(st: os.stat_result) -> datetime:
    return datetime.fromtimestamp(st.st_mtime, tz=timezone.utc)


class Shipper:
    def __init__(self, config: Config):
        if not config.insecure_http and not config.collector_url.startswith("https://"):
            raise ValueError("collector URL must be https:// (use --insecure-http only for local testing)")
        if len(config.key) < wire.MIN_SENSOR_KEY_BYTES:
            raise ValueError(f"sensor key must be at least {wire.MIN_SENSOR_KEY_BYTES} bytes")
        self.config = config
        self.url = config.collector_url.rstrip("/") + wire.PATH
        self.state = State.load(config.state_path)
        https = config.collector_url.startswith("https://")
        self._ssl = ssl.create_default_context(cafile=config.ca_file) if https else None

    # --- transport --------------------------------------------------------

    def send(self, kind: EvidenceKind, data: bytes, observed_at: datetime, claimed_sha256: str) -> dict:
        meta = wire.encode_meta(
            wire.ShipMeta(
                sensor_id=self.config.sensor_id,
                kind=kind,
                sha256=claimed_sha256,
                observed_at=observed_at,
                sent_at=wire.utcnow(),
                size_bytes=len(data),
            )
        )
        request = urllib.request.Request(
            self.url,
            data=data,
            method="POST",
            headers={
                "Content-Type": "application/octet-stream",
                wire.META_HEADER: meta,
                wire.SIGNATURE_HEADER: wire.sign(self.config.key, meta, data),
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=self.config.timeout, context=self._ssl) as response:
                # Only the status and a short JSON reply are read; nothing the
                # collector says is acted on beyond accepted or not.
                return json.loads(response.read(4096) or b"{}")
        except urllib.error.HTTPError as e:
            if e.code in (401, 403, 429) or e.code >= 500:
                raise ShipError(f"collector returned {e.code}") from None
            raise Rejected(f"collector rejected evidence: {e.code} {e.read(512)!r}") from None
        except (urllib.error.URLError, OSError) as e:
            raise ShipError(f"collector unreachable: {e}") from None

    # --- spool readers ----------------------------------------------------

    def ship_json_logs(self) -> int:
        directory = self.config.log_dir
        if directory is None or not directory.is_dir():
            return 0
        sent = 0
        # Oldest rotation first; the live file last.
        for path in sorted(directory.iterdir(), key=lambda p: (p.name == "cowrie.json", p.name)):
            if not JSON_LOG_NAME.match(path.name):
                continue
            try:
                fd, st = _open_regular(path)
            except OSError as e:
                log.warning("skipping %s: %s", path.name, e)
                continue
            key = f"{st.st_dev}:{st.st_ino}"
            with os.fdopen(fd, "rb") as f:
                offset = self.state.offsets.get(key, 0)
                if offset > st.st_size:
                    offset = 0  # truncated or replaced
                f.seek(offset)
                while True:
                    line = f.readline(MAX_LINE_BYTES + 1)
                    if len(line) > MAX_LINE_BYTES:
                        # Oversized line: skip it once it is complete.
                        skipped = len(line)
                        while not line.endswith(b"\n"):
                            line = f.readline(MAX_LINE_BYTES)
                            if not line:
                                break
                            skipped += len(line)
                        if not line.endswith(b"\n"):
                            break
                        log.warning("%s: %d-byte line at offset %d not shipped", path.name, skipped, offset)
                        offset += skipped
                        self.state.offsets[key] = offset
                        continue
                    if not line.endswith(b"\n"):
                        break  # incomplete line: wait for Cowrie to finish it
                    record = line.rstrip(b"\r\n")
                    if record.strip():
                        try:
                            self.send(EvidenceKind.COWRIE_EVENT, record, _mtime(st), hashlib.sha256(record).hexdigest())
                            sent += 1
                        except Rejected as e:
                            log.error("%s offset %d: %s", path.name, offset, e)
                    offset += len(line)
                    self.state.offsets[key] = offset
                    self.state.save(self.config.state_path)
        return sent

    def ship_hashed_files(self, directory: Path | None, kind: EvidenceKind) -> int:
        if directory is None or not directory.is_dir():
            return 0
        sent = 0
        for path in sorted(directory.iterdir()):
            name = path.name
            marker = f"{kind.value}:{name}"
            if not HASH_NAME.match(name) or marker in self.state.shipped:
                continue
            try:
                fd, st = _open_regular(path)
            except OSError as e:
                log.warning("skipping %s: %s", name, e)
                continue
            with os.fdopen(fd, "rb") as f:
                if st.st_size > self.config.max_file_bytes:
                    log.error("%s %s is %d bytes, over the limit; not shipped", kind.value, name, st.st_size)
                    self.state.shipped.add(marker)
                    self.state.save(self.config.state_path)
                    continue
                data = f.read(self.config.max_file_bytes + 1)
            # Cowrie names downloads by the SHA-256 of their bytes; TTY logs by a
            # hash of their input only, so for those the digest is computed here.
            claimed = name if kind is EvidenceKind.UPLOAD else hashlib.sha256(data).hexdigest()
            try:
                self.send(kind, data, _mtime(st), claimed)
                sent += 1
            except Rejected as e:
                log.error("%s %s: %s", kind.value, name, e)
            self.state.shipped.add(marker)
            self.state.save(self.config.state_path)
        return sent

    def run_once(self) -> int:
        """Ship everything new. Raises :class:`ShipError` if the collector is
        unavailable; progress so far is kept."""
        return (
            self.ship_json_logs()
            + self.ship_hashed_files(self.config.tty_dir, EvidenceKind.TTY_LOG)
            + self.ship_hashed_files(self.config.download_dir, EvidenceKind.UPLOAD)
        )


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="bearjug-shipper", description=__doc__.split("\n")[0])
    p.add_argument("--sensor-id", required=True)
    p.add_argument("--key-file", required=True, type=Path, help="this sensor's key, as written by bearjug-collector add-sensor")
    p.add_argument("--collector", required=True, help="collector base URL, e.g. https://collector.internal:8443")
    p.add_argument("--log-dir", type=Path, help="Cowrie JSON log directory (holds cowrie.json)")
    p.add_argument("--tty-dir", type=Path, help="Cowrie ttylog_path")
    p.add_argument("--download-dir", type=Path, help="Cowrie download_path")
    p.add_argument("--state", type=Path, default=Path("shipper-state.json"))
    p.add_argument("--ca-file", help="CA bundle that signed the collector's certificate")
    p.add_argument("--insecure-http", action="store_true", help="allow http:// for local testing only")
    p.add_argument("--interval", type=float, default=5.0)
    p.add_argument("--once", action="store_true", help="ship what is there now, then exit")
    args = p.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")

    shipper = Shipper(
        Config(
            sensor_id=args.sensor_id,
            key=bytes.fromhex(args.key_file.read_text().strip()),
            collector_url=args.collector,
            log_dir=args.log_dir,
            tty_dir=args.tty_dir,
            download_dir=args.download_dir,
            state_path=args.state,
            ca_file=args.ca_file,
            insecure_http=args.insecure_http,
        )
    )
    while True:
        try:
            n = shipper.run_once()
            if n:
                log.info("shipped %d", n)
        except ShipError as e:
            log.warning("%s; will retry", e)
            if args.once:
                return 1
        if args.once:
            return 0
        time.sleep(args.interval)


if __name__ == "__main__":
    sys.exit(main())
