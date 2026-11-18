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

With ``delete_acknowledged`` the shipper also removes evidence from the sensor
once the collector has acknowledged it, so attacker passwords, recordings and
files don't pile up on an internet-facing machine. A file is only ever
removed after the acknowledgement is saved in the shipper's state; a crash or
a lost reply at any point leads to a resend, never to a premature deletion.
See :meth:`Shipper.clean_spool`.

Evidence the collector permanently refuses (bad digest, not a JSON object, too
large) is not dropped: it goes to a local dead-letter directory with the
reason, so it can be investigated, for example when Cowrie changes its output
format. See :class:`DeadLetter`.
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

from . import policy, wire
from .fsutil import fsync_dir, private_dir, write_private
from .schema.evidence import EvidenceKind

log = logging.getLogger("bearjug.shipper")

JSON_LOG_NAME = re.compile(r"^cowrie\.json(\.[0-9][0-9_-]*)?$")
HASH_NAME = re.compile(r"^[0-9a-f]{64}$")
MAX_LINE_BYTES = 1024 * 1024
DEFAULT_MAX_FILE_BYTES = policy.MAX_EVIDENCE_BYTES


def _ident(st: os.stat_result) -> list[int]:
    """What makes a spool file *this* file: device, inode, size and
    modification time. A replacement, or a rewrite in place, changes it."""
    return [st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns]


class ShipError(Exception):
    """The collector can't take evidence right now; stop and retry later."""


class Rejected(Exception):
    """The collector permanently refused one piece of evidence."""


class DeadLetter:
    """Local store for evidence that can't be shipped.

    Each entry is ``<id>.bin`` (the original bytes, when they fit) and
    ``<id>.json`` (kind, where it came from, size, SHA-256, the reason, and
    whether the bytes were kept). Files are written 0600 and never executable,
    and the contents are never parsed or run. The directory has a total size
    cap: past it, only the metadata is kept, so a flood of bad evidence can't
    fill the sensor's disk. Entries older than the retention period are
    removed on every pass.
    """

    def __init__(self, directory: Path, *, max_bytes: int, retention_days: float):
        self.dir = directory
        self.max_bytes = max_bytes
        self.retention_seconds = retention_days * 86400
        private_dir(directory)

    def _write(self, path: Path, data: bytes) -> None:
        write_private(path, data)

    def used_bytes(self) -> int:
        return sum(p.stat().st_size for p in self.dir.glob("*.bin"))

    def add(self, *, kind: EvidenceKind, source: str, reason: str, size: int, sha256: str | None, data: bytes | None) -> bool:
        """Record refused evidence. Returns whether the bytes were kept: only
        then may the source be removed from the spool."""
        now = datetime.now(timezone.utc)
        entry_id = f"{now.strftime('%Y%m%dT%H%M%S%fZ')}-{(sha256 or 'unknown')[:16]}"
        kept, why_not = False, None
        if data is None:
            why_not = "bytes not read (over the size limit); still at the source"
        elif self.used_bytes() + len(data) > self.max_bytes:
            why_not = "dead-letter directory full; still at the source until Cowrie removes it"
        else:
            self._write(self.dir / f"{entry_id}.bin", data)
            kept = True
        meta = {
            "kind": kind.value,
            "source": source,
            "reason": reason,
            "size_bytes": size,
            "sha256": sha256,
            "rejected_at": now.isoformat(),
            "bytes_kept": kept,
            "bytes_not_kept_because": why_not,
        }
        self._write(self.dir / f"{entry_id}.json", json.dumps(meta, indent=2).encode())
        log.error("dead-lettered %s from %s: %s", kind.value, source, reason)
        return kept

    def prune(self) -> int:
        cutoff = time.time() - self.retention_seconds
        removed = 0
        for p in self.dir.iterdir():
            if p.is_file() and not p.is_symlink() and p.stat().st_mtime < cutoff:
                p.unlink()
                removed += 1
        if removed:
            fsync_dir(self.dir)
        return removed


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
    dead_letter_dir: Path = Path("dead-letter")
    dead_letter_max_bytes: int = policy.DEAD_LETTER_MAX_BYTES
    dead_letter_retention_days: float = policy.DEAD_LETTER_RETENTION_DAYS
    delete_acknowledged: bool = False
    """Remove evidence from the spool once the collector has acknowledged it.
    Needs the spool mounted so the shipper can unlink files (see docs)."""
    unpreserved_retention_days: float = policy.UNPRESERVED_RETENTION_DAYS
    """How long evidence that was refused and could not be copied to the
    dead-letter directory stays in the spool before it is removed."""
    rotated_log_settle_seconds: float = 60.0
    """A rotated JSON log must be this old before it is removed."""
    spool_warn_bytes: int = policy.SPOOL_WARN_BYTES
    """Log a warning each pass while the spool holds more than this."""
    timeout: float = 30.0


@dataclass
class State:
    offsets: dict[str, int] = field(default_factory=dict)
    """Byte offset processed so far per JSON log, keyed by ``device:inode`` so
    daily rotation (a rename) keeps its place. Every line before the offset
    was acknowledged by the collector or dead-lettered."""
    acked: set[str] = field(default_factory=set)
    """``kind:name`` of TTY logs and downloads the collector acknowledged, or
    that were dead-lettered with their bytes kept. Safe to remove."""
    unpreserved: dict[str, float] = field(default_factory=dict)
    """``kind:name`` (or a JSON log's ``device:inode``) refused and not copied
    to the dead-letter directory, with when that happened. Not resent; kept in
    the spool until ``unpreserved_retention_days`` passes."""
    identity: dict[str, list[int]] = field(default_factory=dict)
    """For each acknowledged, unpreserved or offset-tracked entry: the
    ``[device, inode, size, mtime_ns]`` of the exact file that was read.
    Cleanup removes a file only if it still matches, so a file swapped in at
    the same name is never deleted on the strength of another file's
    acknowledgement."""

    @classmethod
    def load(cls, path: Path) -> State:
        try:
            raw = json.loads(path.read_text())
        except FileNotFoundError:
            return cls()
        return cls(
            offsets={str(k): int(v) for k, v in raw.get("offsets", {}).items()},
            acked=set(raw.get("acked", [])),
            unpreserved={str(k): float(v) for k, v in raw.get("unpreserved", {}).items()},
            identity={str(k): [int(x) for x in v] for k, v in raw.get("identity", {}).items()},
        )

    def save(self, path: Path) -> None:
        data = {
            "offsets": self.offsets,
            "acked": sorted(self.acked),
            "unpreserved": self.unpreserved,
            "identity": self.identity,
        }
        write_private(path, json.dumps(data).encode())

    def done(self, marker: str) -> bool:
        return marker in self.acked or marker in self.unpreserved


def _open_regular(path: Path) -> tuple[int, os.stat_result]:
    """Open a spool file read-only without following a symlink."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        os.close(fd)
        raise OSError(f"{path} is not a regular file")
    return fd, st


def _warn_if_exposed(path: Path, st: os.stat_result) -> None:
    """Cowrie writes the spool, so the shipper can't set its permissions, but
    it can refuse to stay quiet about a world-accessible one."""
    if st.st_mode & 0o007:
        log.warning("%s is accessible to other users (mode %o); see docs/ingestion.md", path, stat.S_IMODE(st.st_mode))


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
        self.dead_letter = DeadLetter(
            config.dead_letter_dir,
            max_bytes=config.dead_letter_max_bytes,
            retention_days=config.dead_letter_retention_days,
        )
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
            detail = e.read(512).decode("utf-8", "replace")
            raise Rejected(f"collector refused it with {e.code}: {detail}") from None
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
            _warn_if_exposed(path, st)
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
                        self.dead_letter.add(
                            kind=EvidenceKind.COWRIE_EVENT,
                            source=f"{path}@{offset}",
                            reason=f"line of {skipped} bytes is over the {MAX_LINE_BYTES}-byte limit",
                            size=skipped,
                            sha256=None,
                            data=None,
                        )
                        self.state.unpreserved.setdefault(key, time.time())
                        offset += skipped
                        self.state.offsets[key] = offset
                        self.state.save(self.config.state_path)
                        continue
                    if not line.endswith(b"\n"):
                        break  # incomplete line: wait for Cowrie to finish it
                    record = line.rstrip(b"\r\n")
                    if record.strip():
                        digest = hashlib.sha256(record).hexdigest()
                        try:
                            self.send(EvidenceKind.COWRIE_EVENT, record, _mtime(st), digest)
                            sent += 1
                        except Rejected as e:
                            kept = self.dead_letter.add(
                                kind=EvidenceKind.COWRIE_EVENT,
                                source=f"{path}@{offset}",
                                reason=str(e),
                                size=len(record),
                                sha256=digest,
                                data=record,
                            )
                            if not kept:
                                self.state.unpreserved.setdefault(key, time.time())
                    offset += len(line)
                    self.state.offsets[key] = offset
                    self.state.save(self.config.state_path)
                # Identity as of now: if Cowrie appends after this, size and
                # mtime differ and cleanup leaves the file alone.
                if self.state.offsets.get(key) is not None:
                    self.state.identity[key] = _ident(os.fstat(f.fileno()))
                    self.state.save(self.config.state_path)
        return sent

    def ship_hashed_files(self, directory: Path | None, kind: EvidenceKind) -> int:
        if directory is None or not directory.is_dir():
            return 0
        sent = 0
        for path in sorted(directory.iterdir()):
            name = path.name
            marker = f"{kind.value}:{name}"
            if not HASH_NAME.match(name) or self.state.done(marker):
                continue
            try:
                fd, st = _open_regular(path)
            except OSError as e:
                log.warning("skipping %s: %s", name, e)
                continue
            _warn_if_exposed(path, st)
            with os.fdopen(fd, "rb") as f:
                if st.st_size > self.config.max_file_bytes:
                    self.dead_letter.add(
                        kind=kind,
                        source=str(path),
                        reason=f"{st.st_size} bytes is over the {self.config.max_file_bytes}-byte limit",
                        size=st.st_size,
                        sha256=name if kind is EvidenceKind.UPLOAD else None,
                        data=None,
                    )
                    self.state.unpreserved[marker] = time.time()
                    self.state.identity[marker] = _ident(st)
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
                kept = self.dead_letter.add(
                    kind=kind, source=str(path), reason=str(e), size=len(data), sha256=hashlib.sha256(data).hexdigest(), data=data
                )
                if not kept:
                    self.state.unpreserved[marker] = time.time()
                    self.state.identity[marker] = _ident(st)
                    self.state.save(self.config.state_path)
                    continue
            # Only reached after a 2xx reply, or with the bytes safe in the
            # dead-letter directory. Saved, with the identity of the exact
            # file that was sent, before any deletion can happen.
            self.state.acked.add(marker)
            self.state.identity[marker] = _ident(st)
            self.state.save(self.config.state_path)
        return sent

    # --- sensor-side cleanup ----------------------------------------------

    def _unpreserved_expired(self, saved: State, marker: str) -> bool:
        since = saved.unpreserved.get(marker)
        return since is not None and time.time() - since > self.config.unpreserved_retention_days * 86400

    @staticmethod
    def _same_file(path: Path, ident: list[int] | None) -> bool:
        """Whether ``path`` is still the regular file that was acknowledged.
        Checked with lstat, so a symlink put in its place never matches."""
        if ident is None:
            return False
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            return False
        if stat.S_ISREG(st.st_mode) and _ident(st) == ident:
            return True
        log.warning("%s is not the file that was acknowledged (replaced or changed); leaving it", path)
        return False

    def clean_spool(self) -> list[str]:
        """Remove spool files whose evidence is safe elsewhere.

        Removed: TTY logs and downloads whose acknowledgement is saved in the
        state file; rotated JSON logs whose every line was acknowledged (or
        dead-lettered with its bytes), once they have settled. Refused
        evidence that could not be preserved stays until its retention period
        ends. Nothing else is ever removed: evidence the collector hasn't
        acknowledged, the live ``cowrie.json``, and files with other names
        stay where they are.
        """
        removed: list[str] = []
        now = time.time()
        # Decisions are made only from what is saved on disk, never from
        # in-memory progress that a failed save might not have recorded.
        saved = State.load(self.config.state_path)
        for directory, kind in ((self.config.tty_dir, EvidenceKind.TTY_LOG), (self.config.download_dir, EvidenceKind.UPLOAD)):
            if directory is None or not directory.is_dir():
                continue
            present = set()
            for path in directory.iterdir():
                if not HASH_NAME.match(path.name):
                    continue
                marker = f"{kind.value}:{path.name}"
                present.add(marker)
                if marker in saved.acked or self._unpreserved_expired(saved, marker):
                    if not self._same_file(path, saved.identity.get(marker)):
                        continue
                    path.unlink()
                    removed.append(str(path))
                    self.state.acked.discard(marker)
                    self.state.unpreserved.pop(marker, None)
                    self.state.identity.pop(marker, None)
            # Forget markers whose files are gone, so the state stays small.
            prefix = f"{kind.value}:"
            self.state.acked = {m for m in self.state.acked if not m.startswith(prefix) or m in present}
            for table in (self.state.unpreserved, self.state.identity):
                for m in [m for m in table if m.startswith(prefix) and m not in present]:
                    del table[m]
            if any(r.startswith(str(directory)) for r in removed):
                fsync_dir(directory)

        directory = self.config.log_dir
        if directory is not None and directory.is_dir():
            live = set()
            for path in directory.iterdir():
                if not JSON_LOG_NAME.match(path.name) or path.is_symlink() or not path.is_file():
                    continue
                st = os.lstat(path)
                key = f"{st.st_dev}:{st.st_ino}"
                live.add(key)
                if path.name == "cowrie.json" or now - st.st_mtime < self.config.rotated_log_settle_seconds:
                    continue
                if saved.offsets.get(key) != st.st_size:
                    continue  # not every line acknowledged yet
                if key in saved.unpreserved and not self._unpreserved_expired(saved, key):
                    continue
                # A matching device:inode isn't enough (inodes are reused):
                # size and mtime must match what was read, too.
                if not self._same_file(path, saved.identity.get(key)):
                    continue
                path.unlink()
                removed.append(str(path))
                live.discard(key)
                self.state.offsets.pop(key, None)
                self.state.unpreserved.pop(key, None)
                self.state.identity.pop(key, None)
            for key in [k for k in self.state.offsets if k not in live]:
                del self.state.offsets[key]
            for table in (self.state.unpreserved, self.state.identity):
                for key in [k for k in table if k.split(":")[0].isdigit() and k not in live]:
                    del table[key]
            if any(r.startswith(str(directory)) for r in removed):
                fsync_dir(directory)

        self.state.save(self.config.state_path)
        for path in removed:
            log.info("removed acknowledged evidence %s", path)
        return removed

    def spool_bytes(self) -> int:
        total = 0
        for directory in (self.config.log_dir, self.config.tty_dir, self.config.download_dir):
            if directory is not None and directory.is_dir():
                total += sum(p.lstat().st_size for p in directory.iterdir() if p.is_file())
        return total

    # --- health, for the disk guard -----------------------------------------

    @property
    def health_path(self) -> Path:
        return self.config.state_path.with_name(self.config.state_path.stem + ".health.json")

    def probe(self) -> None:
        """Confirm the collector answers over a verified connection. Any HTTP
        status counts (it has no route for GET); no evidence is involved."""
        try:
            with urllib.request.urlopen(self.url, timeout=self.config.timeout, context=self._ssl):
                pass
        except urllib.error.HTTPError:
            return
        except (urllib.error.URLError, OSError) as e:
            raise ShipError(f"collector unreachable: {e}") from None

    def _write_health(self, error: str | None) -> None:
        now = datetime.now(timezone.utc).isoformat()
        previous = {}
        try:
            previous = json.loads(self.health_path.read_text())
        except (FileNotFoundError, ValueError):
            pass
        health = {
            "checked_at": now,
            "ok": error is None,
            "error": error,
            "last_ok_at": now if error is None else previous.get("last_ok_at"),
        }
        write_private(self.health_path, json.dumps(health).encode())

    def run_once(self) -> int:
        """Ship everything new, then remove what the collector acknowledged.
        Raises :class:`ShipError` if the collector is unavailable; progress so
        far is kept, and acknowledged evidence is still cleaned up.

        Each pass records whether it reached the collector in the health file
        next to the state file, which the disk guard reads before restarting
        Cowrie."""
        self.dead_letter.prune()
        try:
            sent = (
                self.ship_json_logs()
                + self.ship_hashed_files(self.config.tty_dir, EvidenceKind.TTY_LOG)
                + self.ship_hashed_files(self.config.download_dir, EvidenceKind.UPLOAD)
            )
            if sent == 0:
                self.probe()
        except ShipError as e:
            self._write_health(str(e))
            raise
        else:
            self._write_health(None)
            return sent
        finally:
            if self.config.delete_acknowledged:
                self.clean_spool()
            size = self.spool_bytes()
            if size > self.config.spool_warn_bytes:
                log.warning(
                    "spool holds %d MiB, over the %d MiB warning level; is the collector reachable?",
                    size // 2**20,
                    self.config.spool_warn_bytes // 2**20,
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
    p.add_argument("--dead-letter-dir", type=Path, default=Path("dead-letter"), help="where refused evidence is kept")
    p.add_argument("--dead-letter-max-mb", type=int, default=policy.DEAD_LETTER_MAX_BYTES // policy.MIB)
    p.add_argument("--dead-letter-days", type=float, default=policy.DEAD_LETTER_RETENTION_DAYS)
    p.add_argument(
        "--delete-acknowledged",
        action="store_true",
        help="remove evidence from the spool once the collector has acknowledged it",
    )
    p.add_argument(
        "--unpreserved-days",
        type=float,
        default=policy.UNPRESERVED_RETENTION_DAYS,
        help="how long refused, unpreserved evidence stays in the spool",
    )
    p.add_argument("--spool-warn-mb", type=int, default=policy.SPOOL_WARN_BYTES // policy.MIB)
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
            dead_letter_dir=args.dead_letter_dir,
            dead_letter_max_bytes=args.dead_letter_max_mb * 1024 * 1024,
            dead_letter_retention_days=args.dead_letter_days,
            delete_acknowledged=args.delete_acknowledged,
            unpreserved_retention_days=args.unpreserved_days,
            spool_warn_bytes=args.spool_warn_mb * 1024 * 1024,
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
