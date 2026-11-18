"""The evidence store: verified, encrypted, append-only, with retention.

Layout of a collector data directory::

    config.json          retention and access settings (see Settings)
    evidence-keys.json   evidence encryption keys (0600)
    sensors.json         sensor authentication keys (0600)
    evidence.db          SQLite index: one RawEvidence record per row, audit log,
                         sensor last-seen, integrity issues, collector heartbeat
    blobs/               AES-256-GCM encrypted original bytes, one file per record
    orphans/             encrypted blobs found without a record (see reconcile)

Every piece of evidence is kept as its original bytes, encrypted, whatever its
sensitivity. The database holds the :class:`RawEvidence` record (metadata only,
never content) and refuses, by trigger, any change other than marking a record
deleted, and any change at all to the audit log.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from pydantic import TypeAdapter, ValidationError

from ..schema.common import Identifier
from ..schema.evidence import (
    ALWAYS_SENSITIVE_KINDS,
    Encryption,
    EvidenceKind,
    InlineContent,
    RawEvidence,
    StoredContent,
    sensitivity_reason,
)
from ..wire import ShipMeta, evidence_id
from .keys import (
    _write_private,
    EVIDENCE_KEYS,
    SENSORS,
    EvidenceKeyring,
    SensorEntry,
    file_signature,
    load_sensors,
    new_sensor_key,
    save_sensors,
)

CONFIG = "config.json"
DB = "evidence.db"
BLOBS = "blobs"
ORPHANS = "orphans"
HEARTBEAT_STALE_SECONDS = 15

_identifier = TypeAdapter(Identifier)

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS evidence (
    evidence_id   TEXT PRIMARY KEY,
    sensor_id     TEXT NOT NULL,
    kind          TEXT NOT NULL,
    sensitive     INTEGER NOT NULL,
    sha256        TEXT NOT NULL,
    size_bytes    INTEGER NOT NULL,
    received_at   TEXT NOT NULL,
    record        TEXT NOT NULL,
    deleted_at    TEXT,
    deleted_by    TEXT,
    delete_reason TEXT
);
CREATE INDEX IF NOT EXISTS evidence_received ON evidence (received_at);

CREATE TABLE IF NOT EXISTS audit (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    at          TEXT NOT NULL,
    actor       TEXT NOT NULL,
    action      TEXT NOT NULL,
    evidence_id TEXT,
    reason      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sensor_seen (
    sensor_id    TEXT PRIMARY KEY,
    last_seen_at TEXT NOT NULL,
    last_ip      TEXT
);

CREATE TABLE IF NOT EXISTS integrity_issue (
    evidence_id TEXT PRIMARY KEY,
    issue       TEXT NOT NULL,
    detected_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS collector_state (
    name  TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TRIGGER IF NOT EXISTS evidence_no_delete BEFORE DELETE ON evidence
BEGIN SELECT RAISE(ABORT, 'evidence is append-only'); END;

CREATE TRIGGER IF NOT EXISTS evidence_only_tombstone BEFORE UPDATE ON evidence
WHEN old.deleted_at IS NOT NULL
  OR new.deleted_at IS NULL
  OR new.evidence_id IS NOT old.evidence_id
  OR new.sensor_id IS NOT old.sensor_id
  OR new.kind IS NOT old.kind
  OR new.sensitive IS NOT old.sensitive
  OR new.sha256 IS NOT old.sha256
  OR new.size_bytes IS NOT old.size_bytes
  OR new.received_at IS NOT old.received_at
  OR new.record IS NOT old.record
BEGIN SELECT RAISE(ABORT, 'evidence is append-only'); END;

CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
"""


class IngestError(Exception):
    """Evidence refused. ``status`` is the HTTP status the server returns."""

    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


class EvidenceMissing(Exception):
    """A live record's encrypted bytes are gone. Never treated as healthy."""


@dataclass
class ReconcileReport:
    temp_files_removed: list[str] = field(default_factory=list)
    """Interrupted blob writes: never referenced by any record."""
    orphans_quarantined: list[str] = field(default_factory=list)
    """Blobs with no record (a crash between the blob write and the insert).
    The shipper was never told the evidence was stored, so it resends it."""
    deletions_completed: list[str] = field(default_factory=list)
    """Tombstoned records whose blob was still there (a crash mid-delete)."""
    missing: list[str] = field(default_factory=list)
    """Live records with no blob. Recorded as integrity issues."""
    corrupt: list[str] = field(default_factory=list)
    """Deep check only: blobs that don't decrypt or don't match their sha256."""

    @property
    def healthy(self) -> bool:
        return not self.missing and not self.corrupt


@dataclass
class Settings:
    """``config.json``. The retention numbers are a draft: design section 8.4
    requires them to be decided before any public sensor is deployed."""

    retention_days_default: int = 365
    retention_days_sensitive: int = 30
    max_evidence_bytes: int = 32 * 1024 * 1024
    sensitive_readers: list[str] = field(default_factory=list)
    """Actors allowed to decrypt sensitive evidence. Empty means nobody."""

    # Limits on what an unauthenticated client can make the collector do.
    max_concurrent_requests: int = 16
    """Connections beyond this are closed at once, before anything is read."""
    request_deadline_seconds: float = 60.0
    """Hard limit on one connection's lifetime, however slowly it sends."""
    idle_timeout_seconds: float = 10.0
    """Socket timeout for each read or write."""
    rate_limit_per_second: float = 100.0
    rate_limit_burst: int = 500
    """Per client IP, all requests."""
    auth_failures_per_minute: float = 10.0
    """Per client IP; beyond this, every request from that IP gets 429 until
    the bucket refills."""

    @classmethod
    def load(cls, path: Path) -> Settings:
        if not path.exists():
            return cls()
        known = set(cls.__dataclass_fields__)
        raw = json.loads(path.read_text())
        unknown = set(raw) - known
        if unknown:
            raise ValueError(f"{path}: unknown settings {sorted(unknown)}")
        return cls(**raw)

    def save(self, path: Path) -> None:
        _write_private(path, json.dumps(self.__dict__, indent=2) + "\n")


def _private_dir(path: Path) -> Path:
    """Create a directory only the collector's user can enter. The mode is
    set explicitly, so it doesn't depend on the umask."""
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    return path


def _ts(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="microseconds")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def init_data_dir(root: Path) -> None:
    _private_dir(root)
    _private_dir(root / BLOBS)
    if not (root / CONFIG).exists():
        Settings().save(root / CONFIG)
    if not (root / EVIDENCE_KEYS).exists():
        EvidenceKeyring.create(root / EVIDENCE_KEYS)
    Store(root).close()


class Store:
    def __init__(self, root: Path):
        self.root = root
        self.settings = Settings.load(root / CONFIG)
        self.blobs = root / BLOBS
        _private_dir(root)
        _private_dir(self.blobs)
        self._lock = threading.RLock()
        self._keyring_sig: tuple | None = None
        self._sensors_sig: tuple | None = None
        self._sensors: dict[str, SensorEntry] = {}
        self.db = sqlite3.connect(root / DB, check_same_thread=False, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript(SCHEMA_SQL)
        for name in (DB, DB + "-wal", DB + "-shm"):
            if (root / name).exists():
                os.chmod(root / name, 0o600)
        self.refresh_keyring()

    def close(self) -> None:
        self.db.close()

    # --- evidence keys ----------------------------------------------------

    def refresh_keyring(self) -> EvidenceKeyring:
        """Reload the keyring if the file changed. Called before every encrypt
        and decrypt, so a rotation made by the CLI applies to the very next
        piece of evidence a running collector stores."""
        path = self.root / EVIDENCE_KEYS
        with self._lock:
            sig = file_signature(path)
            if sig != self._keyring_sig:
                self.keyring = EvidenceKeyring.load(path)
                self._keyring_sig = sig
            return self.keyring

    def rotate_key(self, *, actor: str) -> str:
        with self._lock:
            ring = EvidenceKeyring.load(self.root / EVIDENCE_KEYS)
            key_id = ring.rotate()
            self._audit(actor, "rotate-evidence-key", None, f"active evidence key is now {key_id}")
            self.refresh_keyring()
            return key_id

    def heartbeat(self, *, now: datetime | None = None) -> None:
        """Record, for the CLI to check, which evidence key this running
        collector is encrypting with right now."""
        ring = self.refresh_keyring()
        with self._lock:
            self.db.executemany(
                "INSERT INTO collector_state (name, value) VALUES (?, ?)"
                " ON CONFLICT(name) DO UPDATE SET value = excluded.value",
                [("heartbeat_at", _ts(now or _now())), ("encrypting_key_id", ring.active), ("pid", str(os.getpid()))],
            )

    def running_collector(self, *, now: datetime | None = None) -> dict | None:
        """The key id a running collector reported in the last few seconds,
        or None if no collector is running."""
        with self._lock:
            state = {r["name"]: r["value"] for r in self.db.execute("SELECT name, value FROM collector_state")}
        if "heartbeat_at" not in state:
            return None
        age = (now or _now()) - datetime.fromisoformat(state["heartbeat_at"])
        if age > timedelta(seconds=HEARTBEAT_STALE_SECONDS):
            return None
        return state

    # --- sensors ----------------------------------------------------------

    @property
    def sensors_path(self) -> Path:
        return self.root / SENSORS

    def _load_sensors(self) -> dict[str, SensorEntry]:
        with self._lock:
            sig = file_signature(self.sensors_path)
            if sig != self._sensors_sig:
                self._sensors = load_sensors(self.sensors_path)
                self._sensors_sig = sig
            return self._sensors

    def sensor_key(self, sensor_id: str) -> bytes | None:
        """The key of an active sensor; None for unknown or revoked sensors.
        Re-read when the file changes, so revocation takes effect at once."""
        entry = self._load_sensors().get(sensor_id)
        return entry.key if entry is not None and entry.status == "active" else None

    def add_sensor(self, sensor_id: str, *, actor: str) -> bytes:
        _identifier.validate_python(sensor_id)
        with self._lock:
            sensors = load_sensors(self.sensors_path)
            if sensor_id in sensors:
                raise ValueError(f"sensor {sensor_id} already exists")
            key = new_sensor_key()
            sensors[sensor_id] = SensorEntry(key=key, registered_at=_ts(_now()))
            save_sensors(self.sensors_path, sensors)
            self._audit(actor, "sensor-register", None, f"registered sensor {sensor_id}")
            return key

    def replace_sensor_key(self, sensor_id: str, *, actor: str, reason: str) -> bytes:
        """Issue a new key; the old one stops working immediately. Evidence
        keys are not touched."""
        with self._lock:
            sensors = load_sensors(self.sensors_path)
            entry = sensors.get(sensor_id)
            if entry is None:
                raise KeyError(sensor_id)
            key = new_sensor_key()
            sensors[sensor_id] = SensorEntry(
                key=key, registered_at=entry.registered_at, key_replaced_at=_ts(_now())
            )
            save_sensors(self.sensors_path, sensors)
            self._audit(actor, "sensor-key-replace", None, f"{sensor_id}: {reason}")
            return key

    def revoke_sensor(self, sensor_id: str, *, actor: str, reason: str) -> None:
        """Refuse all further uploads from a sensor. Its key is overwritten so
        it can't be re-enabled by mistake; issue a new key to bring it back.
        Evidence it already sent is kept, and evidence keys are not touched."""
        with self._lock:
            sensors = load_sensors(self.sensors_path)
            entry = sensors.get(sensor_id)
            if entry is None:
                raise KeyError(sensor_id)
            sensors[sensor_id] = SensorEntry(
                key=new_sensor_key(),
                status="revoked",
                registered_at=entry.registered_at,
                key_replaced_at=entry.key_replaced_at,
                revoked_at=_ts(_now()),
            )
            save_sensors(self.sensors_path, sensors)
            self._audit(actor, "sensor-revoke", None, f"{sensor_id}: {reason}")

    def mark_seen(self, sensor_id: str, ip: str, *, now: datetime | None = None) -> None:
        with self._lock:
            self.db.execute(
                "INSERT INTO sensor_seen (sensor_id, last_seen_at, last_ip) VALUES (?, ?, ?)"
                " ON CONFLICT(sensor_id) DO UPDATE SET last_seen_at = excluded.last_seen_at, last_ip = excluded.last_ip",
                (sensor_id, _ts(now or _now()), ip),
            )

    def sensors(self) -> list[dict]:
        with self._lock:
            seen = {r["sensor_id"]: r for r in self.db.execute("SELECT * FROM sensor_seen")}
        out = []
        for sid, e in sorted(load_sensors(self.sensors_path).items()):
            r = seen.get(sid)
            out.append(
                {
                    "sensor_id": sid,
                    "status": e.status,
                    "registered_at": e.registered_at,
                    "key_replaced_at": e.key_replaced_at,
                    "revoked_at": e.revoked_at,
                    "last_seen_at": r["last_seen_at"] if r else None,
                    "last_ip": r["last_ip"] if r else None,
                }
            )
        return out

    # --- ingestion --------------------------------------------------------

    def ingest(self, meta: ShipMeta, body: bytes, *, now: datetime | None = None) -> tuple[str, str]:
        """Verify and store one piece of evidence. Returns ``(status, evidence_id)``
        where status is ``stored``, ``duplicate`` or ``deleted`` (already
        removed under retention; not stored again)."""
        if len(body) > self.settings.max_evidence_bytes:
            raise IngestError(413, "evidence too large")
        if len(body) != meta.size_bytes:
            raise IngestError(422, "size does not match the bytes received")
        digest = hashlib.sha256(body).hexdigest()
        if digest != meta.sha256:
            raise IngestError(422, "sha256 does not match the bytes received")

        eid = evidence_id(meta.sensor_id, meta.kind, body)
        sensitive, session_id, observed_at = self._classify(meta, body)
        now = now or _now()

        with self._lock:
            existing = self._row(eid)
            if existing is not None:
                if existing["sha256"] != digest:  # only possible on a hash collision
                    raise IngestError(409, "evidence id already holds different bytes")
                return ("deleted" if existing["deleted_at"] else "duplicate"), eid

            ring = self.refresh_keyring()
            key_id, blob = ring.encrypt(eid, digest, body)
            record = RawEvidence(
                evidence_id=eid,
                kind=meta.kind,
                sensor_id=meta.sensor_id,
                session_id=session_id,
                observed_at=observed_at,
                received_at=now,
                sha256=digest,
                size_bytes=len(body),
                sensitive=sensitive,
                content=StoredContent(
                    uri=f"blob:{eid}",
                    encryption=Encryption(algorithm=ring.algorithm, key_id=key_id),
                ),
            )
            path = self._blob_path(eid)
            _private_dir(path.parent)
            tmp = path.with_name(path.name + ".tmp")
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(blob)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)
            # A crash here leaves a blob with no record; reconcile() quarantines
            # it, and since no reply was sent the shipper resends it.
            self.db.execute(
                "INSERT INTO evidence (evidence_id, sensor_id, kind, sensitive, sha256, size_bytes, received_at, record)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (eid, meta.sensor_id, meta.kind.value, int(sensitive), digest, len(body), _ts(now), record.model_dump_json()),
            )
        return "stored", eid

    def _classify(self, meta: ShipMeta, body: bytes) -> tuple[bool, str | None, datetime]:
        """Work out sensitivity (and, for Cowrie events, session and time) from
        the bytes themselves; the sensor's say-so is never trusted for this."""
        if meta.kind in ALWAYS_SENSITIVE_KINDS:
            return True, None, meta.observed_at
        try:
            data = json.loads(body)
        except (ValueError, UnicodeDecodeError):
            raise IngestError(422, "cowrie.event is not valid JSON") from None
        if not isinstance(data, dict):
            raise IngestError(422, "cowrie.event is not a JSON object")
        if not isinstance(data.get("eventid"), str):
            raise IngestError(422, "cowrie.event without an eventid cannot be classified")
        reason = sensitivity_reason(meta.kind, InlineContent(data=data))
        session_id = None
        try:
            session_id = _identifier.validate_python(data.get("session"))
        except ValidationError:
            pass
        observed_at = meta.observed_at
        ts = data.get("timestamp")
        if isinstance(ts, str):
            try:
                parsed = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                if parsed.tzinfo is not None:
                    observed_at = parsed
            except ValueError:
                pass
        return reason is not None, session_id, observed_at

    # --- access -----------------------------------------------------------

    def _row(self, eid: str) -> sqlite3.Row | None:
        with self._lock:
            return self.db.execute("SELECT * FROM evidence WHERE evidence_id = ?", (eid,)).fetchone()

    def _blob_path(self, eid: str) -> Path:
        return self.blobs / eid[3:5] / eid

    def _audit(self, actor: str, action: str, eid: str | None, reason: str, now: datetime | None = None) -> None:
        self.db.execute(
            "INSERT INTO audit (at, actor, action, evidence_id, reason) VALUES (?, ?, ?, ?, ?)",
            (_ts(now or _now()), actor, action, eid, reason),
        )

    def record(self, eid: str) -> RawEvidence | None:
        row = self._row(eid)
        return None if row is None else RawEvidence.model_validate_json(row["record"])

    def list(self, *, include_deleted: bool = False) -> list[sqlite3.Row]:
        sql = (
            "SELECT e.evidence_id, e.sensor_id, e.kind, e.sensitive, e.size_bytes, e.received_at, e.deleted_at,"
            " i.issue FROM evidence e LEFT JOIN integrity_issue i ON i.evidence_id = e.evidence_id"
        )
        if not include_deleted:
            sql += " WHERE e.deleted_at IS NULL"
        with self._lock:
            return self.db.execute(sql + " ORDER BY e.received_at").fetchall()

    def read(self, eid: str, *, actor: str, reason: str) -> bytes:
        """Decrypt evidence. Every attempt is audited; sensitive evidence only
        for actors in ``sensitive_readers``. The bytes are re-hashed and must
        still match the record."""
        if not reason.strip():
            raise PermissionError("a reason is required to read evidence")
        with self._lock:
            row = self._row(eid)
            if row is None or row["deleted_at"]:
                raise KeyError(eid)
            if row["sensitive"] and actor not in self.settings.sensitive_readers:
                self._audit(actor, "read-denied", eid, reason)
                raise PermissionError(f"{actor} may not read sensitive evidence")
            self._audit(actor, "read", eid, reason)
        return self._decrypt(row)

    def _decrypt(self, row: sqlite3.Row) -> bytes:
        eid = row["evidence_id"]
        record = RawEvidence.model_validate_json(row["record"])
        assert isinstance(record.content, StoredContent)
        try:
            blob = self._blob_path(eid).read_bytes()
        except FileNotFoundError:
            self._flag(eid, "blob missing")
            raise EvidenceMissing(f"{eid}: encrypted bytes are missing") from None
        data = self.refresh_keyring().decrypt(record.content.encryption.key_id, eid, record.sha256, blob)
        if hashlib.sha256(data).hexdigest() != record.sha256:
            raise ValueError(f"{eid}: stored bytes no longer match their sha256")
        return data

    def _flag(self, eid: str, issue: str) -> None:
        with self._lock:
            self.db.execute(
                "INSERT INTO integrity_issue (evidence_id, issue, detected_at) VALUES (?, ?, ?)"
                " ON CONFLICT(evidence_id) DO UPDATE SET issue = excluded.issue",
                (eid, issue, _ts(_now())),
            )

    def integrity_issues(self) -> list[sqlite3.Row]:
        with self._lock:
            return self.db.execute("SELECT * FROM integrity_issue ORDER BY detected_at").fetchall()

    def reconcile(self, *, deep: bool = False) -> ReconcileReport:
        """Make the blob directory and the records agree after a crash, and
        report anything that can't be repaired. Run at collector start and by
        ``bearjug-collector check``.

        Only safe repairs are made: leftover temp files are removed, blobs
        with no record are moved to ``orphans/`` (never deleted), and an
        interrupted deletion is finished. A live record without its blob is
        never repaired or hidden: it is flagged as an integrity issue, shown
        by ``list`` and ``check``, and reads of it fail.
        """
        report = ReconcileReport()
        with self._lock:
            rows = {r["evidence_id"]: r for r in self.db.execute("SELECT * FROM evidence")}
            on_disk = set()
            for path in self.blobs.glob("*/*"):
                if path.name.endswith(".tmp"):
                    path.unlink()
                    report.temp_files_removed.append(path.name)
                    continue
                on_disk.add(path.name)
                row = rows.get(path.name)
                if row is None:
                    orphans = self.root / ORPHANS
                    _private_dir(orphans)
                    os.replace(path, orphans / path.name)
                    report.orphans_quarantined.append(path.name)
                    self._audit("reconcile", "orphan-quarantined", path.name, "encrypted blob had no record")
                elif row["deleted_at"]:
                    path.unlink()
                    report.deletions_completed.append(path.name)
                    self._audit("reconcile", "delete-completed", path.name, "blob of a deleted record removed")
            for eid, row in rows.items():
                if row["deleted_at"]:
                    continue
                if eid not in on_disk:
                    report.missing.append(eid)
                    self._flag(eid, "blob missing")
                elif deep:
                    try:
                        self._decrypt(row)
                    except Exception as e:  # noqa: BLE001
                        report.corrupt.append(eid)
                        self._flag(eid, f"blob unreadable: {type(e).__name__}")
        return report

    def delete(self, eid: str, *, actor: str, reason: str, now: datetime | None = None) -> None:
        """Remove the encrypted bytes and keep a tombstone, so the record's
        metadata and the fact of deletion survive, and a resend is not stored
        again."""
        if not reason.strip():
            raise PermissionError("a reason is required to delete evidence")
        now = now or _now()
        with self._lock:
            row = self._row(eid)
            if row is None:
                raise KeyError(eid)
            if row["deleted_at"]:
                return
            # Tombstone first: a crash before the unlink leaves a blob that
            # reconcile() finishes deleting, never a live record with no blob.
            self.db.execute(
                "UPDATE evidence SET deleted_at = ?, deleted_by = ?, delete_reason = ? WHERE evidence_id = ?",
                (_ts(now), actor, reason, eid),
            )
            self._audit(actor, "delete", eid, reason, now)
            self._blob_path(eid).unlink(missing_ok=True)

    def purge(self, *, now: datetime | None = None) -> list[str]:
        """Delete everything past its retention period."""
        now = now or _now()
        s = self.settings
        sensitive_cutoff = _ts(now - timedelta(days=s.retention_days_sensitive))
        default_cutoff = _ts(now - timedelta(days=s.retention_days_default))
        with self._lock:
            rows = self.db.execute(
                "SELECT evidence_id FROM evidence WHERE deleted_at IS NULL AND"
                " ((sensitive = 1 AND received_at < ?) OR (sensitive = 0 AND received_at < ?))",
                (sensitive_cutoff, default_cutoff),
            ).fetchall()
        expired = [r[0] for r in rows]
        for eid in expired:
            self.delete(eid, actor="retention", reason="retention period expired", now=now)
        return expired

    def audit_log(self) -> list[sqlite3.Row]:
        with self._lock:
            return self.db.execute("SELECT * FROM audit ORDER BY id").fetchall()
