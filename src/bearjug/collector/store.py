"""The evidence store: verified, encrypted, append-only, with retention.

Layout of a collector data directory::

    config.json          retention and access settings (see Settings)
    evidence-keys.json   evidence encryption keys (0600)
    sensors.json         sensor authentication keys (0600)
    evidence.db          SQLite index: one RawEvidence record per row, plus audit log
    blobs/               AES-256-GCM encrypted original bytes, one file per record

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
from .keys import EVIDENCE_KEYS, SENSORS, EvidenceKeyring

CONFIG = "config.json"
DB = "evidence.db"
BLOBS = "blobs"

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


@dataclass
class Settings:
    """``config.json``. The retention numbers are a draft: design section 8.4
    requires them to be decided before any public sensor is deployed."""

    retention_days_default: int = 365
    retention_days_sensitive: int = 30
    max_evidence_bytes: int = 32 * 1024 * 1024
    sensitive_readers: list[str] = field(default_factory=list)
    """Actors allowed to decrypt sensitive evidence. Empty means nobody."""

    @classmethod
    def load(cls, path: Path) -> Settings:
        if not path.exists():
            return cls()
        return cls(**json.loads(path.read_text()))

    def save(self, path: Path) -> None:
        path.write_text(json.dumps(self.__dict__, indent=2) + "\n")


def _ts(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="microseconds")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def init_data_dir(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    (root / BLOBS).mkdir(exist_ok=True)
    if not (root / CONFIG).exists():
        Settings().save(root / CONFIG)
    if not (root / EVIDENCE_KEYS).exists():
        EvidenceKeyring.create(root / EVIDENCE_KEYS)
    Store(root).close()


class Store:
    def __init__(self, root: Path):
        self.root = root
        self.settings = Settings.load(root / CONFIG)
        self.keyring = EvidenceKeyring.load(root / EVIDENCE_KEYS)
        self.blobs = root / BLOBS
        self.blobs.mkdir(exist_ok=True)
        self._lock = threading.RLock()
        self.db = sqlite3.connect(root / DB, check_same_thread=False, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript(SCHEMA_SQL)

    def close(self) -> None:
        self.db.close()

    @property
    def sensors_path(self) -> Path:
        return self.root / SENSORS

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

            key_id, blob = self.keyring.encrypt(eid, digest, body)
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
                    encryption=Encryption(algorithm=self.keyring.algorithm, key_id=key_id),
                ),
            )
            path = self._blob_path(eid)
            path.parent.mkdir(exist_ok=True)
            tmp = path.with_name(path.name + ".tmp")
            with open(tmp, "wb") as f:
                f.write(blob)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)
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
        sql = "SELECT evidence_id, sensor_id, kind, sensitive, size_bytes, received_at, deleted_at FROM evidence"
        if not include_deleted:
            sql += " WHERE deleted_at IS NULL"
        with self._lock:
            return self.db.execute(sql + " ORDER BY received_at").fetchall()

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
        record = RawEvidence.model_validate_json(row["record"])
        assert isinstance(record.content, StoredContent)
        data = self.keyring.decrypt(record.content.encryption.key_id, eid, record.sha256, self._blob_path(eid).read_bytes())
        if hashlib.sha256(data).hexdigest() != record.sha256:
            raise ValueError(f"{eid}: stored bytes no longer match their sha256")
        return data

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
            self._blob_path(eid).unlink(missing_ok=True)
            self.db.execute(
                "UPDATE evidence SET deleted_at = ?, deleted_by = ?, delete_reason = ? WHERE evidence_id = ?",
                (_ts(now), actor, reason, eid),
            )
            self._audit(actor, "delete", eid, reason, now)

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
