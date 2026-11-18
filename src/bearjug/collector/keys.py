"""Collector-held keys.

Two separate files in the collector's data directory, never shipped anywhere:

``evidence-keys.json``
    Evidence encryption keys by ``key_id``, plus which one is active. Rotation
    adds a new key and makes it active; old keys stay only while evidence
    encrypted under them is retained.
``sensors.json``
    One shared key per sensor, used only to authenticate that sensor's
    shipper. A sensor key can't decrypt anything.

The password HMAC key (see :mod:`bearjug.schema.passwords`) is a third,
separate secret used by normalisation; ingestion doesn't need it.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..schema.evidence import EncryptionAlgorithm

EVIDENCE_KEYS = "evidence-keys.json"
SENSORS = "sensors.json"
BLOB_MAGIC = b"BJE1"
NONCE_BYTES = 12


def _write_private(path: Path, data: dict) -> None:
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)


def _aad(evidence_id: str, sha256: str) -> bytes:
    # Binds a blob to its record: it can't be swapped for another record's blob.
    return f"bearjug-evidence-v1\0{evidence_id}\0{sha256}".encode()


@dataclass
class EvidenceKeyring:
    path: Path
    active: str
    keys: dict[str, bytes]

    algorithm = EncryptionAlgorithm.AES_256_GCM

    @classmethod
    def create(cls, path: Path) -> EvidenceKeyring:
        ring = cls(path, "ek-1", {"ek-1": AESGCM.generate_key(bit_length=256)})
        ring.save()
        return ring

    @classmethod
    def load(cls, path: Path) -> EvidenceKeyring:
        raw = json.loads(path.read_text())
        keys = {k: base64.b64decode(v) for k, v in raw["keys"].items()}
        if raw["active"] not in keys or any(len(k) != 32 for k in keys.values()):
            raise ValueError(f"{path}: invalid evidence keyring")
        return cls(path, raw["active"], keys)

    def save(self) -> None:
        _write_private(
            self.path,
            {"active": self.active, "keys": {k: base64.b64encode(v).decode() for k, v in self.keys.items()}},
        )

    def rotate(self) -> str:
        n = 1 + max(int(k.split("-")[-1]) for k in self.keys)
        key_id = f"ek-{n}"
        self.keys[key_id] = AESGCM.generate_key(bit_length=256)
        self.active = key_id
        self.save()
        return key_id

    def encrypt(self, evidence_id: str, sha256: str, data: bytes) -> tuple[str, bytes]:
        nonce = secrets.token_bytes(NONCE_BYTES)
        ct = AESGCM(self.keys[self.active]).encrypt(nonce, data, _aad(evidence_id, sha256))
        return self.active, BLOB_MAGIC + nonce + ct

    def decrypt(self, key_id: str, evidence_id: str, sha256: str, blob: bytes) -> bytes:
        if not blob.startswith(BLOB_MAGIC):
            raise ValueError("not a BearJug evidence blob")
        nonce = blob[len(BLOB_MAGIC) : len(BLOB_MAGIC) + NONCE_BYTES]
        ct = blob[len(BLOB_MAGIC) + NONCE_BYTES :]
        return AESGCM(self.keys[key_id]).decrypt(nonce, ct, _aad(evidence_id, sha256))


def load_sensor_keys(path: Path) -> dict[str, bytes]:
    if not path.exists():
        return {}
    return {k: bytes.fromhex(v) for k, v in json.loads(path.read_text()).items()}


def add_sensor(path: Path, sensor_id: str) -> bytes:
    keys = load_sensor_keys(path)
    if sensor_id in keys:
        raise ValueError(f"sensor {sensor_id} already exists")
    key = secrets.token_bytes(32)
    keys[sensor_id] = key
    _write_private(path, {k: v.hex() for k, v in keys.items()})
    return key
