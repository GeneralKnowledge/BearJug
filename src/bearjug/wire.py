"""The shipper-to-collector protocol.

One request per piece of evidence: ``POST /v1/evidence`` with the original
bytes as the body and two headers:

``X-BearJug-Meta``
    Compact JSON: ``sensor_id``, ``kind``, ``sha256`` (the digest the shipper
    claims for the body), ``observed_at``, ``sent_at``.
``X-BearJug-Signature``
    Hex HMAC-SHA256, under the sensor's own key, over
    ``"bearjug-v1\\n" + meta + "\\n" + sha256(body)``.

The signature covers the body by its digest, so neither the metadata nor the
bytes can be changed in transit. ``sent_at`` bounds replay to a short window;
inside it a replay is harmless because ingestion is idempotent.

Sensor keys authenticate one sensor to the collector. They are not the evidence
encryption keys or the password HMAC key, which never leave the collector.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone

from pydantic import Field

from .schema.common import Identifier, Model, Sha256, UTCDateTime
from .schema.evidence import EvidenceKind

PATH = "/v1/evidence"
META_HEADER = "X-BearJug-Meta"
SIGNATURE_HEADER = "X-BearJug-Signature"
MAX_CLOCK_SKEW_SECONDS = 300
MIN_SENSOR_KEY_BYTES = 32
MAX_META_BYTES = 1024


class ShipMeta(Model):
    sensor_id: Identifier
    kind: EvidenceKind
    sha256: Sha256
    observed_at: UTCDateTime
    sent_at: UTCDateTime
    size_bytes: int = Field(ge=0)


def evidence_id(sensor_id: str, kind: EvidenceKind | str, data: bytes) -> str:
    """Content-derived evidence id.

    The same bytes from the same sensor always get the same id, so a retry, a
    re-read after the shipper loses its state, or a replay can never create a
    second record.
    """
    kind_value = kind.value if isinstance(kind, EvidenceKind) else kind
    h = hashlib.sha256()
    h.update(b"bearjug-evidence-id-v1\0")
    h.update(sensor_id.encode() + b"\0" + kind_value.encode() + b"\0")
    h.update(data)
    return "ev-" + h.hexdigest()


def encode_meta(meta: ShipMeta) -> str:
    return json.dumps(meta.model_dump(mode="json"), separators=(",", ":"), sort_keys=True)


def sign(key: bytes, meta: str, body: bytes) -> str:
    message = b"bearjug-v1\n" + meta.encode() + b"\n" + hashlib.sha256(body).hexdigest().encode()
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def verify(key: bytes, meta: str, body: bytes, signature: str) -> bool:
    return hmac.compare_digest(sign(key, meta, body), signature)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)
