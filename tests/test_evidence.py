import hashlib

import pytest
from pydantic import ValidationError

from bearjug.schema import RawEvidence


def raw(**kw):
    return {
        "evidence_id": "ev-1",
        "kind": "cowrie.event",
        "sensor_id": "sensor-test",
        "session_id": "sess-1",
        "observed_at": "2026-11-18T03:00:00Z",
        "received_at": "2026-11-18T03:00:01Z",
        "sha256": hashlib.sha256(b"x").hexdigest(),
        "size_bytes": 1,
        "content": {"storage": "inline", "data": {"eventid": "cowrie.command.input"}},
        **kw,
    }


def test_inline_evidence():
    RawEvidence.model_validate(raw())


def test_sensitive_evidence_cannot_be_inline():
    with pytest.raises(ValidationError):
        RawEvidence.model_validate(raw(sensitive=True))


def test_sensitive_evidence_must_be_encrypted():
    stored = {"storage": "stored", "uri": "evidence://ev-1"}
    with pytest.raises(ValidationError):
        RawEvidence.model_validate(raw(sensitive=True, content=stored))
    RawEvidence.model_validate(
        raw(sensitive=True, content={**stored, "encryption": {"algorithm": "aes-256-gcm", "key_id": "ek-1"}})
    )


def test_bad_hash_rejected():
    with pytest.raises(ValidationError):
        RawEvidence.model_validate(raw(sha256="not-a-hash"))
