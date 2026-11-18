import hashlib

import pytest
from pydantic import ValidationError

from bearjug.schema import RawEvidence

ENC = {"algorithm": "aes-256-gcm", "key_id": "ek-1"}
STORED = {"storage": "stored", "uri": "evidence://ev-1", "encryption": ENC}
LOGIN = {
    "eventid": "cowrie.login.failed",
    "username": "root",
    "password": "123456",
    "src_ip": "203.0.113.7",
}


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
        "content": {"storage": "inline", "data": {"eventid": "cowrie.command.input", "input": "uname -a"}},
        **kw,
    }


def test_non_sensitive_cowrie_event_can_be_inline():
    assert RawEvidence.model_validate(raw()).sensitive is False


# --- an auth record with a password can never end up inline or unflagged ----


def test_login_event_with_password_cannot_omit_the_flag():
    with pytest.raises(ValidationError, match="must be marked sensitive"):
        RawEvidence.model_validate(raw(content={"storage": "inline", "data": LOGIN}))


def test_login_event_with_password_cannot_be_inline_even_when_flagged():
    with pytest.raises(ValidationError, match="never inline"):
        RawEvidence.model_validate(raw(sensitive=True, content={"storage": "inline", "data": LOGIN}))


def test_login_event_without_password_field_is_still_sensitive():
    data = {k: v for k, v in LOGIN.items() if k != "password"}
    with pytest.raises(ValidationError, match="must be marked sensitive"):
        RawEvidence.model_validate(raw(content={"storage": "inline", "data": data}))


@pytest.mark.parametrize(
    "data",
    [
        {"eventid": "cowrie.client.custom", "Password": "x"},
        {"eventid": "cowrie.client.custom", "meta": {"auth": [{"passwd": "x"}]}},
        {"eventid": "cowrie.client.custom", "secret": "x"},
    ],
)
def test_password_field_anywhere_makes_inline_data_sensitive(data):
    with pytest.raises(ValidationError, match="must be marked sensitive"):
        RawEvidence.model_validate(raw(content={"storage": "inline", "data": data}))


def test_unclassifiable_cowrie_event_cannot_be_inline():
    with pytest.raises(ValidationError, match="cannot be classified"):
        RawEvidence.model_validate(raw(content={"storage": "inline", "data": {"input": "ls"}}))


def test_login_event_stored_encrypted_is_accepted():
    RawEvidence.model_validate(raw(sensitive=True, content=STORED))


@pytest.mark.parametrize("kind", ["tty.log", "upload"])
def test_tty_logs_and_uploads_are_always_sensitive(kind):
    with pytest.raises(ValidationError, match="must be marked sensitive"):
        RawEvidence.model_validate(raw(kind=kind, content=STORED))
    RawEvidence.model_validate(raw(kind=kind, sensitive=True, content=STORED))


# --- encryption contract -----------------------------------------------------


def test_stored_content_is_always_encrypted():
    with pytest.raises(ValidationError):
        RawEvidence.model_validate(raw(content={"storage": "stored", "uri": "evidence://ev-1"}))


@pytest.mark.parametrize("algorithm", ["aes-256-cbc", "rot13", "none", ""])
def test_only_approved_aead_algorithms(algorithm):
    with pytest.raises(ValidationError):
        RawEvidence.model_validate(raw(sensitive=True, content={**STORED, "encryption": {**ENC, "algorithm": algorithm}}))


def test_chacha20_poly1305_accepted():
    RawEvidence.model_validate(
        raw(sensitive=True, content={**STORED, "encryption": {**ENC, "algorithm": "chacha20-poly1305"}})
    )


def test_bad_hash_format_rejected():
    with pytest.raises(ValidationError):
        RawEvidence.model_validate(raw(sha256="not-a-hash"))
