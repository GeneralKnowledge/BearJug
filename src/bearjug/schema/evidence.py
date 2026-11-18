"""Tier 1: raw evidence.

Raw evidence is what the sensor actually captured, kept exactly as received.
It is append-only: ``sha256`` is the digest of the original bytes, and nothing
downstream ever rewrites it. Normalised events and intelligence point back here
through :class:`~bearjug.schema.common.EvidenceRef`.

The schema checks that ``sha256`` is well formed. It cannot check that it
matches the bytes: the collector must compute and compare the digest before it
accepts evidence (roadmap PR 3–4).

Sensitivity is not left to the producer. The model works out whether a record
can hold attacker plaintext secrets from its kind and content, and rejects any
record that understates it. Sensitive records can never be inline, and stored
content is always encrypted with an approved AEAD algorithm.
"""

from __future__ import annotations

from enum import Enum
from typing import Annotated, Any, Literal, Union

from pydantic import Field, model_validator

from .common import SCHEMA_VERSION, Identifier, Model, Sha256, UTCDateTime


class EvidenceKind(str, Enum):
    COWRIE_EVENT = "cowrie.event"
    """One line of Cowrie's JSON log, verbatim."""
    TTY_LOG = "tty.log"
    """A Cowrie TTY recording for one session. Always sensitive: it holds every
    keystroke, including any password typed at a prompt."""
    UPLOAD = "upload"
    """A file the attacker uploaded or tried to download, held in quarantine.
    Always sensitive."""


ALWAYS_SENSITIVE_KINDS = frozenset({EvidenceKind.TTY_LOG, EvidenceKind.UPLOAD})

SENSITIVE_COWRIE_EVENT_PREFIXES = ("cowrie.login.",)
"""Cowrie events that carry the attempted password."""

SECRET_KEY_NAMES = frozenset({"password", "passwd", "pass", "pwd", "passphrase", "secret"})
"""Field names that mark inline data as holding a secret, at any depth."""


class EncryptionAlgorithm(str, Enum):
    """Authenticated encryption algorithms accepted for stored evidence."""

    AES_256_GCM = "aes-256-gcm"
    CHACHA20_POLY1305 = "chacha20-poly1305"


class InlineContent(Model):
    storage: Literal["inline"] = "inline"
    data: dict[str, Any]


class Encryption(Model):
    algorithm: EncryptionAlgorithm
    key_id: Identifier
    """Version of the collector-held data key that encrypted the content. Used
    for rotation; the key itself never appears in any record."""


class StoredContent(Model):
    """Content held outside the record, such as a TTY log or a quarantined file.

    Always encrypted, so nothing that leaves the record is ever stored in the
    clear, whatever it turns out to contain.
    """

    storage: Literal["stored"] = "stored"
    uri: str = Field(min_length=1)
    encryption: Encryption


Content = Annotated[Union[InlineContent, StoredContent], Field(discriminator="storage")]


def _has_secret_key(value: Any) -> bool:
    if isinstance(value, dict):
        return any(
            (isinstance(k, str) and k.lower() in SECRET_KEY_NAMES) or _has_secret_key(v)
            for k, v in value.items()
        )
    if isinstance(value, list):
        return any(_has_secret_key(v) for v in value)
    return False


def sensitivity_reason(kind: EvidenceKind, content: InlineContent | StoredContent) -> str | None:
    """Why evidence of this kind and content must be treated as sensitive, or None."""
    if kind in ALWAYS_SENSITIVE_KINDS:
        return f"{kind.value} evidence is always sensitive"
    if isinstance(content, InlineContent):
        eventid = content.data.get("eventid")
        if not isinstance(eventid, str):
            return "cowrie event without an eventid cannot be classified"
        if eventid.startswith(SENSITIVE_COWRIE_EVENT_PREFIXES):
            return f"{eventid} carries an attempted password"
        if _has_secret_key(content.data):
            return "inline data contains a password or secret field"
    return None


class RawEvidence(Model):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    evidence_id: Identifier
    kind: EvidenceKind
    sensor_id: Identifier
    session_id: Identifier | None = None
    observed_at: UTCDateTime
    """When the sensor captured it."""
    received_at: UTCDateTime
    """When the collector accepted it."""
    sha256: Sha256
    """Digest of the original bytes, before any encryption. Format-checked
    here; verified against the bytes by the collector."""
    size_bytes: int = Field(ge=0)
    sensitive: bool = False
    """True when the content may hold attacker-supplied plaintext secrets. A
    producer may set it for any record, but cannot clear it for one the schema
    classifies as sensitive."""
    content: Content

    @model_validator(mode="after")
    def _sensitivity_is_derived_and_enforced(self) -> RawEvidence:
        reason = sensitivity_reason(self.kind, self.content)
        if reason is not None and not self.sensitive:
            raise ValueError(f"evidence must be marked sensitive: {reason}")
        # Plaintext secrets may exist only here, and only encrypted at rest.
        if self.sensitive and isinstance(self.content, InlineContent):
            raise ValueError("sensitive evidence must be stored encrypted, never inline")
        return self
