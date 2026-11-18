"""Tier 1: raw evidence.

Raw evidence is what the sensor actually captured, kept exactly as received.
It is append-only and integrity-checked: ``sha256`` is the digest of the
original bytes, and nothing downstream ever rewrites it. Normalised events and
intelligence point back here through :class:`~bearjug.schema.common.EvidenceRef`.
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
    """A Cowrie TTY recording for one session."""
    UPLOAD = "upload"
    """A file the attacker uploaded or tried to download, held in quarantine."""


class InlineContent(Model):
    storage: Literal["inline"] = "inline"
    data: dict[str, Any]


class Encryption(Model):
    algorithm: str = Field(min_length=1)
    key_id: Identifier


class StoredContent(Model):
    """Content held outside the record, such as a TTY log or a quarantined file."""

    storage: Literal["stored"] = "stored"
    uri: str = Field(min_length=1)
    encryption: Encryption | None = None


Content = Annotated[Union[InlineContent, StoredContent], Field(discriminator="storage")]


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
    """Digest of the original bytes, before any encryption."""
    size_bytes: int = Field(ge=0)
    sensitive: bool = False
    """True when the content holds attacker-supplied plaintext secrets, such as
    a password from a login attempt."""
    content: Content

    @model_validator(mode="after")
    def _sensitive_content_is_encrypted(self) -> RawEvidence:
        # Plaintext passwords may exist only here, and only encrypted at rest.
        if self.sensitive and not (
            isinstance(self.content, StoredContent) and self.content.encryption is not None
        ):
            raise ValueError("sensitive evidence must be stored encrypted, never inline")
        return self
