"""Types shared by all three data tiers."""

from __future__ import annotations

from datetime import datetime, timezone
from ipaddress import IPv4Address, IPv6Address
from typing import Annotated

from pydantic import AfterValidator, BaseModel, ConfigDict, Field

SCHEMA_VERSION = "1.0"


def _require_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamps must be timezone-aware")
    return value.astimezone(timezone.utc)


UTCDateTime = Annotated[datetime, AfterValidator(_require_utc)]
"""A timezone-aware timestamp, normalised to UTC."""

Sha256 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
"""Lower-case hex SHA-256 digest."""

Identifier = Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")]
"""Opaque id: sensor ids, session ids, profile ids, event ids and so on."""


class Model(BaseModel):
    """Base for every schema record.

    Records are immutable and reject unknown fields, so a stray field such as a
    plaintext ``password`` cannot slip into a tier that must not hold it.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)


class Endpoint(Model):
    """A network endpoint as seen by the sensor."""

    ip: IPv4Address | IPv6Address
    port: int = Field(ge=0, le=65535)


class EvidenceRef(Model):
    """Pointer from a derived record back to the raw evidence it came from."""

    evidence_id: Identifier
    sha256: Sha256
