"""Tier 3: intelligence.

Intelligence records are conclusions drawn from normalised events by an
analysis engine. They are versioned by engine, can be recomputed at any time,
and every conclusion carries a confidence and the events that support it, so a
reader can always go from a claim back to the evidence.
"""

from __future__ import annotations

from enum import Enum
from typing import Annotated, Any, Literal, Union

from pydantic import Field, TypeAdapter

from .common import SCHEMA_VERSION, Identifier, Model, UTCDateTime

Probability = Annotated[float, Field(ge=0.0, le=1.0)]


class Engine(Model):
    name: str = Field(min_length=1)
    version: str = Field(min_length=1)


class Support(Model):
    """How sure the engine is, and why."""

    confidence: Probability
    supporting_events: list[Identifier] = Field(min_length=1)
    """Normalised event ids the conclusion rests on."""
    rationale: str | None = None


class Scored(Model):
    value: Probability
    support: Support


class BaseIntelligence(Model):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    record_id: Identifier
    created_at: UTCDateTime
    engine: Engine


class SessionAssessment(BaseIntelligence):
    kind: Literal["session.assessment"] = "session.assessment"
    session_id: Identifier
    automation_likelihood: Scored
    """0 means clearly a human at a keyboard, 1 clearly a script."""
    credential_discovered: bool
    """True only when access came from an exact synthetic match under the
    production policy. Experimental admissions are never counted here."""


class LinkBasis(str, Enum):
    DECOY_SECRET_REUSE = "decoy_secret_reuse"
    PASSWORD_REUSE = "password_reuse"
    BEHAVIOURAL_FINGERPRINT = "behavioural_fingerprint"
    PAYLOAD_REUSE = "payload_reuse"
    SOURCE_OVERLAP = "source_overlap"


class CampaignLink(BaseIntelligence):
    """Assigns a session to a campaign."""

    kind: Literal["campaign.link"] = "campaign.link"
    campaign_id: Identifier
    session_id: Identifier
    basis: list[LinkBasis] = Field(min_length=1)
    support: Support


Intelligence = Annotated[
    Union[SessionAssessment, CampaignLink],
    Field(discriminator="kind"),
]

INTELLIGENCE_ADAPTER: TypeAdapter[Intelligence] = TypeAdapter(Intelligence)


def parse_intelligence(data: dict[str, Any] | str | bytes) -> Intelligence:
    if isinstance(data, (str, bytes)):
        return INTELLIGENCE_ADAPTER.validate_json(data)
    return INTELLIGENCE_ADAPTER.validate_python(data)
