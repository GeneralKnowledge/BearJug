"""Tier 2: normalised events.

Normalised events are derived from raw evidence by a parser, and can be thrown
away and regenerated when the parser changes. Every event names the parser that
produced it and points back to at least one piece of raw evidence.

Passwords appear here only as a keyed hash (:class:`PasswordRef`).
"""

from __future__ import annotations

from enum import Enum
from typing import Annotated, Any, Literal, Union

from pydantic import Field, TypeAdapter, model_validator

from .common import (
    SCHEMA_VERSION,
    Endpoint,
    EvidenceRef,
    Identifier,
    Model,
    Sha256,
    UTCDateTime,
)
from .passwords import PasswordRef

# --- authentication policy -------------------------------------------------

RULE_EXACT_SYNTHETIC_MATCH = "exact_synthetic_match"
RULE_NO_SYNTHETIC_MATCH = "no_synthetic_match"
PRODUCTION_RULES = frozenset({RULE_EXACT_SYNTHETIC_MATCH, RULE_NO_SYNTHETIC_MATCH})


class PolicyKind(str, Enum):
    PRODUCTION = "production"
    EXPERIMENTAL = "experimental"


class AuthPolicy(Model):
    """Which credential policy was in force.

    Anything other than exact synthetic matching (for example "accept after N
    attempts") is an experiment and must say so, with its experiment id, so
    analysis can separate it from genuine credential discovery.
    """

    kind: PolicyKind
    experiment_id: Identifier | None = None

    @model_validator(mode="after")
    def _experiment_id_matches_kind(self) -> AuthPolicy:
        if self.kind is PolicyKind.EXPERIMENTAL and self.experiment_id is None:
            raise ValueError("experimental policy requires an experiment_id")
        if self.kind is PolicyKind.PRODUCTION and self.experiment_id is not None:
            raise ValueError("production policy must not carry an experiment_id")
        return self


class AuthDecision(str, Enum):
    ACCEPT = "accept"
    REJECT = "reject"


# --- base -------------------------------------------------------------------


class BaseEvent(Model):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    event_id: Identifier
    occurred_at: UTCDateTime
    sensor_id: Identifier
    profile_id: Identifier
    """The deception profile active on the sensor."""
    session_id: Identifier
    parser: str = Field(min_length=1)
    """Name and version of the parser that produced this event."""
    evidence: list[EvidenceRef] = Field(min_length=1)


# --- authentication and sessions ---------------------------------------------


class AuthAttempt(BaseEvent):
    event_type: Literal["auth.attempt"] = "auth.attempt"
    src: Endpoint
    username: str
    password: PasswordRef
    decision: AuthDecision
    rule: Identifier
    """The rule that produced the decision."""
    policy: AuthPolicy

    @model_validator(mode="after")
    def _production_accepts_only_exact_matches(self) -> AuthAttempt:
        if self.policy.kind is PolicyKind.PRODUCTION:
            if self.rule not in PRODUCTION_RULES:
                raise ValueError(
                    f"production policy rule must be one of {sorted(PRODUCTION_RULES)}"
                )
            expected = (
                AuthDecision.ACCEPT
                if self.rule == RULE_EXACT_SYNTHETIC_MATCH
                else AuthDecision.REJECT
            )
            if self.decision is not expected:
                raise ValueError(f"rule {self.rule!r} must produce decision {expected.value!r}")
        return self


class SessionStart(BaseEvent):
    event_type: Literal["session.start"] = "session.start"
    src: Endpoint
    account: str
    """The synthetic account the attacker logged in as."""
    policy: AuthPolicy
    returning_visitor: bool | None = None
    """None until the collector has checked for earlier visits."""


class SessionEnd(BaseEvent):
    event_type: Literal["session.end"] = "session.end"
    duration_seconds: float = Field(ge=0)
    reason: str | None = None


# --- commands -----------------------------------------------------------------


class CommandInput(BaseEvent):
    event_type: Literal["command.input"] = "command.input"
    sequence: int = Field(ge=0)
    """Position of this command within the session, from 0."""
    line: str
    """The line as the attacker entered it."""
    command: str
    args: list[str] = Field(default_factory=list)
    handler: str | None = None
    """The simulated handler that answered, if any."""
    since_previous_ms: int | None = Field(default=None, ge=0)


class Outcome(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"


class CommandResult(BaseEvent):
    event_type: Literal["command.result"] = "command.result"
    sequence: int = Field(ge=0)
    outcome: Outcome
    """Outcome of the simulated operation as shown to the attacker."""
    error_class: str | None = None


# --- what they did -------------------------------------------------------------


class FsOperation(str, Enum):
    READ = "read"
    LIST = "list"
    SEARCH = "search"
    WRITE = "write"
    DELETE = "delete"


class FsAccess(BaseEvent):
    event_type: Literal["fs.access"] = "fs.access"
    path: str
    operation: FsOperation


class OutboundSimulated(BaseEvent):
    """An attempted outbound action. Recorded, answered locally, never made."""

    event_type: Literal["outbound.simulated"] = "outbound.simulated"
    tool: str
    url: str | None = None
    host: str | None = None
    port: int | None = Field(default=None, ge=0, le=65535)
    simulated_response: str
    """Short description of what the attacker was shown, e.g. "http 404"."""
    connection_made: Literal[False] = False
    """Always false. A record claiming a real connection is rejected."""

    @model_validator(mode="after")
    def _has_destination(self) -> OutboundSimulated:
        if self.url is None and self.host is None:
            raise ValueError("outbound.simulated needs a url or a host")
        return self


class DiscoveryAttempt(BaseEvent):
    event_type: Literal["discovery.attempt"] = "discovery.attempt"
    technique: str
    target: str | None = None
    """The fictional host, network or service they looked for."""


class PrivescSimulated(BaseEvent):
    event_type: Literal["privesc.simulated"] = "privesc.simulated"
    technique: str
    outcome: Outcome


class PersistenceAttempt(BaseEvent):
    event_type: Literal["persistence.attempt"] = "persistence.attempt"
    mechanism: str
    """For example cron, authorized_keys, systemd, rc_file."""
    target: str
    """Path or unit name."""


class SecretAccessed(BaseEvent):
    event_type: Literal["secret.accessed"] = "secret.accessed"
    decoy_id: Identifier
    location: str
    """Where they found it, usually a path."""


class SecretUsed(BaseEvent):
    event_type: Literal["secret.used"] = "secret.used"
    decoy_id: Identifier
    used_with: str
    """The tool or command they used it with."""
    target: str | None = None


class UploadReceived(BaseEvent):
    event_type: Literal["upload.received"] = "upload.received"
    quarantine_ref: str = Field(min_length=1)
    size_bytes: int = Field(ge=0)
    sha256: Sha256
    filename_as_given: str | None = None
    """Name the attacker supplied, for analysis only. Never used as a path."""


Event = Annotated[
    Union[
        AuthAttempt,
        SessionStart,
        SessionEnd,
        CommandInput,
        CommandResult,
        FsAccess,
        OutboundSimulated,
        DiscoveryAttempt,
        PrivescSimulated,
        PersistenceAttempt,
        SecretAccessed,
        SecretUsed,
        UploadReceived,
    ],
    Field(discriminator="event_type"),
]

EVENT_ADAPTER: TypeAdapter[Event] = TypeAdapter(Event)


def parse_event(data: dict[str, Any] | str | bytes) -> Event:
    """Validate a dict or JSON document as a normalised event."""
    if isinstance(data, (str, bytes)):
        return EVENT_ADAPTER.validate_json(data)
    return EVENT_ADAPTER.validate_python(data)
