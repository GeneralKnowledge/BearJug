"""BearJug canonical schema: raw evidence, normalised events, intelligence.

The three tiers are kept separate on purpose:

* :mod:`.evidence` holds what the sensor captured, append-only and hashed.
* :mod:`.events` holds normalised events derived from evidence.
* :mod:`.intelligence` holds conclusions derived from events, with confidence.

See ``docs/schema.md``.
"""

from .common import SCHEMA_VERSION, Endpoint, EvidenceRef
from .events import (
    RULE_EXACT_SYNTHETIC_MATCH,
    RULE_NO_SYNTHETIC_MATCH,
    AuthAttempt,
    AuthDecision,
    AuthPolicy,
    CommandInput,
    CommandResult,
    DiscoveryAttempt,
    Event,
    FsAccess,
    FsOperation,
    Outcome,
    OutboundSimulated,
    PersistenceAttempt,
    PolicyKind,
    PrivescSimulated,
    SecretAccessed,
    SecretUsed,
    SessionEnd,
    SessionStart,
    UploadReceived,
    parse_event,
)
from .evidence import EvidenceKind, InlineContent, RawEvidence, StoredContent
from .intelligence import CampaignLink, Intelligence, SessionAssessment, parse_intelligence
from .passwords import PasswordRef, password_ref

__all__ = [
    "SCHEMA_VERSION",
    "Endpoint",
    "EvidenceRef",
    "EvidenceKind",
    "InlineContent",
    "StoredContent",
    "RawEvidence",
    "PasswordRef",
    "password_ref",
    "RULE_EXACT_SYNTHETIC_MATCH",
    "RULE_NO_SYNTHETIC_MATCH",
    "AuthAttempt",
    "AuthDecision",
    "AuthPolicy",
    "PolicyKind",
    "SessionStart",
    "SessionEnd",
    "CommandInput",
    "CommandResult",
    "Outcome",
    "FsAccess",
    "FsOperation",
    "OutboundSimulated",
    "DiscoveryAttempt",
    "PrivescSimulated",
    "PersistenceAttempt",
    "SecretAccessed",
    "SecretUsed",
    "UploadReceived",
    "Event",
    "parse_event",
    "SessionAssessment",
    "CampaignLink",
    "Intelligence",
    "parse_intelligence",
]
