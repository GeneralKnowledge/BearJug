# Canonical event schema

Schema version: `1.0`. Source of truth: `src/bearjug/schema/` (Pydantic).
JSON Schema copies for non-Python components are in `schema/`, regenerated with
`python -m bearjug.schema.export` (CI fails if they are stale). Cross-field rules
listed under "Enforced rules" live in the Python models only, so anything that
writes events should validate them with `bearjug.schema.parse_event`.

The schema is deliberately small: enough to carry a session from sensor to
collector and through the MVP release gate. Fields get added when a PR needs
them, not before.

## Three tiers

| Tier | Model | Derived from | Rewritten? |
|---|---|---|---|
| Raw evidence | `RawEvidence` | the sensor | Never. Append-only, `sha256` of the original bytes |
| Normalised events | `Event` (13 types) | raw evidence, via `evidence: [EvidenceRef]` | Regenerated when the parser changes; `parser` names the version |
| Intelligence | `Intelligence` | events, via `supporting_events` | Recomputed per `engine` version |

Every record in a derived tier points back to the tier below it. Tiers are
separate models with no shared storage assumptions.

## Raw evidence

`kind` is `cowrie.event` (one Cowrie JSON log line), `tty.log` or `upload`.
Content is either `inline` (small JSON) or `stored` (a URI, optionally
encrypted). Evidence that holds attacker plaintext secrets, such as a login
attempt with its password, must be marked `sensitive` and stored encrypted.

## Normalised events

Common fields: `event_id`, `event_type`, `occurred_at` (UTC), `sensor_id`,
`profile_id`, `session_id`, `parser`, `evidence`.

| `event_type` | Specific fields |
|---|---|
| `auth.attempt` | `src`, `username`, `password` (PasswordRef), `decision`, `rule`, `policy` |
| `session.start` | `src`, `account`, `policy`, `returning_visitor` |
| `session.end` | `duration_seconds`, `reason` |
| `command.input` | `sequence`, `line`, `command`, `args`, `handler`, `since_previous_ms` |
| `command.result` | `sequence`, `outcome`, `error_class` |
| `fs.access` | `path`, `operation` (read/list/search/write/delete) |
| `outbound.simulated` | `tool`, `url`, `host`, `port`, `simulated_response`, `connection_made` (always false) |
| `discovery.attempt` | `technique`, `target` |
| `privesc.simulated` | `technique`, `outcome` |
| `persistence.attempt` | `mechanism`, `target` |
| `secret.accessed` | `decoy_id`, `location` |
| `secret.used` | `decoy_id`, `used_with`, `target` |
| `upload.received` | `quarantine_ref`, `size_bytes`, `sha256`, `filename_as_given` |

See `examples/prod-db-01-session.jsonl` for a full short session.

## Intelligence

* `session.assessment`: `automation_likelihood` (value 0 to 1) and
  `credential_discovered`.
* `campaign.link`: assigns a session to a campaign, with the `basis` for the
  link (decoy secret reuse, password reuse, fingerprint, payload reuse, source
  overlap).

Every conclusion carries `support`: a `confidence` from 0 to 1 and at least one
supporting event id.

## Enforced rules

* **No plaintext passwords outside raw evidence.** Events carry a `PasswordRef`:
  HMAC-SHA256 under a collector-held key (`key_id` recorded; hashes only compare
  within one key), plus length, character classes and optional wordlist
  membership. All models reject unknown fields, so a stray plaintext field
  fails validation.
* **Sensitive raw evidence is encrypted**, never inline.
* **Production policy accepts only exact synthetic matches.** Under
  `policy.kind = "production"`, `rule` is `exact_synthetic_match` (accept) or
  `no_synthetic_match` (reject), nothing else.
* **Experimental policies are labelled.** `policy.kind = "experimental"` requires
  an `experiment_id`; production forbids one. Both `auth.attempt` and
  `session.start` carry the policy.
* **Outbound actions are never real.** `outbound.simulated.connection_made` can
  only be `false`.
* **Timestamps are timezone-aware**, stored as UTC.
* **Records are immutable** once built.

## Not in this version

Retention periods, evidence hash chaining, storage layout and the Cowrie
to-event mapping belong to the ingestion and storage PRs (3 and 4). Behavioural
fingerprints as their own record type come with PR 10 and 11.
