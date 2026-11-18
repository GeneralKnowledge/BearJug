# Canonical event schema

Schema version: `1.0`. Source of truth: `src/bearjug/schema/` (Pydantic).
JSON Schema copies for non-Python components are in `schema/`, regenerated with
`python -m bearjug.schema.export` (CI fails if they are stale).

> **JSON Schema is structural only.** The exported files check shapes and
> types. They do not encode the cross-field security rules under "Enforced
> rules" (evidence sensitivity, production auth policy, experiment labelling,
> outbound destinations), and each file says so in its `$comment`. A record
> that passes JSON Schema is not thereby acceptable. Until a second
> implementation of those rules exists and is tested against the same cases,
> anything that stores or acts on a record must validate it with
> `bearjug.schema` (`parse_event`, `parse_intelligence`,
> `RawEvidence.model_validate`).

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
Content is either `inline` (small JSON) or `stored` (a URI to encrypted bytes).

### Sensitivity is derived, not trusted

The producer cannot downgrade sensitivity. The model classifies each record and
rejects one that is understated:

| Record | Sensitive? |
|---|---|
| `tty.log`, `upload` | Always (keystrokes include typed passwords; uploads are hostile) |
| `cowrie.event` with `eventid` starting `cowrie.login.` | Always (carries the attempted password) |
| `cowrie.event` whose inline data has a `password`, `passwd`, `pass`, `pwd`, `passphrase` or `secret` key at any depth (case-insensitive) | Yes |
| inline `cowrie.event` with no `eventid` | Rejected: cannot be classified |
| anything else | No, unless the producer sets `sensitive: true` |

Sensitive evidence can never be inline. Stored content is always encrypted,
sensitive or not, so nothing outside a record is ever held in the clear.

### Encryption contract

`content.encryption.algorithm` must be an AEAD algorithm: `aes-256-gcm` or
`chacha20-poly1305`. `key_id` names the version of the data key used.

Key-management expectations (implemented in PR 3–4):

* Evidence encryption keys are held by the collector's key management, never
  by the honeypot process or the shipper, and never appear in any record.
* They are separate from the password HMAC key.
* Rotation means a new `key_id`; old keys are kept only as long as evidence
  encrypted under them is retained.
* Decryption is restricted to named research roles and logged.

### Hash format versus integrity

The schema only checks that `sha256` is 64 lower-case hex characters. That is
not integrity verification. Before accepting evidence the collector must
compute SHA-256 over the original bytes and reject any mismatch, and storage
must be append-only (PR 3–4). `EvidenceRef.sha256` on events likewise only
proves the format until the collector checks it against stored evidence.

## Normalised events

Common fields: `event_id`, `event_type`, `occurred_at` (UTC), `sensor_id`,
`profile_id`, `session_id`, `parser`, `evidence`.

| `event_type` | Specific fields |
|---|---|
| `auth.attempt` | `src`, `username`, `password` (PasswordRef), `decision`, `rule`, `policy` |
| `session.start` | `src`, `account`, `policy`, `source_ip_seen_before` |
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
* `session.link`: judges that a session continues an earlier one by the same
  actor, with the `basis` for the judgement.
* `campaign.link`: assigns a session to a campaign, with the `basis` for the
  link (decoy secret reuse, password reuse, fingerprint, payload reuse, source
  overlap).

### Recurring IP is not a recurring attacker

`session.start.source_ip_seen_before` is a plain fact about the address. It says
nothing about who is behind it (NAT, proxies, shared scanners). Whether a
session belongs to the same actor as an earlier one is a judgement, so it lives
only in the intelligence tier as a `session.link` with confidence and
supporting events. The design doc's "returning-visitor flag" maps to these two
fields.

Every conclusion carries `support`: a `confidence` from 0 to 1 and at least one
supporting event id.

## Enforced rules

* **No plaintext passwords outside raw evidence.** Events carry a `PasswordRef`:
  HMAC-SHA256 under a collector-held key (`key_id` recorded; hashes only compare
  within one key), plus length, character classes and optional wordlist
  membership. All models reject unknown fields, so a stray plaintext field
  fails validation.
* **Sensitivity is derived from kind and content**, cannot be understated, and
  sensitive evidence is never inline. Stored evidence is always AEAD-encrypted.
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

Digest verification against the bytes, encrypted storage and draft retention are
implemented by the collector (see [ingestion.md](ingestion.md)). Evidence hash
chaining and the Cowrie-to-event mapping come later. Behavioural
fingerprints as their own record type come with PR 10 and 11.
