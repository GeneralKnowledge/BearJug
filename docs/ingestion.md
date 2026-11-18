# Evidence ingestion and storage

How raw evidence gets from a sensor into the collector's evidence store, and
what each part is trusted to do. Design background: [design doc section 2.3](design/deceptive-access.md)
and [tooling audit section 2.6](research/tooling-audit.md).

```
Cowrie (honeypot)                    shipper (own container)                 collector (separate machine)
  writes its own output  --mount----->  reads, hashes, signs  --HTTPS POST-->  verifies, encrypts, stores
  cowrie.json, tty/, downloads/         never executes content                never connects out
```

## The spool is Cowrie's own output

BearJug doesn't add a spool format. Cowrie already writes everything we need,
and the shipper reads it from a mount it can't write files into (see
"Evidence on the sensor" for the one exception, removing acknowledged files):

| Cowrie output | Shipped as | When it is shipped |
|---|---|---|
| `cowrie.json` and its daily rotations | one `cowrie.event` per line | once the line ends with a newline |
| `ttylog_path/<64 hex>` | `tty.log` | Cowrie gives a TTY log this name only when the session closes |
| `download_path/<sha256>` | `upload` | Cowrie gives a download this name only when it is complete; the name is the SHA-256 of its bytes |

Files with any other name (in-progress TTY logs, `tmp_*` downloads) are left
alone. Symlinks and non-regular files are refused, so a compromised honeypot
can't point the shipper at something outside the spool.

## Shipper

`bearjug-shipper` (in `src/bearjug/shipper.py`):

* treats every byte as opaque: it splits the JSON log on newlines and hashes
  files, and never parses, executes or interprets them;
* only makes outbound HTTPS requests to one collector URL, and never listens;
* holds only its own sensor key;
* keeps its progress (log offsets by inode, so rotation is safe; files the
  collector acknowledged) in its own state file (0600), outside the spool.
  Losing that file only causes resends, which the collector recognises.

If the collector is down, rate-limits it or refuses authentication, it stops
and retries next pass. If the collector permanently refuses one item (bad
digest, not valid JSON, too large) it moves on, but the item is not lost: it
goes to the dead-letter directory.

### Dead-letter directory

`--dead-letter-dir` (default `dead-letter/`, created 0700) gets one entry per
refused item: `<id>.bin` with the original bytes (0600, never executable) and
`<id>.json` with the kind, where it came from (file and byte offset), size,
SHA-256, the collector's reason, and whether the bytes were kept. The shipper
never parses or runs the `.bin` files.

* Size cap, `--dead-letter-max-mb` (default 256): past it, only the metadata is
  written, so a flood of bad evidence can't fill the sensor's disk. Items over
  the shipping size limit are recorded the same way, metadata only.
* Retention, `--dead-letter-days` (default 30): older entries are removed on
  every pass.

These entries can hold attacker passwords in the clear, just like Cowrie's own
log. They need the same protection as the rest of the evidence on the sensor
(next section).

## Evidence on the sensor

Cowrie's output, the shipper's state and the dead-letter directory all hold
attacker material in the clear: attempted passwords, keystroke recordings and
captured files. The sensor is the machine on the internet, so this material is
kept there as briefly and as tightly as possible.

### Removing acknowledged evidence

With `--delete-acknowledged`, each pass removes from the spool:

| What | When |
|---|---|
| a TTY log or download | once the collector's acknowledgement is saved in the state file |
| a rotated JSON log (`cowrie.json.<date>`) | once every line in it has been acknowledged, and it hasn't changed for 60 seconds |
| refused evidence copied to the dead-letter directory | at once: the dead-letter copy is now the only one |
| refused evidence that could not be copied (dead-letter full, or over the size limit) | after `--unpreserved-days` (default 30) |

The live `cowrie.json` is never removed (Cowrie is writing it), nor is
anything the collector hasn't acknowledged.

**Crash safety.** An acknowledgement is a 2xx reply (`stored`, `duplicate` or
`deleted`). It is written to the state file (fsync, then atomic rename) before
anything can be removed, and removal decisions are made from the state file
on disk, not from memory. So:

* collector unreachable, or the reply lost after the collector stored it: no
  acknowledgement, nothing removed; the next pass resends and the collector
  answers `duplicate`, which counts;
* killed after the reply but before the state was saved: same as a lost reply;
* killed after the state was saved but before the file was removed: the next
  pass removes it without resending;
* a rotated log that was only partly shipped: kept until the rest is
  acknowledged.

Tests cover each of these.

Removing files means the shipper needs permission to delete entries in
Cowrie's output directories, not just read them. The intended setup (PR 5):
Cowrie owns the directories, the shipper's user is in their group, directories
are `2770` and files `0640`. The shipper still can't change any file's
contents, and it never creates files there. Without `--delete-acknowledged`
the mount can stay fully read-only, and the spool has to be cleared some other
way.

### Size limits on the sensor

| What | Limit |
|---|---|
| TTY logs | Cowrie's `ttylog_limit_size` (ends the session) and `ttylog_min_free` (stops recording when the disk is low) |
| downloads | Cowrie's `download_limit_size` |
| one item the shipper will send | 32 MiB; larger ones are dead-lettered as metadata |
| dead-letter directory | `--dead-letter-max-mb` (256), `--dead-letter-days` (30) |
| the whole spool | the shipper logs a warning every pass while it holds more than `--spool-warn-mb` (512). That means the collector isn't acknowledging; unacknowledged evidence is never removed to make room |

The evidence volume should also be its own filesystem or have a quota, so a
full spool can't fill the sensor's root filesystem.

### Permissions

The shipper creates its state file `0600` and the dead-letter directory `0700`
with `0600` files. These modes are set explicitly, not left to the umask, and
a test checks them with a umask of 0. Cowrie creates its own output, so the
shipper can't set those permissions. Instead it logs a warning for any spool
file other users can read. Run Cowrie with `umask 027` so its files come out
`0640`.

### Encryption at rest on the sensor

This is a deployment requirement (PR 5), not something the shipper can do:
Cowrie writes plaintext. Put Cowrie's output, the shipper state and the
dead-letter directory on one volume that is encrypted at rest (LUKS/dm-crypt,
or the provider's encrypted block storage). That protects against disk
snapshots, backups, and a provider reusing a disk. It does not protect against
someone who controls the running sensor, which is why acknowledged evidence is
removed promptly and the retention limits above are short.

**Before any public sensor**, decide these values. The current numbers are
placeholders: unpreserved evidence (30 days), dead-letter retention (30 days)
and size (256 MiB). They go with the collector's retention decision (design
8.4).

## Wire protocol

`POST /v1/evidence`, body = the original bytes, plus `X-BearJug-Meta` (sensor
id, kind, claimed SHA-256, size, observed and sent times) and
`X-BearJug-Signature` (HMAC-SHA256 under the sensor's key over the metadata
and the body's digest). See `src/bearjug/wire.py`.

The collector:

1. checks the signature before looking at the body, using the key registered
   for the sensor id in the metadata, so a sensor can't ship as another sensor;
2. refuses requests sent more than 5 minutes ago (replays inside that window
   are harmless, see idempotency);
3. checks the body's SHA-256 and size against the claimed values. For
   downloads, the claimed digest is Cowrie's own, taken at capture, so a file
   changed in the spool afterwards is refused;
4. works out sensitivity itself from the bytes, using the schema's rules
   (`tty.log` and `upload` always; `cowrie.login.*` and any event with a
   password or secret field). A Cowrie event that isn't a JSON object with an
   `eventid` is refused;
5. encrypts and stores it, and answers `201 stored`, or `200` with
   `duplicate` or `deleted`.

There are no other routes. Evidence can't be read back over the network, and
the collector has no client code (a test checks its imports and calls), so it
has no way to reach into a sensor.

### Limits on unauthenticated clients

The signature proves who sent the evidence, but anyone who can reach the port
can still make the collector do work. The collector limits that work itself.
Every limit is set in `config.json`:

| Limit | Default | Effect |
|---|---|---|
| `max_concurrent_requests` | 16 | Connections past this are closed at once, before the TLS handshake or any read |
| `request_deadline_seconds` | 60 | Hard limit on a connection's lifetime, however slowly it sends |
| `idle_timeout_seconds` | 10 | Socket timeout on each read and write, including the TLS handshake |
| `rate_limit_per_second` / `rate_limit_burst` | 100 / 500 | Requests per client IP |
| `auth_failures_per_minute` | 10 | Failed authentications per client IP; past it, every request from that IP gets 429 until the limit recovers |
| `max_evidence_bytes` | 32 MiB | Larger requests are refused from the `Content-Length` header alone |

The path, size, metadata, sensor status and request time are all checked
before the body is read. An unknown or revoked sensor never gets its body read.

**Deploying a public-facing collector.** These limits are a last line of
defence, not the main one. In front of the collector:

* a firewall that only admits the sensors' addresses to the ingestion port;
* a reverse proxy (nginx, HAProxy or Caddy) that terminates TLS and enforces
  its own limits: `client_max_body_size` at or below `max_evidence_bytes`,
  short header and body timeouts, `limit_conn` and `limit_req` per address,
  and only `POST /v1/evidence` passed through;
* the collector itself listening on loopback or a private interface only.

If a proxy is used, every request reaches the collector from the proxy's
address, so the per-IP limits should be enforced in the proxy.

Use TLS for anything but local testing: the shipper refuses `http://` unless
given `--insecure-http`, and the collector refuses to serve plain HTTP except
on loopback.

## Idempotency

The evidence id is derived from the sensor id, kind and bytes. A retry, a
replay, or a full resend after the shipper loses its state always maps to the
same id, so nothing is stored twice. Evidence that has been deleted is not
stored again either.

## Storage

A collector data directory holds:

| File | What |
|---|---|
| `config.json` (0600) | retention periods, size limit, who may read sensitive evidence |
| `evidence-keys.json` (0600) | AES-256-GCM evidence keys by `key_id`, and which is active |
| `sensors.json` (0600) | one authentication key per sensor |
| `evidence.db` (0600) | SQLite: one `RawEvidence` record per row (metadata only), the audit log, sensor last-seen, integrity issues |
| `blobs/` (0700, files 0600) | the original bytes of every record, encrypted |
| `orphans/` (0700) | encrypted blobs found without a record after a crash (see crash recovery) |

The data directory itself is `0700`. Every mode here is set explicitly by the
code, so it doesn't depend on the umask, and a test checks this with a umask
of 0.

* **Everything is encrypted**, sensitive or not, with AES-256-GCM. The
  associated data binds each blob to its evidence id and digest, so a blob
  can't be swapped onto another record. Reads re-check the SHA-256.
* **Append-only.** SQLite triggers refuse any change to a record except
  marking it deleted, and any change at all to the audit log.
* **Keys.** Evidence keys and sensor keys never leave the collector's data
  directory and are separate from each other and from the password HMAC key.

### Evidence key rotation

`rotate-key` adds a new `key_id`, makes it active, and records it in the audit
log. Old keys keep decrypting old evidence. A running collector checks the
keyring file before every encryption, so the very next item it stores uses the
new key, with no restart.

A running collector reports which key it is encrypting with every 2 seconds.
`rotate-key` waits for that report. It prints a confirmation, or a warning
and exits 1 if the collector hasn't switched within `--wait` seconds. If no
collector is running, it says so, and the new key is used on the next start.
`key-status` compares the keyring with what the running collector reports at
any time, and exits 1 if they differ.

### Crash recovery

A blob is written (to a temp file, then renamed) before its record is inserted.
A deletion marks the record deleted before it removes the blob. So a crash can
leave:

| Left behind | What `reconcile` does |
|---|---|
| a `*.tmp` blob | removes it (no record ever pointed at it) |
| a blob with no record | moves it to `orphans/` and audits it. The shipper never got a reply, so it resends the evidence, which is then stored normally |
| a blob for a deleted record | finishes the deletion and audits it |
| a live record with no blob | **flags it**, never repairs it: recorded as an integrity issue, marked `!! BLOB MISSING` in `list`, and reads of it fail |

`serve` runs this at startup and logs an error if anything is missing.
`check` runs it on demand and exits 1 unless the store is healthy. `check
--deep` also decrypts every blob and checks its SHA-256.

Plaintext attacker passwords therefore exist only inside encrypted raw
evidence. Keyed password hashes (`PasswordRef`) are produced when Cowrie
events are normalised, which is a later PR.

## Access, retention and deletion

All of these go through `bearjug-collector` on the collector machine and are
written to the audit log (`--actor` names who acted; it defaults to `$USER`):

* `show ID --reason R` decrypts one record. Sensitive records can
  only be read by actors listed in `sensitive_readers` (empty by default); a
  refused attempt is audited too.
* `delete ID --reason R` removes the encrypted bytes and keeps the
  record as a tombstone.
* `purge` deletes everything past its retention period.

### Sensors

| Command | Effect |
|---|---|
| `add-sensor ID --key-out F` | registers a sensor and writes its key (0600) for the shipper |
| `replace-sensor-key ID --key-out F --reason R` | issues a new key; the old one stops working immediately |
| `revoke-sensor ID --reason R` | refuses all further uploads from that sensor, effective on its next request; its key is overwritten. Evidence already received is kept. `replace-sensor-key` brings a sensor back |
| `sensors` | each sensor's status, when it was registered, re-keyed or revoked, and when and from where it last uploaded |

Registration, key replacement and revocation are audited. None of them touch
the evidence encryption keys, so a compromised sensor key is dealt with
without re-encrypting anything.

### Retention

**Draft retention policy**: sensitive evidence 30 days, everything else 365
days, 32 MiB per item. **These are placeholders, and a decision is required
before deployment.** Design section 8.4 requires the real values, who may
read sensitive evidence, and the sensor-side limits above to be decided
before any public sensor is deployed.

## Trying it locally

```
pip install -e '.[dev]'
bearjug-collector --data ./collector init
bearjug-collector --data ./collector add-sensor sensor-1 --key-out sensor-1.key
openssl req -x509 -newkey rsa:2048 -nodes -keyout tls.key -out tls.crt -days 30 \
  -subj /CN=localhost -addext subjectAltName=DNS:localhost
bearjug-collector --data ./collector serve --port 8443 --tls-cert tls.crt --tls-key tls.key

# in another shell, pointing at Cowrie's output directories
bearjug-shipper --sensor-id sensor-1 --key-file sensor-1.key \
  --collector https://localhost:8443 --ca-file tls.crt \
  --log-dir var/log/cowrie --tty-dir var/lib/cowrie/tty \
  --download-dir var/lib/cowrie/downloads --state shipper-state.json \
  --delete-acknowledged

bearjug-collector --data ./collector list
bearjug-collector --data ./collector check
```

## Not in this PR

* Network isolation, containers, the spool mount and its permissions, the
  encrypted evidence volume and the reverse proxy configuration itself: PR 5,
  which also turns the shipper's boundary into tests against real containers.
* Normalising Cowrie events into canonical events, and keyed password hashes.
* Evidence hash chaining.
