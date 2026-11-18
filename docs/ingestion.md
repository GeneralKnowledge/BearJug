# Evidence ingestion and storage

How raw evidence gets from a sensor into the collector's evidence store, and
what each part is trusted to do. Design background: [design doc section 2.3](design/deceptive-access.md)
and [tooling audit section 2.6](research/tooling-audit.md).

```
Cowrie (honeypot)                    shipper (own container)                 collector (separate machine)
  writes its own output  --ro mount-->  reads, hashes, signs  --HTTPS POST-->  verifies, encrypts, stores
  cowrie.json, tty/, downloads/         never executes content                never connects out
```

## The spool is Cowrie's own output

BearJug doesn't add a spool format. Cowrie already writes everything we need,
and the shipper reads it from a read-only mount:

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
* keeps its progress (log offsets by inode, so rotation is safe; names already
  shipped) in its own state file, outside the spool. Losing that file only
  causes resends, which the collector recognises.

If the collector is down or refuses authentication it stops and retries next
pass. If the collector permanently refuses one item (bad digest, not valid
JSON, too large) it logs it and moves on.

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
the collector has no client code (a test checks its imports), so it has no
way to reach into a sensor.

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
| `config.json` | retention periods, size limit, who may read sensitive evidence |
| `evidence-keys.json` (0600) | AES-256-GCM evidence keys by `key_id`, and which is active |
| `sensors.json` (0600) | one authentication key per sensor |
| `evidence.db` | SQLite: one `RawEvidence` record per row (metadata only), and the audit log |
| `blobs/` | the original bytes of every record, encrypted |

* **Everything is encrypted**, sensitive or not, with AES-256-GCM. The
  associated data binds each blob to its evidence id and digest, so a blob
  can't be swapped onto another record. Reads re-check the SHA-256.
* **Append-only.** SQLite triggers refuse any change to a record except
  marking it deleted, and any change at all to the audit log.
* **Keys.** Evidence keys and sensor keys never leave the collector's data
  directory and are separate from each other and from the password HMAC key.
  `rotate-key` starts a new `key_id`; old keys keep decrypting old evidence.

Plaintext attacker passwords therefore exist only inside encrypted raw
evidence. Keyed password hashes (`PasswordRef`) are produced when Cowrie
events are normalised, which is a later PR.

## Access, retention and deletion

All of these go through `bearjug-collector` on the collector machine and are
written to the audit log:

* `show ID --actor A --reason R` decrypts one record. Sensitive records can
  only be read by actors listed in `sensitive_readers` (empty by default); a
  refused attempt is audited too.
* `delete ID --actor A --reason R` removes the encrypted bytes and keeps the
  record as a tombstone.
* `purge` deletes everything past its retention period.

**Draft retention policy**: sensitive evidence 30 days, everything else 365
days, 32 MiB per item. These are placeholders. Design section 8.4 requires
the real values, and who may read sensitive evidence, to be decided before any
public sensor is deployed.

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
  --download-dir var/lib/cowrie/downloads --state shipper-state.json

bearjug-collector --data ./collector list
```

## Not in this PR

* Network isolation, containers and the read-only mount itself: PR 5, which
  also turns the shipper's boundary into tests against real containers.
* Normalising Cowrie events into canonical events, and keyed password hashes.
* Clearing shipped files out of Cowrie's output directories on the sensor.
* Evidence hash chaining.
