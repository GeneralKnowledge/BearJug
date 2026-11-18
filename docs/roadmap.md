# Implementation roadmap

Deceptive Access is part of the initial product, not a later experimental
feature. See [design/deceptive-access.md](design/deceptive-access.md).

> **Defining engineering rule:** make the deception as convincing as possible
> to the attacker, while making the real infrastructure as inaccessible as
> possible to them.

Every PR keeps the safety constraints intact (no real shell or host
authentication; synthetic secrets never valid and never real-shaped; all
outbound actions simulated and recorded), and from PR 5 onward every PR must
pass the security boundary test suite.

The security boundary test suite runs in CI (`sensor-deploy` workflow,
`deploy/tests`) against a sensor deployed by `deploy/ansible`; see
[deployment.md](deployment.md). Upload quarantine and the profile secret scan
are still to come with the features they test.

## PR plan

| PR | Responsibility | Scope |
|---|---|---|
| 1–2 | Foundation and canonical event schema | Repo foundation; one canonical schema covering raw evidence, normalised events and intelligence, including the Deceptive Access event types |
| 3–4 | Ingestion, storage and evidence integrity | Collector ingestion; three-tier storage; append-only, hashed raw evidence; keyed password hashes; draft password and upload retention, access and quarantine policy (decided before any public sensor) |
| 5 | Egress boundary, Cowrie integration and security boundary tests | **Egress boundary first**: honeypot container on an internal-only network with default-deny egress (no route out, no DNS), no route to the collector, shipper as the only component reaching the collector's ingestion endpoint. Executable boundary tests in CI, including malicious commands (`bash -c`, `$(…)`, `python -c`), SSH forwarding, and a deliberately network-capable canary command proving the network holds when Cowrie doesn't. Then Cowrie, pinned to a commit, with a BearJug overlay that registers BearJug command modules and removes the FoxIO-licensed JA4+ code. Config: `backend = shell`, forwarding/redirect/tunnel off, every output plugin except jsonlog off, `sensor_name` set, fail closed without a compiled `userdb.txt`. All five real-fetch tools (`wget`, `curl`, `ftpget`, `tftp`, `nc`) replaced with simulated versions for realism, not as the safety guarantee; `free` no longer shows host RAM. One milestone, which may be delivered as several smaller PRs (e.g. 5a network boundary and shipper, 5b boundary tests, 5c Cowrie container and overlay) |
| 6 | Exact-match synthetic authentication | Compiled exact-match `userdb.txt` per profile (Cowrie `UserDB`); a custom auth class only if the decision needs more than username and password. Exact synthetic matches only, per-profile credential sets, consistent across reconnects; compiler rejects passwords containing `*`, a leading `!`, `/…/` or `:`; experimental policies possible only when explicitly labelled in event data |
| 7 | Profile-driven Linux simulation | Profile data model (`profiles/<name>/*.yaml`); compiler emitting a sensor bundle (`fs.pickle` with embedded contents, txtcmds, `cmdoutput.json`, `cowrie.cfg`, `userdb.txt`) and a collector-side manifest (decoy ids, bundle hashes) that never ships to the sensor; consistency checks, pickle opcode allowlist, fingerprint-marker validation, and a test that boots the pinned Cowrie with the compiled profile and checks it matches; Level 1 shell where every command tells the same story |
| 8 | Full interactive session recording | TTY evidence plus normalised events with timing and outcomes. **MVP release gate** passes here |
| 9 | Fictional infrastructure and decoy secrets | Decoy registry (decoy types informed by the Canarytokens catalogue; no off-sensor beacons unless decided separately) and displayed-value generation rules per secret type; Level 2 and first Level 3: apps, decoy `.env`, Git repos, DB contents, SSH keys, services, Docker, simulated DB/cloud/SSH clients; secret validator and CI scan; profile generator for distinct environments |
| 10–11 | Behavioural intelligence and campaign correlation | Command timing, automation likelihood with confidence, search patterns, persistence and discovery attempts, credential and decoy-secret reuse, recurrence; fingerprints and campaigns, every link carrying confidence and supporting evidence |
| — | OpenCanary adapter (after the release gate) | TCP-listener modules only, own container, no host networking |
| 12 | Investigation dashboard | Session replay, attacker timelines, credential-to-behaviour views, links back to raw evidence |
| — | Intelligence export (after PR 11) | MISP event and STIX 2.1 bundle files from the intelligence tier; no MISP or OpenCTI server |
| 13+ | Distributed sensors and research | Multiple sensors with distinct linked profiles forming a fictional network, profile rotation, remaining Level 3, research datasets; one of Suricata or Zeek as an extra evidence kind |

Tooling choices behind PR 5–9 are in
[research/tooling-audit.md](research/tooling-audit.md). Not on the roadmap:
T-Pot, Dionaea, OpenCTI, and Cowrie's LLM backend.

## Deployment

The public sensor and the private collector are separate security zones on
separate machines. The 8 GB development machine is for local development and
benchmarking only.

## Release gate (MVP)

The first successful end-to-end test is a formal release gate. An external
test client connects, authenticates with a synthetic credential, explores the
fake server, attempts a simulated download, and produces a complete
investigation record, with no external connection and no real command
execution. Details in the design doc, section 9.

## Sequencing

1. Event schema, isolated sensor and collector working (PR 1–5).
2. Prove fake login to fake shell, end to end (PR 6–8, release gate).
3. Then add believable infrastructure and intelligence (PR 9 onward).
