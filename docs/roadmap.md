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

The security boundary test suite is **specified** in the design doc, not yet
implemented. A specified suite is not a passing one.

## PR plan

| PR | Responsibility | Scope |
|---|---|---|
| 1–2 | Foundation and canonical event schema | Repo foundation; one canonical schema covering raw evidence, normalised events and intelligence, including the Deceptive Access event types |
| 3–4 | Ingestion, storage and evidence integrity | Collector ingestion; three-tier storage; append-only, hashed raw evidence; keyed password hashes; draft password and upload retention, access and quarantine policy (decided before any public sensor) |
| 5 | Cowrie integration and security boundary tests | Isolated sensor container (emulated shell only, proxy off, forwarding off, real-fetch `wget`/`curl` replaced); spool and separate shipper; default-deny egress firewall; executable security boundary test suite in CI. One milestone, which may be delivered as several smaller PRs (e.g. 5a container and Cowrie config, 5b network and shipper, 5c boundary tests) |
| 6 | Exact-match synthetic authentication | AITO auth class: exact synthetic matches only, per-profile credential sets, consistent across reconnects; experimental policies possible only when explicitly labelled in event data |
| 7 | Profile-driven Linux simulation | Profile data model, compiler to Cowrie artefacts, consistency checks; Level 1 shell where every command tells the same story |
| 8 | Full interactive session recording | TTY evidence plus normalised events with timing and outcomes. **MVP release gate** passes here |
| 9 | Fictional infrastructure and decoy secrets | Decoy registry and displayed-value generation rules per secret type; Level 2 and first Level 3: apps, decoy `.env`, Git repos, DB contents, SSH keys, services, Docker, simulated DB/cloud/SSH clients; secret validator and CI scan; profile generator for distinct environments |
| 10–11 | Behavioural intelligence and campaign correlation | Command timing, automation likelihood with confidence, search patterns, persistence and discovery attempts, credential and decoy-secret reuse, recurrence; fingerprints and campaigns, every link carrying confidence and supporting evidence |
| 12 | Investigation dashboard | Session replay, attacker timelines, credential-to-behaviour views, links back to raw evidence |
| 13+ | Distributed sensors and research | Multiple sensors with distinct linked profiles forming a fictional network, profile rotation, remaining Level 3, research datasets |

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
