# Implementation roadmap

Deceptive Access is part of the initial product, not a later experimental
feature. See [design/deceptive-access.md](design/deceptive-access.md).

Every PR must keep the Deceptive Access safety constraints intact: no real
shell or host authentication; synthetic secrets are never valid and never
resemble usable ones; all outbound actions are simulated and recorded.

## PR plan

| PR | Responsibility | Notes |
|---|---|---|
| 1–2 | Project foundation and event schema | Event schema includes the Deceptive Access event types (auth decisions with rule, session lifecycle, commands, file access, simulated outbound, privesc, persistence, secret access/use) |
| 3–4 | Ingestion and database | Store full sessions, not just login attempts |
| 5 | Sensor agent and Cowrie integration | Cowrie in shell (emulated) mode only; proxy backend off; SSH forwarding off; egress denied except to collector; unprivileged container |
| 6 | Deceptive authentication engine | Custom Cowrie auth class driven by the AITO credential policy: synthetic account profiles, exact-match and accept-after-N rules, per-source consistency, decision + rule recorded. No PAM or host auth. Deterministic tests for the policy |
| 7 | Synthetic Linux environment | Deception profile format and compiler to Cowrie artefacts (filesystem, file contents, command outputs). Level 1: users, processes, basic commands, all consistent with one profile. Replace Cowrie's real-fetch `wget`/`curl` with simulated handlers |
| 8 | Interactive session recording | Structured per-command events plus TTY replay, shipped to the collector. Completes Level 1 (MVP) |
| 9 | Fake infrastructure and credentials | Level 2 and first Level 3 pieces: apps, `.env`, Git repos, DB contents, SSH keys, cron/services, cloud config, Docker, simulated DB/cloud/SSH clients. Synthetic-secret validator and CI secret scan. Profile generator for multiple distinct personalities |
| 10 | Behavioural intelligence | Session features, behavioural fingerprints, post-compromise behaviour metrics |
| 11 | Campaign correlation | Link sessions across sources and sensors using fingerprints and decoy-secret reuse |
| 12 | Dashboard investigation tools | Session replay, per-attacker timelines, credential-to-behaviour views |
| 13+ | Distributed sensors and research | Multiple sensors with distinct profiles, profile rotation, remaining Level 3 (simulated lateral movement across fictional hosts, long-running sessions), research datasets |

## Milestones

- **MVP (after PR 8):** an attacker who guesses a synthetic credential gets a
  consistent Level 1 fake server, and the whole session lands in AITO.
- **Believable server (after PR 9):** Level 2 profiles with synthetic secrets
  that attackers try to use, all uses simulated and recorded.
- **Intelligence (after PR 12):** fingerprints, campaigns, and investigation UI.
