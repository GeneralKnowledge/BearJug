# Tooling audit: what BearJug should reuse

Status: research, 2026-11-18. No code changes. Recommends roadmap changes
(section 7) but does not edit the roadmap.

Sources were read from the projects themselves, not from summaries:

| Project | Inspected at | Licence |
|---|---|---|
| Cowrie | `cowrie/cowrie` `d99515c` (2026-11-17, 3.1.8.dev) | BSD-3-Clause; vendored JA4+ under FoxIO License 1.1 |
| T-Pot | `telekom-security/tpotce` `043e2f0` (2026-11-16) | GPL-3.0 |
| OpenCanary | `thinkst/opencanary` `08bebdf` (2026-11-17) | BSD-3-Clause |
| Dionaea | `DinoTools/dionaea` `4e459f1` (**last commit 2021-02-08**) | GPL-2.0 |
| Canarytokens | `thinkst/canarytokens` `e3d1da1` (2026-11-13) | GPL-3.0 **plus Thinkst's extra terms** (broad "derivative work" reading; incompatible with plain GPL) |
| MISP | licence, `misp-rfc`, `misp-objects` | AGPL-3.0 (software); formats freely reusable; object templates CC0/BSD |
| OpenCTI | licence and docs | Apache-2.0 Community Edition; Enterprise Edition separate |
| Suricata | licence and docs | GPL-2.0 |
| Zeek | licence and docs | BSD-3-Clause |

BearJug itself has **no licence file yet**. That decides whether GPL code (T-Pot)
could ever be copied in. This report assumes it is not: learn from GPL projects,
reimplement, and run them only as separate processes.

## 1. Verdict per tool

| Tool | Use directly | Adapt | Learn from | Duplicates BearJug | Dangerous boundary |
|---|---|---|---|---|---|
| **Cowrie** | SSH protocol, emulated shell, per-session fake FS, TTY logs, JSON events, HASSH/JA4SSH | Command set (overlay of BearJug command modules), config, userdb | Event pipeline design | Output plugins (Elastic, Postgres, S3, MISP…), OCSF/CEF formatters | Real-fetch `wget`/`curl`/`ftpget`/`tftp`/`nc`; `forwarding = true` by default; proxy/pool backends; LLM backend; host `/proc/meminfo` read by `free`; `pickle.load` of the FS file |
| **T-Pot** | Nothing | Nothing (GPL-3) | **Cowrie persona compiler** (closest prior art to our profile compiler), container hardening, sensor/hive split | ELK stack, attack map, ewsposter = our collector and dashboard | Needs unfiltered outbound internet; 8–16 GB RAM, 128–256 GB disk. Not for the 8 GB Dell |
| **OpenCanary** | Low-interaction decoy listeners (after the release gate) | Small adapter from its JSON log | Module structure | None | `portscan` runs `iptables` via `subprocess` (needs root/NET_ADMIN); `llmnr`/`snmp` use scapy and `llmnr` sends packets; `smb` drives real Samba; shipped compose uses `network_mode: host` |
| **Dionaea** | No | No | Protocol list for later expansion | None | Built to fetch malware and run shellcode emulation (libemu); unmaintained since 2021 |
| **Canarytokens** | No | No | **Catalogue of decoy types** for the decoy registry | Alerting/webhooks | Its AWS key tokens are **real IAM keys**; every token needs a public DNS/HTTP callback server. Both conflict with safety constraint 2 |
| **MISP** | No server yet | Export format only | Event/attribute/object/sighting model, TLP tags | Correlation engine | Cowrie's MISP output and MISP's `cowrie` object both carry plaintext `password` |
| **OpenCTI** | No | STIX 2.1 export only | Relationship model with confidence and provenance | Graph/correlation | Heavy stack (OpenSearch, Redis, RabbitMQ, S3) |
| **Suricata / Zeek** | Later, pick one | Adapter from EVE JSON / Zeek JSON | `community_id` for joining flows | SSH fingerprinting (Cowrie already does HASSH/JA4SSH) | Suricata inline/IPS mode can drop traffic; run passive only |

## 2. Cowrie in depth

### 2.1 What the virtual system is made of

Everything an attacker sees comes from six operator-controlled inputs. All of
them are plain data and config, so a compiler can produce every one.

| Input | Config key | What it holds | Notes from the source |
|---|---|---|---|
| `fs.pickle` | `[shell] filesystem` | The whole tree: metadata, and optionally file bytes | See 2.2 |
| honeyfs dir | `[honeypot] contents_path` | File contents overriding the pickle | Only applies to paths **already in the pickle** (`shell/fs.py` `init_honeyfs`) |
| txtcmds dir | `[honeypot] txtcmds_path` | Static stdout per command path, e.g. `usr/bin/lscpu` | Path must also exist in the pickle. Output ignores arguments |
| `cmdoutput.json` | `[shell] processes` | The process table `ps` prints | Bundled one has 73 Debian processes |
| `cowrie.cfg` | | `hostname`, `kernel_version`, `kernel_build_string`, `hardware_platform`, `operating_system`, `arch`, `[ssh] version`, `timezone`, `fake_addr`, `internet_facing_ip`, `boot_offset` | `uname` reads config, not the FS |
| `userdb.txt` | `[honeypot] etc_path` | `user:x:password` login rules | See 2.4 |

`/etc/passwd`, `/etc/group` and the banner are read out of the pickle by
`core/honeyfs.py`, so accounts shown by `id`, `whoami`, `cat /etc/passwd`
come from the same compiled tree.

### 2.2 The `fs.pickle` format

Each node is a 10-field Python list (`shell/fs.py`):

```
[name, type, uid, gid, size, mode, ctime, contents, target, realfile]
type: 0 link, 1 dir, 2 file, 3 blk, 4 chr, 5 sock, 6 fifo
contents: list of child nodes (dir) or bytes (file)
```

Findings that matter for a compiler:

- **It is just nested lists of ints, strings and bytes.** Walking the bundled
  pickle with `pickletools` shows only primitive opcodes (`EMPTY_LIST`,
  `APPEND(S)`, `BININT*`, `SHORT_BINUNICODE`, `BINBYTES`, `NONE`…): no
  `GLOBAL`/`REDUCE`, so no objects. BearJug can emit it with `pickle.dump`
  from a plain data structure. `createfs` (snapshot a real directory) is not
  needed.
- **File bytes can live inside the pickle** (`A_CONTENTS`), so one compiled
  file can carry the entire profile; honeyfs becomes optional.
- **Cowrie trusts the metadata.** It doesn't reconcile `size` with the bytes, or
  `/etc/passwd` with node uids. Consistency is the compiler's job, which is
  what design section 5.4 already asks for.
- **Per-session state comes for free.** The tree is loaded once and shared;
  the first write in a session deep-copies it (`_ensure_private_fs`), and the
  copy is discarded at logout. BearJug doesn't need its own copy-on-write.
  Persistence across reconnects (design Level 3) is **not** supported and would
  be our own work later.
- **Risk:** Cowrie calls `pickle.load` on whatever file the config names. That
  is safe only while the file is produced by our compiler. CI should check that
  a compiled pickle contains only the opcodes above.

### 2.3 Where data alone isn't enough

Python commands take precedence over txtcmds when called by name
(`shell/protocol.py` `getCommand`: `self.commands` is checked first). So the
compiler **can't override `ps`, `uname`, `netstat`, `ifconfig` or `free`
through txtcmds**. T-Pot hit the same wall and patches Cowrie with a
`skip_python_commands` option.

Things a profile can't control today without code:

| Behaviour | Why | Fix |
|---|---|---|
| `free` | Reads the **sensor host's real** `/proc/meminfo` (`commands/free.py`). Leaks the real RAM | BearJug module reading profile values |
| `ifconfig`, `netstat -r` | MAC is random per process start; addresses derive from the listening IP or `fake_addr` | Module reading `network.yaml` |
| `systemctl`, `ss`, `docker`, `psql`, `aws`, `ip` | Not implemented, or txtcmd output that ignores arguments | Modules (design already plans these) |
| Outbound tools | `wget`, `curl`, `ftpget`, `tftp`, `nc` make **real connections** to any globally routable IP (`core/network.py` blocks only non-global ranges) | Replace all five, not just `wget`/`curl` |
| Sensor name in events | `sensor_name` falls back to `socket.gethostname()` | Always set it |

Python command modules are registered from a **hard-coded list** in
`cowrie/commands/__init__.py`, and auth classes are looked up with
`getattr(cowrie.core.auth, name)`. There is no plugin path, so BearJug needs a
small **overlay** applied at image build against a **pinned Cowrie commit**
(T-Pot does exactly this: commit pin plus a patch script that fails if the
upstream text it expects has moved).

### 2.4 Authentication

Cowrie's `UserDB` already gives exact matching: a `userdb.txt` line
`postgres:x:<password>` accepts only that pair. But:

- The **bundled default accepts `root` with almost any password**, and is used
  whenever `userdb.txt` is missing. The sensor must fail closed if the compiled
  file is absent.
- `*`, a leading `!`, `/regex/` and `:` are special. The compiler must reject
  synthetic passwords using them.
- Cowrie's login events don't say which rule matched. The BearJug adapter
  derives `rule = exact_synthetic_match` from the profile it compiled.

So PR 6 can start from a compiled `userdb.txt` with no custom auth class.
A custom class (which needs the overlay) is only required if the decision must
be made on more than the username and password.

### 2.5 Answer: can a profile compiler replace a shell emulator?

**Yes.** `profiles/prod-db-01/*.yaml` can compile to Cowrie artefacts, and
nothing in Cowrie needs rewriting. The work is a compiler plus about ten small
command modules.

| Profile file | Compiles to |
|---|---|
| `identity.yaml` | `cowrie.cfg` (`hostname`, kernel strings, `arch`, SSH banner, timezone, `boot_offset`); `/etc/hostname`, `/etc/os-release`, `/etc/issue`, `/proc/version` in the pickle |
| `users.yaml` | `/etc/passwd`, `/etc/group`, `/etc/shadow`, home dirs, histories in the pickle; `userdb.txt` |
| `filesystem.yaml` | Pickle nodes with owners, modes, timestamps and embedded bytes |
| `services.yaml` | `cmdoutput.json`; data read by `systemctl`/`ss` modules |
| `network.yaml` | `/etc/hosts`, `/etc/resolv.conf`, `/proc/net/arp`; data read by `ip`/`ifconfig`/`netstat` modules and simulated neighbours |
| `applications/`, `secrets/` | Files in the pickle; plus a **collector-side** manifest mapping displayed values to decoy ids, which never ships to the sensor |
| `command_outputs/` | txtcmds (static), for commands with no argument-dependent output |

The compiler should emit **two bundles**: a sensor bundle (Cowrie artefacts
only) and a collector manifest (profile id, decoy registry entries, hashes of
the sensor bundle). That keeps decoy ids off the sensor, as design 5.3 requires.

Treat Cowrie as one **compile target**, not the profile format. Its layout has
changed recently (`contents_path` replaced the old honeyfs setting, and
`getCommand` now takes `cwd`, which already breaks T-Pot's patch against
current upstream). A test that boots the pinned Cowrie with a compiled profile
and runs `uname -a`, `cat /etc/passwd`, `ps`, `free`, `ls -la /root` and
compares with the profile catches drift on upgrade.

### 2.6 Events and recordings

- `cowrie.json`: one JSON object per line, ~45 event ids (`cowrie.login.*`,
  `cowrie.command.input/failed/success`, `cowrie.session.*`,
  `cowrie.direct-tcpip.*`, `cowrie.client.kex` with HASSH…). Each line becomes
  a `RawEvidence` of kind `cowrie.event`, as the schema already expects; the
  adapter turns those into canonical events. Our sensitivity rules already flag
  `cowrie.login.*`.
- TTY logs: binary records (`core/ttylog.py`), with `playlog` and
  `asciinema` converters. Reuse the converter for PR 12 replay.
- Cowrie also ships OCSF 1.8 and CEF formatters. Don't use them as an
  interface: they're Cowrie's mapping, not ours.
- Only `output_jsonlog` (and TTY logging) should be enabled. Every other
  output plugin either duplicates the shipper or calls a third party from the
  sensor.

### 2.7 LLM mode

`backend = llm` replaces the shell backend entirely. Each command, with the last
10 commands as history, goes to an OpenAI-compatible API; there is no virtual
filesystem behind it, and the docs say it "may occasionally be inconsistent".
That breaks the core idea (every command tells the same story) and the
boundary (attacker input leaves the sensor). **Keep it out of the build.** The
interesting use later is offline: generating profile content at compile time,
reviewed and then frozen, so runtime stays deterministic.

## 3. T-Pot: the persona compiler already exists (in GPL form)

T-Pot's Cowrie image (`docker/cowrie/dist/`) contains:

- `generate_cowrie_fs.py` (1,642 lines): builds 11 personas (`ubuntu-jammy`,
  `debian-bookworm-vuln`, `qnap-qts`, `openwrt-1806`, …), each with its own
  `fs.pickle`, honeyfs, txtcmds, `cmdoutput.json` and `cowrie.cfg`; validates
  each persona for leftover fingerprints (`FORBIDDEN_MARKERS`, distro-mismatch
  markers).
- `patch_cowrie_persona_support.py`: adds `skip_python_commands` and patches
  `ssh`, `netstat` and `service` so persona data wins.
- `start-cowrie-persona.py`: picks a persona at container start.

This confirms the approach works at scale. Its choices differ from ours:
`AuthRandom` (accept after N tries) and `auth_publickey_allow_any = true`,
i.e. what our design calls an experimental policy. Copy the ideas (marker
validation, per-persona bundle, skip list), not the code.

Hardening worth copying into PR 5: `read_only: true`, tmpfs for runtime dirs,
a separate Docker network per honeypot, `forwarding = false`,
`forward_redirect = false`, `forward_tunnel = false`.

## 4. The other sensors

**OpenCanary** listens on real ports and rejects every login (`ssh`:
`UnauthorizedLogin`; `mysql`: `Access denied`), logging JSON with numeric
`logtype` codes (`8001` MySQL login, `4002` SSH login…). It makes the public
IP look like a busier server. It does **not** help with the fictional
10.20.0.0/24 network seen from inside the shell; that is Cowrie command
modules. It has no PostgreSQL module, which is `prod-db-01`'s main service.
Use later, in its own container, with only TCP-listener modules, no host
networking, and portscan/llmnr/snmp/samba off.

**Dionaea** is unmaintained and designed to let exploits run far enough to
download payloads. Not before a separate design for malware handling.

**Canarytokens** solves a different problem: alerting when a secret is used
*off* the sensor, from the attacker's own machine. That needs secrets that
really work somewhere (its AWS keys are real IAM keys) and a public callback
server. Both cross constraint 2. Take its **list of decoy types** (DNS
hostname, URL, AWS/Azure keys, kubeconfig, MySQL dump, Word/PDF, WireGuard,
SVN, credit card…) into the PR 9 decoy registry, and detect use on-sensor via
`secret.accessed` / `secret.used`. Off-sensor beacons would be an explicit new
design decision, not a default.

## 5. The intelligence side (formats only)

| Format | Shape | BearJug mapping |
|---|---|---|
| MISP core format (`misp-rfc`) | Event → Attributes (`type`, `category`, `to_ids`, `value`), Objects from templates, Sightings, Tags/Galaxies, TLP | Export a session or campaign as a MISP event file. Use `ip-src`, `command-line`/`shell-commands`, `authentication-session`, `credential` objects with **no password attribute**; the stock `cowrie` object includes `password`, so don't use it as is |
| STIX 2.1 (OpenCTI's native model) | SDOs (Campaign, Intrusion Set, Indicator, Attack Pattern), SCOs, Relationships and Sightings with `confidence` 0–100, `created_by_ref`, markings | `campaign.link` → relationship to Campaign; `Support.confidence` × 100 → `confidence`; supporting event ids → `x_bearjug_supporting_events` or external references; `session.link` → relationship between observed-data |
| Suricata EVE JSON | One JSON per event with `event_type` (`flow`, `alert`, `ssh`, `tls`, `dns`…), `community_id` | New raw evidence kind later |
| Zeek logs | `conn`, `ssh`, `dns`… as TSV or JSON, `community_id` | Same |

The intelligence tier already carries confidence and supporting evidence on
every conclusion, which is the hard part of both MISP and STIX. An export is a
file writer, not a platform. No MISP or OpenCTI server is needed for that.

## 6. Smallest useful combination

**Cowrie (pinned, shell backend) + BearJug overlay + profile compiler + adapter
+ the PR 3–4 spool, shipper and collector.** Nothing else.

```
profiles/prod-db-01/*.yaml
  -> compiler -> sensor bundle (fs.pickle, txtcmds, cmdoutput.json, cowrie.cfg, userdb.txt)
              -> collector manifest (decoy ids, bundle hashes)

Cowrie + overlay (safe outbound tools, free, ifconfig/ip, netstat/ss, systemctl, later psql/aws/docker)
  -> cowrie.json + tty logs -> spool -> shipper -> collector
  -> adapter -> RawEvidence -> Events -> Intelligence
```

Cowrie is a single Python process (not measured here, but far below T-Pot's 8 GB
sensor minimum), so this should fit on the 8 GB Dell alongside
the collector. Add OpenCanary after the release gate, then one of Suricata or
Zeek, then a MISP/STIX export file. T-Pot, Dionaea, OpenCTI and LLM mode stay
off the roadmap.

## 7. Recommended roadmap changes

| PR | Change |
|---|---|
| 5 | Pin a Cowrie commit and add the overlay mechanism (registers BearJug command modules). Replace all five real-fetch tools (`wget`, `curl`, `ftpget`, `tftp`, `nc`), not only `wget`/`curl`. Config hardening list: `backend = shell`, `forwarding`/`forward_redirect`/`forward_tunnel` off, every output plugin except jsonlog off, `sensor_name` set, fail closed without a compiled `userdb.txt`. Add boundary tests: `free` doesn't show host RAM, sensor events don't contain the host name |
| 6 | Start with a compiled exact-match `userdb.txt`; custom auth class only if needed. Compiler rejects passwords with `*`, `!`, `/…/` or `:` |
| 7 | Scope it concretely as "compile profiles to `fs.pickle` (with embedded contents), txtcmds, `cmdoutput.json`, `cowrie.cfg`, `userdb.txt`, plus a collector manifest". Add a pickle opcode allowlist check, T-Pot-style fingerprint-marker validation, and a "boots in pinned Cowrie and matches the profile" test |
| 9 | Use the Canarytokens type list for the decoy registry. Off-sensor beacons stay out unless decided separately |
| new, after 8 | OpenCanary adapter (TCP listeners only) |
| new, after 11 | MISP event and STIX 2.1 bundle export from the intelligence tier |
| 13+ | Suricata or Zeek (one) as an extra evidence kind |

## 8. Open questions for Reuben

- **BearJug's licence.** None yet. Matters if any GPL code is ever copied in,
  and for the vendored JA4+ code in Cowrie (FoxIO 1.1 is non-commercial).
- **Persistent per-attacker filesystem.** Cowrie discards a session's changes
  at logout. Reconnects see the pristine profile. Fine for the MVP; Level 3
  "returning sessions" would need our own state.
