# Deploying an isolated sensor

How to deploy one public BearJug sensor and its private collector with
Ansible, what isolates each part, and how to check it on a real machine.
Everything here is reproducible from `deploy/`: there are no manual setup
steps beyond filling in an inventory.

```
                internet                                     private
  attacker ──SSH:22──▶ ┌──────────── sensor (Ubuntu 24.04) ─────────────┐
                       │ nftables: 22 in (DNAT to Cowrie), admin SSH     │
                       │ from admin CIDRs only, nothing from collector   │
                       │                                                 │
                       │  Cowrie container ──writes──▶ evidence volume   │
                       │  (no route out)               (LUKS2, 12 GiB,   │
                       │                                noexec)          │
                       │  disk guard ◀──statvfs──┘        │ reads        │
                       │  (no network; may only           ▼              │
                       │   start/stop Cowrie)        shipper ──HTTPS──────┼──▶ collector :8443
                       └─────────────────────────────────────────────────┘    (accepts sensors only,
                                                                               never connects out)
```

## The guarantees, and what enforces them

| Guarantee | Enforced by | Tested by |
|---|---|---|
| No attacker command runs on the host | Cowrie's emulated shell (proxy and LLM backends removed by the overlay, refused by the entrypoint); distroless image with no shell; read-only root, `noexec` `/tmp`, no capabilities, no-new-privileges, unprivileged uid | `test_attacker_explores_…_nothing_runs_on_the_host`, `test_container_has_no_shell…` |
| No outbound attacker-controlled connection | nftables drops every new connection from Cowrie's bridge (TCP, UDP, ICMP, to anywhere, including the host and collector); no masquerade on that network; `--dns 127.0.0.1` so Docker's resolver doesn't forward lookups from outside the container. The overlay's simulated tools are realism on top | `test_egress_firewall_holds_without_cowrie` (a network-capable canary on Cowrie's network), `test_simulated_network_tools_…`, `test_ssh_forwarding_is_refused…`, `test_container_dns_is_not_forwarded…` |
| Only the shipper reaches the collector | nftables output rule by uid; the shipper's systemd `IPAddressAllow=` the collector only | `test_only_the_shipper_reaches_the_collector` |
| The collector can't initiate into the sensor | Sensor: drops every new packet from the collector, on every port including 22. Collector: drops every new connection to a sensor, and its service account makes no outbound connections | `test_collector_cannot_initiate_into_the_sensor` |
| No unacknowledged evidence is lost | Shipper deletes only what the collector acknowledged (PR #6); disk guard never deletes; Cowrie stops at 80% instead | `test_collector_recovery_delivers_the_backlog…` |
| Evidence can't fill the root filesystem | Evidence lives on its own fixed-size filesystem (the guard refuses otherwise); container log capped at 3×10 MB; attacker events kept out of that log | `test_evidence_volume_is_its_own_encrypted_noexec_filesystem` |

`deploy/tests` holds these tests. The `sensor-deploy` workflow runs them on
every pull request against a sensor that `sensor.yml` has just deployed onto a
fresh Ubuntu 24.04 runner, with the collector in a container on its own
network and a network namespace playing the external attacker.

## Components

### Cowrie (`deploy/cowrie`)

* **Pinned.** Cowrie v3.1.7 by commit (`8e36327f`), checked after fetching;
  base images by digest; Python requirements at Cowrie's pinned versions,
  prebuilt wheels only (no compiler in the image).
* **Overlay** (`overlay/apply.py`), refusing to apply if any upstream file it
  touches differs from the reviewed version:
  * `wget`, `curl`, `ftpget`, `tftp`, `nc` replaced with simulated versions:
    names fail to resolve, IP addresses time out, nothing opens a socket. Each
    attempt is a `bearjug.outbound.simulated` event (tool, target, URL; a
    password given on the command line goes in a `password` field so the
    collector treats the event as sensitive);
  * `free` shows configured figures, not the host's `/proc/meminfo`;
  * `direct-tcpip` (`ssh -L`, `ssh -D`) is always recorded and refused,
    whatever the config; `tcpip-forward` (`ssh -R`) has no handler, so it is
    refused;
  * the JA4+ code (FoxIO licence) and the SSH proxy backend are deleted, and
    only the shell backend can start;
  * no fallback to Cowrie's permissive example user database.
* **Entrypoint** (`entrypoint.py`) refuses to start unless: shell backend,
  Telnet off, all three forwarding options explicitly false, no output plugin
  but `jsonlog`, `sensor_name` set, and `userdb.txt` holds only exact
  `user:x:password` lines (no `*`, `!`, `/regex/`).
* **Container**: `--read-only`, `--cap-drop ALL`, `no-new-privileges`, the
  `bearjug-cowrie` uid with the `bearjug-spool` gid, memory/CPU/pid limits,
  `--dns 127.0.0.1`. Two mounts only: its output directory on the evidence
  volume, and its config read-only.

### Network (`roles/sensor/templates/sensor.nft.j2`)

Its own nftables table (`inet bearjug`), loaded by `bearjug-firewall.service`
before Docker starts, so Docker's rules are untouched and a drop here is final
whatever Docker accepts. `bearjug-firewall-check.timer` stops Cowrie if the
table disappears, and Cowrie won't start without it.

Docker publishes port 22 to Cowrie with `userland-proxy` off, so the
connection is plain DNAT: Cowrie records the attacker's real address and no
host process relays attacker traffic.

**DNS finding.** On a user-defined Docker network, the container's resolver is
Docker's embedded DNS server, which forwards lookups to the host's upstream
servers *from the host's network namespace*, so they bypass any firewall rule
on the container's bridge. We confirmed this here (lookups from a container
left the host as root-owned UDP). With `--dns 127.0.0.1`, Docker forwards
inside the container's namespace instead, to an address where nothing
listens, so lookups fail at once and nothing leaves. A test checks the
container's resolver configuration says so.

### Services (`roles/sensor/templates/systemd`)

| Unit | Runs as | Notes |
|---|---|---|
| `bearjug-firewall` | root, oneshot | before `network-pre` and Docker |
| `bearjug-diskguard` | `bearjug-guard` | no network (`PrivateNetwork`); polkit lets it start and stop `bearjug-cowrie.service` and nothing else |
| `bearjug-shipper` | `bearjug-shipper` (+ `bearjug-spool`) | independent of Cowrie, keeps running while Cowrie is stopped |
| `bearjug-cowrie` | root (Docker client); container as `bearjug-cowrie` | requires the firewall, Docker and the disk guard; `ExecCondition` start gate |

All three BearJug services need the evidence volume (`RequiresMountsFor`), so
none starts without it.

**How restarts keep the PR #7 rules.** systemd can start Cowrie behind the
disk guard's back: at boot, after a crash (`Restart=on-failure`), or when a
unit it depends on restarts. Two additions to the guard close that:

* the **start gate** (`bearjug-diskguard --gate`, Cowrie's `ExecCondition`)
  applies the guard's own rules from its saved state: never at or above 80%;
  if the guard stopped Cowrie (or its state is unknown), only below 60% with
  healthy shipping. A "no" skips the start; it isn't a failure, so systemd
  doesn't loop on it;
* the **running check** (`--running-command`): if Cowrie is up while the guard
  says it must be down, the guard stops it again.

An unreadable guard state is now saved as "unknown" at once, so the gate (a
separate process) applies the strict rule too. The shipper's health file is
now 0640 (group `bearjug-guard`) so the guard's account can read it; it holds
no evidence.

### Evidence volume (`roles/sensor/tasks/evidence_volume.yml`)

A LUKS2 volume with ext4, mounted at `/srv/bearjug/evidence` with `noexec`,
`nodev`, `nosuid`, unlocked at boot from `/etc/crypttab`:

* `bearjug_evidence_backing: file` (default): a 12 GiB preallocated image on
  the root disk, for single-disk VPSes. It can't grow, so evidence still can't
  fill the root filesystem.
* `bearjug_evidence_backing: device`: a dedicated blank block device. The role
  refuses to format a device that has any signature.

The key is 64 random bytes in `/etc/bearjug/evidence.key` (root, 0400). That
protects evidence in snapshots, backups and reuse of the volume or image, not
against someone who controls the running sensor (which is why acknowledged
evidence is removed promptly). If you need more, unlock manually after each
reboot (remove the key from crypttab) or use network-bound unlocking (Clevis
and Tang); both are outside this PR. The volume is `nofail`, so a volume that
won't unlock can't stop the machine booting and lock you out.

```
/srv/bearjug/evidence/
  cowrie/{log,tty,downloads}   bearjug-cowrie:bearjug-spool 2770  (Cowrie writes, shipper reads/removes)
  cowrie/state                 bearjug-cowrie 0700                (Cowrie's SSH host keys)
  shipper/                     bearjug-shipper:bearjug-guard 2750 (state 0600, health 0640, dead-letter 0700)
  guard/                       bearjug-guard 0700
```

## Deploying

You need two Ubuntu 24.04 machines (sensor and collector), SSH key access to
both, and Ansible 2.16+ where you run it.

1. `cp deploy/ansible/inventory.example.yml deploy/ansible/inventory.yml` and
   fill it in. Put the synthetic credentials in an Ansible vault. The sensor
   must reach the collector on 8443; give `bearjug_collector_address` the
   collector's private address if they share a network.
2. `cd deploy/ansible && ansible-playbook collector.yml`. It registers every
   sensor in the inventory and leaves each sensor's key and the collector's
   certificate in `secrets/` (git-ignored, 0600).
3. `ansible-playbook sensor.yml`. The first run moves administrative SSH to
   `bearjug_admin_ssh_port` and stops for that host. Set `ansible_port` to the
   admin port and run it again: it builds the Cowrie image on the sensor,
   starts everything, and reports whether Cowrie is running.

Re-running either playbook is safe; CI checks that a second sensor run
changes nothing.

## Checks on a real VPS

CI covers everything above on one machine. These need a real pair of
machines and an internet-facing address, and should be done before the
sensor is left running:

- [ ] From a separate machine on the internet: log in with a synthetic
      credential, explore, run `wget`/`curl` against a server you control,
      try `ssh -L`/`-R`/`-D`; confirm your server saw nothing and the events
      appear at the collector (`bearjug-collector list`).
- [ ] `nmap` the sensor from outside and from the collector: only 22 from
      outside (plus the admin port from your admin address); nothing from the
      collector.
- [ ] Reboot the sensor: the volume unlocks and mounts, the firewall loads
      before Docker, and the guard, shipper and Cowrie come back (CI only does
      a cold start of the services, not a kernel reboot).
- [ ] Collector outage on the real network: stop `bearjug-collector`, fill
      the evidence volume past 80% with `fallocate` in a scratch directory
      on it, watch Cowrie stop and stay stopped, remove the file, start the
      collector, watch the backlog arrive and Cowrie come back.
- [ ] Note the evidence volume's daily growth for the first week and revisit
      the 12 GiB size and thresholds (the policy says so).

## Not in this PR

* Profiles (`fs.pickle`, `uname` strings, per-profile credentials): the image
  uses Cowrie's stock filesystem with a configured hostname. Roadmap PR 6-7.
* SFTP/SCP upload quarantine tests (SFTP is off).
* A reverse proxy in front of the collector (the collector's firewall admits
  only the sensors).
* Off-host alerting: alerts go to the journal as `bearjug-alert`.
