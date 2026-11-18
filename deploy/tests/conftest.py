"""Deployment tests: run as root on a sensor deployed by deploy/ansible.

They treat the sensor as a black box from three places: an "external machine"
(a network namespace whose traffic reaches the sensor like an attacker's), the
host itself, and the collector. deploy/ci/prepare.sh builds that environment
on a fresh Ubuntu 24.04 machine; the GitHub workflow sensor-deploy.yml runs
it, then sensor.yml, then these tests. Settings come from BJ_* variables.
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "src"))

from bearjug.wire import evidence_id  # noqa: E402

E = os.environ
SENSOR_ADDR = E.get("BJ_SENSOR_ADDR", "10.250.0.1")
HONEYPOT_PORT = int(E.get("BJ_HONEYPOT_PORT", "22"))
ADMIN_PORT = int(E.get("BJ_ADMIN_PORT", "22022"))
NETNS = E.get("BJ_NETNS", "bj-ext")
SINK = E.get("BJ_SINK_ADDR", "10.250.0.2")
SINK_TCP = [80, 443, 21, 4444, 8000]
SINK_UDP = [53, 69]
COLLECTOR_CONTAINER = E.get("BJ_COLLECTOR_CONTAINER", "bj-collector")
COLLECTOR_DATA = E.get("BJ_COLLECTOR_DATA", "/data/store")
COLLECTOR_ADDR = E.get("BJ_COLLECTOR_ADDR", "172.31.200.10")
COLLECTOR_PORT = int(E.get("BJ_COLLECTOR_PORT", "8443"))
SENSOR_ID = E.get("BJ_SENSOR_ID", "ci-sensor")
USER = E.get("BJ_USER", "deploy")
PASSWORD = E.get("BJ_PASSWORD", "")
EVIDENCE = Path(E.get("BJ_EVIDENCE", "/srv/bearjug/evidence"))
COWRIE_IMAGE = E.get("BJ_COWRIE_IMAGE", "bearjug/cowrie:3.1.7-bj1")
COWRIE_NETWORK = E.get("BJ_COWRIE_NETWORK", "bearjug-cowrie")
COWRIE_LOG = EVIDENCE / "cowrie/log/cowrie.json"


def sh(*argv, check=True, timeout=120, **kw):
    return subprocess.run(argv, capture_output=True, text=True, check=check, timeout=timeout, **kw)


def wait_for(predicate, timeout, interval=1.0, what="condition"):
    end = time.time() + timeout
    while time.time() < end:
        value = predicate()
        if value:
            return value
        time.sleep(interval)
    raise AssertionError(f"timed out after {timeout}s waiting for {what}")


def is_active(unit):
    return sh("systemctl", "is-active", unit, check=False).stdout.strip()


# --- the external machine --------------------------------------------------------


def client(action, **req):
    """Run the SSH client in the external namespace."""
    req = {"action": action, "host": SENSOR_ADDR, "port": HONEYPOT_PORT, "user": USER, "password": PASSWORD, **req}
    r = sh("ip", "netns", "exec", NETNS, sys.executable, str(HERE / "client.py"), json.dumps(req), check=False, timeout=600)
    if r.returncode != 0:
        raise AssertionError(f"client failed: {r.stderr[-2000:]}")
    return json.loads(r.stdout)


def session(*commands, timeout=60):
    return client("shell", commands=list(commands), timeout=timeout)["results"]


def can_login(user=USER, password=PASSWORD):
    try:
        return client("login", user=user, password=password)["ok"]
    except AssertionError:
        return False


def tcp_from(netns, host, port, timeout=3):
    """Try a TCP connection from inside a network namespace (or the host when
    netns is None). True if it connected."""
    code = f"import socket; socket.create_connection(({host!r}, {port}), {timeout}).close()"
    argv = [sys.executable, "-c", code]
    if netns:
        argv = ["ip", "netns", "exec", netns, *argv]
    return sh(*argv, check=False, timeout=timeout + 10).returncode == 0


# --- the sink: an "attacker server" on the internet side -------------------------


class Sink:
    def __init__(self, log: Path):
        self.log = log
        self.mark = 0

    def entries(self):
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text().splitlines() if line.strip()]

    def hits_since_mark(self):
        return [e for e in self.entries()[self.mark :] if e.get("proto") != "ready"]

    def set_mark(self):
        self.mark = len(self.entries())


@pytest.fixture(scope="session")
def sink(tmp_path_factory):
    log = tmp_path_factory.mktemp("sink") / "sink.jsonl"
    proc = subprocess.Popen(
        ["ip", "netns", "exec", NETNS, sys.executable, str(HERE / "sink.py"), str(log),
         ",".join(map(str, SINK_TCP)), ",".join(map(str, SINK_UDP))]
    )
    s = Sink(log)
    wait_for(lambda: any(e.get("proto") == "ready" for e in s.entries()), 10, 0.2, "the sink")
    # Positive control: the sink is reachable from the host, so silence
    # later means the boundary held, not that the sink was down.
    assert tcp_from(None, SINK, 8000)
    wait_for(lambda: s.hits_since_mark(), 5, 0.2, "the positive control hit")
    s.set_mark()
    yield s
    proc.terminate()


# --- evidence and the collector -------------------------------------------------


def cowrie_events():
    if not COWRIE_LOG.exists():
        return []
    return [json.loads(line) for line in COWRIE_LOG.read_text().splitlines() if line.strip()]


def cowrie_lines():
    if not COWRIE_LOG.exists():
        return []
    return [line for line in COWRIE_LOG.read_bytes().split(b"\n") if line.strip()]


def line_ids(lines):
    return {evidence_id(SENSOR_ID, "cowrie.event", line) for line in lines}


def file_id(path: Path, kind):
    return evidence_id(SENSOR_ID, kind, path.read_bytes())


def collector(*args, check=True):
    return sh("docker", "exec", COLLECTOR_CONTAINER, "bearjug-collector", "--data", COLLECTOR_DATA, *args, check=check)


def collector_ids():
    return {line.split()[0] for line in collector("list").stdout.splitlines() if line.strip()}


def shipper_health():
    try:
        return json.loads((EVIDENCE / "shipper/shipper-state.health.json").read_text())
    except (OSError, ValueError):
        return {}


def guard_state():
    try:
        return json.loads((EVIDENCE / "guard/diskguard-state.json").read_text())
    except (OSError, ValueError):
        return {}


# --- filling the evidence volume --------------------------------------------------

FILLER_DIR = EVIDENCE / "ci-filler"


def volume_percent():
    st = os.statvfs(EVIDENCE)
    used = (st.f_blocks - st.f_bfree) * st.f_frsize
    avail = st.f_bavail * st.f_frsize
    return 100.0 * used / (used + avail)


def fill_to(percent):
    """Add or remove filler until the evidence volume is about ``percent`` full."""
    FILLER_DIR.mkdir(mode=0o700, exist_ok=True)
    for f in sorted(FILLER_DIR.iterdir(), reverse=True):
        if volume_percent() <= percent:
            break
        f.unlink()
    st = os.statvfs(EVIDENCE)
    used = (st.f_blocks - st.f_bfree) * st.f_frsize
    total = used + st.f_bavail * st.f_frsize
    need = int(total * percent / 100) - used
    if need > 0:
        path = FILLER_DIR / f"fill-{time.time_ns()}"
        with open(path, "wb") as f:
            os.posix_fallocate(f.fileno(), 0, need)
    os.sync()
    return volume_percent()


def clear_filler():
    if FILLER_DIR.exists():
        for f in FILLER_DIR.iterdir():
            f.unlink()
    os.sync()


def sha256_file(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def host_name():
    return socket.gethostname()
