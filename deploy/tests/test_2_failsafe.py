"""Fail-safe behaviour of a deployed sensor, in one story (runs after the
boundary tests, in order):

collector outage -> evidence held on the sensor -> volume to 70% (warning)
-> 80% (Cowrie stopped, and stays stopped, whatever starts it) -> back below
60% while the collector is still down (still stopped) -> collector back
(backlog delivered, nothing lost, Cowrie restarted) -> crash restart ->
service restarts above the threshold -> a cold start of the whole stack.
"""

from __future__ import annotations

import time

import pytest

from conftest import (
    COLLECTOR_CONTAINER, EVIDENCE, can_login, clear_filler, collector_ids, cowrie_lines, file_id, fill_to,
    guard_state, is_active, line_ids, session, sh, shipper_health, volume_percent, wait_for,
)

GUARD_ROUNDS = 20  # seconds: a few disk guard checks at the CI interval of 5 s

state = {}


def journal_since(since, *args):
    return sh("journalctl", "--no-pager", "--since", since, *args, check=False).stdout


def cowrie_down():
    return is_active("bearjug-cowrie.service") != "active"


@pytest.fixture(scope="module", autouse=True)
def cleanup():
    yield
    clear_filler()
    sh("docker", "start", COLLECTOR_CONTAINER, check=False)


def test_collector_outage_is_seen_by_the_shipper():
    state["start"] = time.strftime("%Y-%m-%d %H:%M:%S")
    sh("docker", "stop", COLLECTOR_CONTAINER)
    wait_for(lambda: shipper_health().get("ok") is False, 120, 2, "the shipper to report the outage")
    assert is_active("bearjug-shipper.service") == "active"
    assert is_active("bearjug-cowrie.service") == "active"  # an outage alone doesn't stop Cowrie


def test_evidence_is_held_while_the_collector_is_down():
    before = set(cowrie_lines())
    session("echo outage-evidence", "cat /etc/hostname")
    time.sleep(3)
    new = [line for line in cowrie_lines() if line not in before]
    assert new
    state["outage_ids"] = line_ids(new)
    tty = [p for p in (EVIDENCE / "cowrie/tty").iterdir() if len(p.name) == 64]
    assert tty, "the session's TTY log should be waiting in the spool"
    state["outage_ids"] |= {file_id(p, "tty.log") for p in tty}


def test_volume_at_70_percent_warns():
    since = time.strftime("%Y-%m-%d %H:%M:%S")
    fill_to(72)
    wait_for(lambda: "full" in journal_since(since, "-t", "bearjug-alert"), 60, 2, "the 70% alert")
    assert is_active("bearjug-cowrie.service") == "active"


def test_volume_at_80_percent_stops_cowrie_and_it_stays_stopped():
    since = time.strftime("%Y-%m-%d %H:%M:%S")
    fill_to(82)
    wait_for(cowrie_down, 60, 1, "Cowrie to stop")
    assert guard_state().get("cowrie_stopped") is True
    assert "Cowrie stopped" in journal_since(since, "-t", "bearjug-alert")
    assert not can_login()
    # Nothing else may start it: not an operator, not systemd.
    sh("systemctl", "start", "bearjug-cowrie.service", check=False)
    time.sleep(3)
    assert cowrie_down()
    assert "must stay stopped" in journal_since(since, "-u", "bearjug-cowrie.service")
    assert is_active("bearjug-shipper.service") == "active"


def test_below_60_percent_with_the_collector_down_cowrie_stays_stopped():
    fill_to(50)
    assert volume_percent() < 60
    time.sleep(GUARD_ROUNDS)
    assert cowrie_down()
    assert shipper_health().get("ok") is False


def test_collector_recovery_delivers_the_backlog_and_restarts_cowrie():
    sh("docker", "start", COLLECTOR_CONTAINER)
    wait_for(lambda: state["outage_ids"] <= collector_ids(), 180, 2, "the outage evidence at the collector")
    # Nothing unacknowledged was lost, and acknowledged TTY logs left the sensor.
    wait_for(lambda: not [p for p in (EVIDENCE / "cowrie/tty").iterdir() if len(p.name) == 64], 120, 2,
             "TTY logs to be removed after acknowledgement")
    wait_for(lambda: not cowrie_down(), 120, 2, "the disk guard to restart Cowrie")
    assert guard_state().get("cowrie_stopped") is False
    wait_for(can_login, 60, 2, "Cowrie to accept logins again")


def test_a_crashed_cowrie_is_restarted_by_systemd():
    sh("docker", "kill", "bearjug-cowrie")
    wait_for(lambda: is_active("bearjug-cowrie.service") == "active" and can_login(), 120, 3,
             "systemd to restart Cowrie after the crash")


def test_restarts_above_the_threshold_keep_cowrie_stopped():
    fill_to(85)
    wait_for(cowrie_down, 60, 1, "Cowrie to stop")
    for unit in ["bearjug-diskguard.service", "docker.service", "bearjug-shipper.service"]:
        sh("systemctl", "restart", unit)
        time.sleep(5)
        assert cowrie_down(), f"restarting {unit} restarted Cowrie"
    # And a manual start with the guard's state removed (lost state) is still
    # refused, because the volume itself is over the threshold.
    (EVIDENCE / "guard/diskguard-state.json").unlink()
    sh("systemctl", "start", "bearjug-cowrie.service", check=False)
    time.sleep(3)
    assert cowrie_down()
    clear_filler()
    wait_for(lambda: not cowrie_down(), 120, 2, "Cowrie to resume below 60%")


def test_cold_start_of_the_whole_stack():
    """As close to a reboot as CI allows: stop everything, lock the evidence
    volume, then start Cowrie alone and let systemd bring up what it needs
    (unlock from crypttab, mount from fstab, firewall, disk guard, Docker).
    A real reboot of a VPS is in the deployment checklist."""
    for unit in ["bearjug-cowrie.service", "bearjug-shipper.service", "bearjug-diskguard.service"]:
        sh("systemctl", "stop", unit)
    sh("umount", str(EVIDENCE))
    sh("systemctl", "stop", "systemd-cryptsetup@bearjug\\x2devidence.service", check=False)
    sh("cryptsetup", "close", "bearjug-evidence", check=False)
    assert not sh("findmnt", str(EVIDENCE), check=False).stdout

    sh("systemctl", "start", "bearjug-cowrie.service", "bearjug-shipper.service")
    wait_for(lambda: is_active("bearjug-cowrie.service") == "active", 120, 2, "Cowrie after a cold start")
    assert sh("findmnt", str(EVIDENCE), check=False).stdout
    for unit in ["bearjug-diskguard.service", "bearjug-shipper.service", "bearjug-firewall.service"]:
        assert is_active(unit) == "active", unit
    wait_for(can_login, 60, 2, "logins after a cold start")
    before = set(cowrie_lines())
    session("echo after-cold-start")
    time.sleep(2)
    new = line_ids([line for line in cowrie_lines() if line not in before])
    wait_for(lambda: new <= collector_ids(), 120, 2, "evidence delivery after a cold start")
