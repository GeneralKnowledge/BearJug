"""Disk guard: warn at 70%, stop Cowrie at 80%, resume below 60% once shipping is healthy."""

import json
import os
import sys
from datetime import datetime, timedelta, timezone

import pytest

from bearjug.diskguard import DiskGuard, GuardConfig, run_command, shipper_healthy, volume_usage_percent


class Volume:
    def __init__(self, percent):
        self.percent = percent

    def __call__(self, path):
        return self.percent


class Commands:
    def __init__(self):
        self.calls = []
        self.fail = False

    def __call__(self, argv):
        self.calls.append(argv[0])
        return not self.fail


def write_health(path, ok=True, age=0, error=None):
    at = datetime.now(timezone.utc) - timedelta(seconds=age)
    path.write_text(json.dumps({"checked_at": at.isoformat(), "ok": ok, "error": error, "last_ok_at": None}))


@pytest.fixture
def setup(tmp_path):
    volume, commands = Volume(10), Commands()
    config = GuardConfig(
        evidence_dir=tmp_path,
        shipper_health=tmp_path / "shipper-state.health.json",
        state_path=tmp_path / "diskguard-state.json",
        stop_command=["stop"],
        start_command=["start"],
        alert_command=["alert"],
        allow_shared_filesystem=True,
    )

    def make():
        return DiskGuard(config, usage=volume, runner=commands)

    return make, volume, commands, config


def test_below_warning_does_nothing(setup):
    make, volume, commands, _ = setup
    volume.percent = 69.9
    assert make().check() == "ok"
    assert commands.calls == []


def test_warning_alerts_once_then_logs(setup, caplog):
    make, volume, commands, _ = setup
    guard = make()
    volume.percent = 70
    with caplog.at_level("WARNING"):
        assert guard.check() == "warn"
        assert guard.check() == "warn"
    assert commands.calls == ["alert"]  # one alert, not one per check
    assert "70.0% full" in caplog.text


def test_stops_cowrie_at_80_percent_once(setup):
    make, volume, commands, config = setup
    guard = make()
    volume.percent = 80
    assert guard.check() == "stopped"
    assert guard.check() == "stopped"
    assert commands.calls == ["stop", "alert"]
    assert json.loads(config.state_path.read_text())["cowrie_stopped"] is True


def test_stays_stopped_between_60_and_80_even_when_healthy(setup):
    make, volume, commands, config = setup
    guard = make()
    volume.percent = 85
    guard.check()
    write_health(config.shipper_health)
    for pct in (79, 70, 60):
        volume.percent = pct
        assert guard.check() == "held"
    assert "start" not in commands.calls


def test_does_not_resume_while_shipping_is_unhealthy(setup):
    make, volume, commands, config = setup
    guard = make()
    volume.percent = 90
    guard.check()
    volume.percent = 40
    assert guard.check() == "held"  # shipper has never reported
    write_health(config.shipper_health, ok=False, error="collector unreachable")
    assert guard.check() == "held"
    write_health(config.shipper_health, ok=True, age=600)  # healthy, but stale
    assert guard.check() == "held"
    assert "start" not in commands.calls


def test_resumes_below_60_once_shipping_is_healthy(setup):
    make, volume, commands, config = setup
    guard = make()
    volume.percent = 90
    guard.check()
    volume.percent = 59
    write_health(config.shipper_health)
    assert guard.check() == "resumed"
    assert commands.calls == ["stop", "alert", "start", "alert"]
    assert json.loads(config.state_path.read_text())["cowrie_stopped"] is False
    assert guard.check() == "ok"


def test_failed_stop_is_retried(setup):
    make, volume, commands, config = setup
    guard = make()
    volume.percent = 95
    commands.fail = True
    guard.check()
    assert guard.stopped is False
    commands.fail = False
    assert guard.check() == "stopped"
    assert commands.calls == ["stop", "stop", "alert"]


def test_a_restarted_guard_remembers_it_stopped_cowrie(setup):
    make, volume, commands, config = setup
    volume.percent = 85
    make().check()
    volume.percent = 70
    write_health(config.shipper_health)
    restarted = make()
    assert restarted.stopped is True
    assert restarted.check() == "held"
    assert "start" not in commands.calls


def test_guard_never_deletes_anything(setup, tmp_path):
    make, volume, commands, config = setup
    evidence = tmp_path / "tty"
    evidence.mkdir()
    for i in range(3):
        (evidence / f"{i:064x}").write_bytes(b"unacknowledged")
    guard = make()
    for pct in (75, 85, 99, 100, 59):
        volume.percent = pct
        guard.check()
    assert len(list(evidence.iterdir())) == 3


def test_refuses_the_root_filesystem(tmp_path):
    config = GuardConfig(
        evidence_dir=tmp_path, shipper_health=tmp_path / "h", state_path=tmp_path / "s", stop_command=["x"], start_command=["y"]
    )
    import os

    if os.stat(tmp_path).st_dev == os.stat("/").st_dev:
        with pytest.raises(ValueError, match="root filesystem"):
            DiskGuard(config)
    else:
        pytest.skip("tmp_path is already on its own filesystem")


def test_resume_must_be_below_stop(tmp_path):
    config = GuardConfig(
        evidence_dir=tmp_path,
        shipper_health=tmp_path / "h",
        state_path=tmp_path / "s",
        stop_command=["x"],
        start_command=["y"],
        resume_percent=80,
        allow_shared_filesystem=True,
    )
    with pytest.raises(ValueError):
        DiskGuard(config)


def test_real_usage_and_commands(tmp_path):
    assert 0 <= volume_usage_percent(tmp_path) <= 100
    assert run_command([sys.executable, "-c", "pass"]) is True
    assert run_command([sys.executable, "-c", "raise SystemExit(3)"]) is False
    assert run_command([str(tmp_path / "missing")]) is False


def test_shipper_health_reasons(tmp_path):
    h = tmp_path / "h.json"
    assert shipper_healthy(h, within_seconds=60)[0] is False
    h.write_text("not json")
    assert shipper_healthy(h, within_seconds=60) == (False, "shipper health file is unreadable: JSONDecodeError")
    write_health(h)
    assert shipper_healthy(h, within_seconds=60)[0] is True


# --- review hardening: untrustworthy state and health files ---------------------


@pytest.mark.parametrize(
    "content",
    ["", "{", "[]", "null", '{"cowrie_stopped": "no"}', '{"other": true}', '{"cowrie_stopped": 1}'],
)
def test_corrupt_state_never_restarts_cowrie_unsafely(setup, content):
    make, volume, commands, config = setup
    config.state_path.write_text(content)
    write_health(config.shipper_health)
    guard = make()  # starts despite the bad file
    assert guard.uncertain and guard.stopped
    assert (config.state_path.parent / (config.state_path.name + ".corrupt")).read_text() == content
    volume.percent = 70  # between resume and stop: no restart while uncertain
    assert guard.check() == "held"
    assert "start" not in commands.calls


def test_corrupt_state_still_stops_cowrie_at_the_threshold(setup):
    make, volume, commands, config = setup
    config.state_path.write_text("garbage")
    guard = make()
    volume.percent = 81
    assert guard.check() == "stopped"
    assert commands.calls[0] == "stop"  # stopped even though it might already be
    assert guard.uncertain is False
    assert json.loads(config.state_path.read_text())["cowrie_stopped"] is True


def test_corrupt_state_resumes_only_by_the_safe_rule(setup):
    make, volume, commands, config = setup
    config.state_path.write_text("garbage")
    guard = make()
    volume.percent = 50
    assert guard.check() == "held"  # shipper hasn't reported
    write_health(config.shipper_health)
    assert guard.check() == "resumed"
    assert guard.uncertain is False
    assert json.loads(config.state_path.read_text())["cowrie_stopped"] is False


@pytest.mark.parametrize(
    "content",
    [
        "[]",
        '"ok"',
        "42",
        '{"ok": "yes", "checked_at": "2026-11-18T00:00:00+00:00"}',
        '{"ok": true}',
        '{"ok": true, "checked_at": 12345}',
        '{"ok": true, "checked_at": "yesterday"}',
        '{"ok": true, "checked_at": "2026-11-18T12:00:00"}',
        '{"ok": true, "checked_at": "2999-01-01T00:00:00+00:00"}',
        '{"ok": false, "checked_at": "2026-11-18T12:00:00+00:00", "error": ["x"]}',
    ],
)
def test_malformed_health_reports_are_unhealthy_never_errors(tmp_path, content):
    h = tmp_path / "h.json"
    h.write_text(content)
    healthy, reason = shipper_healthy(h, within_seconds=10**9)
    assert healthy is False and reason


def test_health_file_that_is_a_directory_is_unhealthy(tmp_path):
    (tmp_path / "h.json").mkdir()
    assert shipper_healthy(tmp_path / "h.json", within_seconds=60)[0] is False


def test_guard_keeps_running_with_a_malformed_health_report(setup):
    make, volume, commands, config = setup
    guard = make()
    volume.percent = 90
    guard.check()
    config.shipper_health.write_text('{"ok": true, "checked_at": null}')
    volume.percent = 10
    assert guard.check() == "held"
    assert "start" not in commands.calls


# --- deployment: the start gate and the running check -------------------------
# On the sensor, systemd can start Cowrie too (at boot, or restarting it after a
# crash). The gate keeps those starts inside the guard's rules, and the running
# check stops a Cowrie that is up when the guard says it must be down.

from bearjug.diskguard import main, may_start, read_state  # noqa: E402


class Probe:
    def __init__(self, answer):
        self.answer = answer

    def __call__(self, argv):
        return self.answer


@pytest.fixture
def gate_config(tmp_path):
    return GuardConfig(
        evidence_dir=tmp_path,
        shipper_health=tmp_path / "shipper-state.health.json",
        state_path=tmp_path / "diskguard-state.json",
        stop_command=["stop"],
        start_command=["start"],
        allow_shared_filesystem=True,
    )


@pytest.mark.parametrize("percent, allowed", [(0, True), (79.9, True), (80, False), (95, False)])
def test_gate_with_no_guard_stop_allows_only_below_the_stop_threshold(gate_config, percent, allowed):
    assert may_start(gate_config, usage=Volume(percent))[0] is allowed


@pytest.mark.parametrize("percent", [60, 70, 79.9])
def test_gate_keeps_a_guard_stopped_cowrie_stopped_between_60_and_80(gate_config, percent):
    gate_config.state_path.write_text(json.dumps({"cowrie_stopped": True}))
    write_health(gate_config.shipper_health)
    assert may_start(gate_config, usage=Volume(percent))[0] is False


def test_gate_after_a_guard_stop_needs_healthy_shipping(gate_config):
    gate_config.state_path.write_text(json.dumps({"cowrie_stopped": True}))
    assert may_start(gate_config, usage=Volume(10))[0] is False  # shipper never reported
    write_health(gate_config.shipper_health, ok=False, error="collector unreachable")
    assert may_start(gate_config, usage=Volume(10))[0] is False
    write_health(gate_config.shipper_health)
    assert may_start(gate_config, usage=Volume(10))[0] is True


@pytest.mark.parametrize("content", ["", "{", "[]", '{"cowrie_stopped": "no"}', '{"cowrie_stopped": false, "uncertain": 1}'])
def test_gate_treats_an_untrustworthy_state_as_stopped(gate_config, content):
    gate_config.state_path.write_text(content)
    write_health(gate_config.shipper_health)
    assert may_start(gate_config, usage=Volume(70))[0] is False
    assert may_start(gate_config, usage=Volume(50))[0] is True
    assert gate_config.state_path.read_text() == content  # the gate changes nothing


def test_gate_refuses_evidence_on_the_root_filesystem(tmp_path):
    config = GuardConfig(
        evidence_dir=tmp_path, shipper_health=tmp_path / "h", state_path=tmp_path / "s", stop_command=[], start_command=[]
    )
    if os.stat(tmp_path).st_dev != os.stat("/").st_dev:
        pytest.skip("tmp is its own filesystem here")
    assert may_start(config, usage=Volume(0))[0] is False


def test_gate_cli_exit_codes(tmp_path):
    args = ["--gate", "--evidence-dir", str(tmp_path), "--shipper-health", str(tmp_path / "h"),
            "--state", str(tmp_path / "s"), "--allow-shared-filesystem", "--stop-percent", "101", "--resume-percent", "100"]
    assert main(args) == 0  # nothing stopped, below a 101% stop threshold
    (tmp_path / "s").write_text(json.dumps({"cowrie_stopped": True}))
    assert main(args) == 1  # stopped by the guard, shipper never reported
    assert main([*args[:-4], "--evidence-dir", str(tmp_path / "missing")]) == 1  # can't decide: no


def test_gate_and_guard_agree_after_the_guard_stops_cowrie(setup, gate_config):
    make, volume, commands, config = setup
    guard = make()
    volume.percent = 85
    guard.check()
    write_health(config.shipper_health)
    for percent in (85, 70, 60):
        assert may_start(config, usage=Volume(percent))[0] is False
    assert may_start(config, usage=Volume(59))[0] is True


def test_corrupt_state_is_saved_as_unknown_for_the_gate(setup):
    make, volume, commands, config = setup
    config.state_path.write_text("garbage")
    make()
    assert read_state(config.state_path) == (True, True, None)
    write_health(config.shipper_health)
    assert may_start(config, usage=Volume(70))[0] is False
    guard = make()  # a restarted guard keeps the uncertainty
    assert guard.uncertain and guard.stopped


def test_guard_stops_cowrie_again_if_it_runs_above_the_stop_threshold(tmp_path):
    commands = Commands()
    config = GuardConfig(
        evidence_dir=tmp_path, shipper_health=tmp_path / "h", state_path=tmp_path / "s",
        stop_command=["stop"], start_command=["start"], running_command=["is-active"], allow_shared_filesystem=True,
    )
    probe = Probe(False)
    guard = DiskGuard(config, usage=Volume(85), runner=commands, probe=probe)
    guard.check()
    assert commands.calls == ["stop"]
    guard.check()
    assert commands.calls == ["stop"]  # stopped and not running: nothing to do
    probe.answer = True  # started behind the guard's back
    guard.check()
    assert commands.calls == ["stop", "stop"]
    probe.answer = None  # can't tell: stopping again is the safe answer
    guard.check()
    assert commands.calls == ["stop", "stop", "stop"]


@pytest.mark.parametrize("percent, healthy", [(70, True), (50, False)])
def test_guard_stops_a_cowrie_started_while_it_must_stay_stopped(tmp_path, percent, healthy):
    commands = Commands()
    config = GuardConfig(
        evidence_dir=tmp_path, shipper_health=tmp_path / "h", state_path=tmp_path / "s",
        stop_command=["stop"], start_command=["start"], running_command=["is-active"], allow_shared_filesystem=True,
    )
    config.state_path.write_text(json.dumps({"cowrie_stopped": True}))
    if healthy:
        write_health(config.shipper_health)
    guard = DiskGuard(config, usage=Volume(percent), runner=commands, probe=Probe(True))
    assert guard.check() == "held"
    assert commands.calls == ["stop"]


def test_without_a_running_command_behaviour_is_unchanged(setup):
    make, volume, commands, config = setup
    guard = make()
    volume.percent = 85
    guard.check()
    guard.check()
    assert commands.calls == ["stop", "alert"]


def test_guard_stays_stopped_if_a_start_does_not_bring_cowrie_up(tmp_path):
    commands = Commands()
    config = GuardConfig(
        evidence_dir=tmp_path, shipper_health=tmp_path / "h", state_path=tmp_path / "s",
        stop_command=["stop"], start_command=["start"], running_command=["is-active"], allow_shared_filesystem=True,
    )
    config.state_path.write_text(json.dumps({"cowrie_stopped": True}))
    write_health(config.shipper_health)
    probe = Probe(False)
    guard = DiskGuard(config, usage=Volume(50), runner=commands, probe=probe)
    assert guard.check() == "held"
    assert guard.stopped and read_state(config.state_path)[0] is True
    probe.answer = True
    assert guard.check() == "resumed"
    assert read_state(config.state_path)[0] is False
