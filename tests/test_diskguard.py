"""Disk guard: warn at 70%, stop Cowrie at 80%, resume below 60% once shipping is healthy."""

import json
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
    assert shipper_healthy(h, within_seconds=60) == (False, "shipper health file is unreadable")
    write_health(h)
    assert shipper_healthy(h, within_seconds=60)[0] is True
