"""The adopted evidence policy is what the code actually uses."""

import json

from bearjug import policy
from bearjug.collector.store import Settings, init_data_dir
from bearjug.diskguard import GuardConfig
from bearjug.shipper import Config


def test_policy_values_are_the_adopted_ones():
    assert policy.RETENTION_DAYS_SENSITIVE == 30
    assert policy.RETENTION_DAYS_DEFAULT == 90
    assert policy.MAX_EVIDENCE_BYTES == 33554432
    assert policy.SENSITIVE_READERS == ()
    assert policy.DEAD_LETTER_RETENTION_DAYS == 14
    assert policy.DEAD_LETTER_MAX_BYTES == 67108864
    assert policy.UNPRESERVED_RETENTION_DAYS == 7
    assert policy.SPOOL_WARN_BYTES == 8192 * 1024 * 1024
    assert policy.EVIDENCE_VOLUME_BYTES == 12 * 1024**3
    assert (policy.VOLUME_WARN_PERCENT, policy.VOLUME_STOP_PERCENT, policy.VOLUME_RESUME_PERCENT) == (70, 80, 60)


def test_generated_collector_config_uses_the_policy(tmp_path):
    init_data_dir(tmp_path / "c")
    config = json.loads((tmp_path / "c" / "config.json").read_text())
    assert config["retention_days_sensitive"] == 30
    assert config["retention_days_default"] == 90
    assert config["max_evidence_bytes"] == 33554432
    assert config["sensitive_readers"] == []
    assert Settings().sensitive_readers == []


def test_shipper_defaults_use_the_policy(tmp_path):
    c = Config(sensor_id="s", key=b"k" * 32, collector_url="https://c")
    assert c.dead_letter_retention_days == 14
    assert c.dead_letter_max_bytes == 64 * 1024 * 1024
    assert c.unpreserved_retention_days == 7
    assert c.spool_warn_bytes == 8192 * 1024 * 1024
    assert c.max_file_bytes == 32 * 1024 * 1024


def test_shipper_cli_defaults_use_the_policy(monkeypatch, tmp_path):
    import bearjug.shipper as shipper_mod

    captured = {}

    class Stop(Exception):
        pass

    def fake_shipper(config):
        captured["config"] = config
        raise Stop

    monkeypatch.setattr(shipper_mod, "Shipper", fake_shipper)
    key = tmp_path / "k"
    key.write_text("ab" * 32)
    try:
        shipper_mod.main(["--sensor-id", "s", "--key-file", str(key), "--collector", "https://c", "--once"])
    except Stop:
        pass
    c = captured["config"]
    assert (c.dead_letter_retention_days, c.dead_letter_max_bytes, c.unpreserved_retention_days, c.spool_warn_bytes) == (
        14,
        64 * 1024 * 1024,
        7,
        8192 * 1024 * 1024,
    )


def test_disk_guard_defaults_use_the_policy(tmp_path):
    g = GuardConfig(evidence_dir=tmp_path, shipper_health=tmp_path / "h", state_path=tmp_path / "s", stop_command=["x"], start_command=["y"])
    assert (g.warn_percent, g.stop_percent, g.resume_percent) == (70, 80, 60)
