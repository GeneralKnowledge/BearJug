"""The Cowrie container's entrypoint refuses unsafe configurations.

These run without Docker; the deployment workflow also boots the real image."""

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("bearjug_entrypoint", ROOT / "deploy/cowrie/entrypoint.py")
entrypoint = importlib.util.module_from_spec(spec)
spec.loader.exec_module(entrypoint)

SAFE = """
[honeypot]
sensor_name = sensor-1
backend = shell
[ssh]
forwarding = false
forward_redirect = false
forward_tunnel = false
[telnet]
enabled = false
[output_jsonlog]
enabled = true
"""


def cfg(tmp_path, text):
    p = tmp_path / "cowrie.cfg"
    p.write_text(text)
    return entrypoint.check_config(p)


def userdb(tmp_path, text):
    p = tmp_path / "userdb.txt"
    p.write_text(text)
    return entrypoint.check_userdb(p)


def test_safe_config_passes(tmp_path):
    assert cfg(tmp_path, SAFE) == []


def test_the_ansible_template_is_safe(tmp_path):
    jinja2 = pytest.importorskip("jinja2")
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(ROOT / "deploy/ansible/roles/sensor/templates"))
    text = env.get_template("cowrie.cfg.j2").render(
        ansible_managed="test", bearjug_sensor_id="sensor-1", bearjug_fake_hostname="prod-db-01",
        bearjug_ttylog_min_free_bytes=1, bearjug_fake_mem_total_kb=1, bearjug_ssh_banner="SSH-2.0-OpenSSH_9.6",
    )
    assert cfg(tmp_path, text) == []


@pytest.mark.parametrize(
    "change, problem",
    [
        (("backend = shell", "backend = proxy"), "backend must be shell"),
        (("backend = shell", "backend = llm"), "backend must be shell"),
        (("sensor_name = sensor-1", "sensor_name ="), "sensor_name"),
        (("forwarding = false", "forwarding = true"), "forwarding must be set to false"),
        (("forwarding = false\n", ""), "forwarding must be set to false"),  # Cowrie's default is true
        (("forward_redirect = false", "forward_redirect = yes"), "forward_redirect"),
        (("forward_tunnel = false", "forward_tunnel = maybe"), "forward_tunnel"),  # unparseable counts as on
        (("[telnet]\nenabled = false", "[telnet]\nenabled = true"), "telnet"),
        (("[output_jsonlog]\nenabled = true", "[output_jsonlog]\nenabled = false"), "output_jsonlog"),
    ],
)
def test_unsafe_config_is_refused(tmp_path, change, problem):
    old, new = change
    assert old in SAFE
    problems = cfg(tmp_path, SAFE.replace(old, new))
    assert any(problem in p for p in problems), problems


@pytest.mark.parametrize("section", ["output_elasticsearch", "output_virustotal", "output_socketlog", "output_s3"])
def test_network_output_plugins_are_refused(tmp_path, section):
    assert any(section in p for p in cfg(tmp_path, SAFE + f"\n[{section}]\nenabled = true\n"))


@pytest.mark.parametrize("section", ["proxy", "backend_pool", "llm"])
def test_proxy_pool_and_llm_sections_are_refused(tmp_path, section):
    assert cfg(tmp_path, SAFE + f"\n[{section}]\nfoo = bar\n")


def test_missing_config_is_refused(tmp_path):
    assert entrypoint.check_config(tmp_path / "nope.cfg")


def test_exact_credentials_pass(tmp_path):
    assert userdb(tmp_path, "# comment\ndeploy:x:Summer2024!\nbackup:x:b4ckup-2019\n") == []


@pytest.mark.parametrize(
    "line",
    [
        "root:x:*",  # any password
        "root:x:pass*",
        "*:x:secret",  # any user
        "root:x:!123456",  # negation
        "root:x:/^a.*/",  # regex
        "root:x:/abc/i",
        "/r.*/:x:secret",
        "root:x:",  # empty
        "root:x: padded",
        "root:secret",  # wrong shape
        "Root:x:secret",  # not a plain account name
    ],
)
def test_wildcard_negated_regex_or_malformed_credentials_are_refused(tmp_path, line):
    assert userdb(tmp_path, line + "\n")


def test_missing_or_empty_userdb_is_refused(tmp_path):
    assert entrypoint.check_userdb(tmp_path / "userdb.txt")
    assert userdb(tmp_path, "# only comments\n\n")
