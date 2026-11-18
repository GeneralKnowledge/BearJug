"""BearJug Cowrie entrypoint: refuse to start unless the configuration is safe.

Runs inside the container (which has no shell) before Cowrie. It checks the
mounted ``etc/cowrie.cfg`` and ``etc/userdb.txt`` and exits with status 78
(EX_CONFIG) on the first problem, so a missing or unsafe configuration never
becomes a running honeypot:

* backend is the emulated shell; Telnet is off;
* SSH forwarding, redirect and tunnelling are off;
* no output plugin but ``jsonlog`` is enabled (no network outputs);
* ``sensor_name`` is set, so events never carry the container's host name;
* ``userdb.txt`` exists and holds only exact synthetic credentials: no
  wildcard (``*``), no negation (``!``), no regular expression (``/.../``).

Then it runs Cowrie in the foreground with ``twistd``, in this process.
"""

from __future__ import annotations

import configparser
import os
import re
import sys
from pathlib import Path

ETC = Path("etc")
EX_CONFIG = 78
USERNAME = re.compile(r"^[a-z_][a-z0-9_.-]{0,31}$")
REGEX_RULE = re.compile(r"^/(.+)/(i)?$")  # how Cowrie's UserDB spots a regex rule


def fail(message: str) -> None:
    print(f"bearjug-entrypoint: refusing to start: {message}", file=sys.stderr, flush=True)
    sys.exit(EX_CONFIG)


def check_config(path: Path) -> list[str]:
    if not path.is_file():
        return [f"{path} is missing"]
    cfg = configparser.ConfigParser(interpolation=None)
    try:
        cfg.read(path)
    except configparser.Error as e:
        return [f"{path} does not parse: {e}"]
    problems = []

    def get(section: str, option: str) -> str | None:
        return cfg.get(section, option, fallback=None)

    def is_true(section: str, option: str, default: bool) -> bool:
        try:
            return cfg.getboolean(section, option, fallback=default)
        except ValueError:
            return True  # unparseable counts as on

    if (get("honeypot", "backend") or "shell") != "shell":
        problems.append("[honeypot] backend must be shell")
    if not (get("honeypot", "sensor_name") or "").strip():
        problems.append("[honeypot] sensor_name must be set")
    if is_true("telnet", "enabled", False):
        problems.append("[telnet] enabled must be false")
    # Cowrie's own default for forwarding is true, so it must be set explicitly.
    for option in ("forwarding", "forward_redirect", "forward_tunnel"):
        if get("ssh", option) is None or is_true("ssh", option, True):
            problems.append(f"[ssh] {option} must be set to false")
    for section in cfg.sections():
        if section.startswith("output_") and section != "output_jsonlog" and is_true(section, "enabled", False):
            problems.append(f"[{section}] must not be enabled: only jsonlog is allowed")
    if not is_true("output_jsonlog", "enabled", True):
        problems.append("[output_jsonlog] must be enabled")
    if cfg.has_section("proxy") or cfg.has_section("backend_pool") or cfg.has_section("llm"):
        problems.append("proxy, backend_pool and llm sections are not allowed")
    return problems


def check_userdb(path: Path) -> list[str]:
    """Exact synthetic credentials only: ``user:x:password`` per line."""
    if not path.is_file():
        return [f"{path} is missing: without it every login would be refused, which is not a sensor"]
    problems, entries = [], 0
    for n, line in enumerate(path.read_text(encoding="ascii", errors="replace").splitlines(), 1):
        if not line.strip() or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) != 3:
            problems.append(f"userdb.txt line {n}: expected user:x:password")
            continue
        user, _, password = parts
        if not USERNAME.match(user):
            problems.append(f"userdb.txt line {n}: username is not a plain account name")
        if not password:
            problems.append(f"userdb.txt line {n}: empty password")
        elif "*" in password or password.startswith("!") or REGEX_RULE.match(password) or password != password.strip():
            problems.append(f"userdb.txt line {n}: wildcard, negated or regex password; exact matches only")
        entries += 1
    if entries == 0:
        problems.append("userdb.txt has no credentials")
    return problems


def main() -> None:
    problems = check_config(ETC / "cowrie.cfg") + check_userdb(ETC / "userdb.txt")
    if problems:
        fail("; ".join(problems))
    os.umask(0o027)
    sys.argv = ["twistd", "-n", "--umask=0027", "--pidfile=", "--logger", "cowrie.python.logfile.stdoutLogger", "cowrie"]
    from twisted.scripts.twistd import run

    run()


if __name__ == "__main__":
    main()
