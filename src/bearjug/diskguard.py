"""The disk guard: keeps the sensor's evidence volume from filling up.

It runs on the sensor next to Cowrie and the shipper, and watches the whole
evidence filesystem (Cowrie's logs, TTY recordings, downloads, the shipper's
state and the dead-letter directory all live on it):

* at ``warn_percent`` (70%) it logs a capacity warning and runs the alert
  command, if one is set;
* at ``stop_percent`` (80%) it stops Cowrie cleanly with the stop command, so
  no new evidence is written. The shipper keeps running and delivers the
  backlog;
* it starts Cowrie again only once usage is below ``resume_percent`` (60%)
  **and** the shipper's last pass reached the collector recently.

It never deletes anything. Unacknowledged evidence is not removed to make
room; space comes back only as the shipper delivers evidence and removes
what the collector acknowledged.

The gap between 80% and 60% (hysteresis) keeps Cowrie from flapping on and
off around one threshold. Whether the guard stopped Cowrie is saved in a
small state file, so a restarted guard doesn't start Cowrie while the volume
is still too full.

The guard refuses to run if the evidence directory is on the same filesystem
as ``/``: the evidence volume must never be able to fill the root
filesystem. ``--allow-shared-filesystem`` overrides this for local testing.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from . import policy
from .fsutil import write_private

log = logging.getLogger("bearjug.diskguard")


def volume_usage_percent(path: Path) -> float:
    """Used space on the filesystem holding ``path``, as a percentage of the
    space available to it (blocks reserved for root count as used, like df)."""
    st = os.statvfs(path)
    avail = st.f_bavail * st.f_frsize
    used = (st.f_blocks - st.f_bfree) * st.f_frsize
    usable = used + avail
    return 100.0 * used / usable if usable else 100.0


def shipper_healthy(health_file: Path, *, within_seconds: float, now: datetime | None = None) -> tuple[bool, str]:
    """Whether the shipper's latest pass reached the collector, recently."""
    try:
        health = json.loads(health_file.read_text())
    except FileNotFoundError:
        return False, "shipper has not reported yet"
    except ValueError:
        return False, "shipper health file is unreadable"
    if not health.get("ok"):
        return False, f"shipper's last pass failed: {health.get('error')}"
    checked = datetime.fromisoformat(health["checked_at"])
    age = ((now or datetime.now(timezone.utc)) - checked).total_seconds()
    if age > within_seconds:
        return False, f"shipper last reported {age:.0f}s ago"
    return True, "shipper reached the collector"


def run_command(argv: list[str]) -> bool:
    """Run an operator-configured command (never anything from the spool).
    No shell; a failure is logged and retried on the next check."""
    try:
        result = subprocess.run(argv, capture_output=True, timeout=120, check=False)
    except (OSError, subprocess.TimeoutExpired) as e:
        log.error("command %s failed: %s", argv, e)
        return False
    if result.returncode != 0:
        log.error("command %s exited %d: %s", argv, result.returncode, result.stderr[-500:].decode("utf-8", "replace"))
        return False
    return True


@dataclass
class GuardConfig:
    evidence_dir: Path
    shipper_health: Path
    state_path: Path
    stop_command: list[str]
    start_command: list[str]
    alert_command: list[str] | None = None
    warn_percent: float = policy.VOLUME_WARN_PERCENT
    stop_percent: float = policy.VOLUME_STOP_PERCENT
    resume_percent: float = policy.VOLUME_RESUME_PERCENT
    healthy_within_seconds: float = policy.SHIPPER_HEALTHY_WITHIN_SECONDS
    allow_shared_filesystem: bool = False


class DiskGuard:
    def __init__(
        self,
        config: GuardConfig,
        *,
        usage: Callable[[Path], float] = volume_usage_percent,
        runner: Callable[[list[str]], bool] = run_command,
    ):
        if not config.resume_percent < config.stop_percent:
            raise ValueError("resume threshold must be below the stop threshold")
        if not config.allow_shared_filesystem and os.stat(config.evidence_dir).st_dev == os.stat("/").st_dev:
            raise ValueError(
                f"{config.evidence_dir} is on the root filesystem; the evidence volume must be its own filesystem"
            )
        self.config = config
        self.usage = usage
        self.runner = runner
        self.stopped = self._load()
        self.level = "ok"

    def _load(self) -> bool:
        try:
            return bool(json.loads(self.config.state_path.read_text())["cowrie_stopped"])
        except FileNotFoundError:
            return False

    def _save(self) -> None:
        write_private(
            self.config.state_path,
            json.dumps({"cowrie_stopped": self.stopped, "at": datetime.now(timezone.utc).isoformat()}),
        )

    def _alert(self, message: str) -> None:
        if self.config.alert_command:
            self.runner([*self.config.alert_command, message])

    def check(self) -> str:
        """One check. Returns what the guard did: ``ok``, ``warn``,
        ``stopped``, ``held`` (stopped, waiting to resume) or ``resumed``."""
        c = self.config
        used = self.usage(c.evidence_dir)

        if used >= c.stop_percent:
            if not self.stopped:
                log.critical("evidence volume %.1f%% full (stop at %.0f%%): stopping Cowrie", used, c.stop_percent)
                if self.runner(c.stop_command):
                    self.stopped = True
                    self._save()
                    self._alert(f"BearJug: evidence volume {used:.1f}% full; Cowrie stopped")
                else:
                    log.critical("could not stop Cowrie; will try again")
            return "stopped" if self.stopped else "warn"

        if self.stopped:
            if used >= c.resume_percent:
                log.warning("Cowrie stopped; volume %.1f%% full, resumes below %.0f%%", used, c.resume_percent)
                return "held"
            healthy, why = shipper_healthy(c.shipper_health, within_seconds=c.healthy_within_seconds)
            if not healthy:
                log.warning("Cowrie stopped; volume %.1f%% full but not resuming: %s", used, why)
                return "held"
            log.warning("evidence volume %.1f%% full and shipping is healthy: starting Cowrie", used)
            if self.runner(c.start_command):
                self.stopped = False
                self._save()
                self._alert(f"BearJug: evidence volume {used:.1f}% full; Cowrie restarted")
                return "resumed"
            log.error("could not start Cowrie; will try again")
            return "held"

        if used >= c.warn_percent:
            log.warning("evidence volume %.1f%% full (warning at %.0f%%)", used, c.warn_percent)
            if self.level != "warn":
                self._alert(f"BearJug: evidence volume {used:.1f}% full")
            self.level = "warn"
            return "warn"
        self.level = "ok"
        return "ok"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="bearjug-diskguard", description=__doc__.split("\n")[0])
    p.add_argument("--evidence-dir", type=Path, required=True, help="a directory on the evidence volume")
    p.add_argument("--shipper-health", type=Path, required=True, help="the shipper's <state>.health.json")
    p.add_argument("--state", type=Path, default=Path("diskguard-state.json"))
    p.add_argument("--stop-command", required=True, help='e.g. "docker stop --time 30 cowrie"')
    p.add_argument("--start-command", required=True, help='e.g. "docker start cowrie"')
    p.add_argument("--alert-command", help="run with the message appended as the last argument")
    p.add_argument("--warn-percent", type=float, default=policy.VOLUME_WARN_PERCENT)
    p.add_argument("--stop-percent", type=float, default=policy.VOLUME_STOP_PERCENT)
    p.add_argument("--resume-percent", type=float, default=policy.VOLUME_RESUME_PERCENT)
    p.add_argument("--healthy-within", type=float, default=policy.SHIPPER_HEALTHY_WITHIN_SECONDS)
    p.add_argument("--interval", type=float, default=15.0)
    p.add_argument("--once", action="store_true")
    p.add_argument("--allow-shared-filesystem", action="store_true", help="local testing only")
    args = p.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")

    guard = DiskGuard(
        GuardConfig(
            evidence_dir=args.evidence_dir,
            shipper_health=args.shipper_health,
            state_path=args.state,
            stop_command=shlex.split(args.stop_command),
            start_command=shlex.split(args.start_command),
            alert_command=shlex.split(args.alert_command) if args.alert_command else None,
            warn_percent=args.warn_percent,
            stop_percent=args.stop_percent,
            resume_percent=args.resume_percent,
            healthy_within_seconds=args.healthy_within,
            allow_shared_filesystem=args.allow_shared_filesystem,
        )
    )
    while True:
        guard.check()
        if args.once:
            return 0
        time.sleep(args.interval)


if __name__ == "__main__":
    sys.exit(main())
