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

On a deployed sensor two more pieces close the gaps a separate supervisor
(systemd) opens:

* ``--running-command`` (e.g. ``systemctl is-active --quiet
  bearjug-cowrie.service``) tells the guard whether Cowrie is really running.
  If Cowrie runs while the guard says it must be stopped (someone started it
  by hand, or the state was lost), the guard stops it again.
* ``--gate`` answers one question and exits: may Cowrie start now? It applies
  the same rules as the guard (below the stop threshold; if the guard stopped
  Cowrie, or its state is unknown, only below the resume threshold with
  healthy shipping) and changes nothing. Cowrie's systemd unit runs it as an
  ``ExecCondition``, so neither a reboot nor an automatic restart can start
  Cowrie when the guard wouldn't.
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


MAX_CLOCK_AHEAD_SECONDS = 60


def shipper_healthy(health_file: Path, *, within_seconds: float, now: datetime | None = None) -> tuple[bool, str]:
    """Whether the shipper's latest pass reached the collector, recently.

    Anything that isn't a well-formed, recent, successful report counts as
    unhealthy: a missing or unreadable file, the wrong JSON shape, a missing
    or invalid timestamp, a timestamp without a time zone or in the future.
    This never raises, so a bad report can't crash the guard."""
    try:
        health = json.loads(health_file.read_text())
    except FileNotFoundError:
        return False, "shipper has not reported yet"
    except (OSError, ValueError) as e:
        return False, f"shipper health file is unreadable: {type(e).__name__}"
    if not isinstance(health, dict):
        return False, "shipper health report is malformed"
    if health.get("ok") is not True:
        return False, f"shipper's last pass failed: {str(health.get('error'))[:200]}"
    checked_raw = health.get("checked_at")
    if not isinstance(checked_raw, str):
        return False, "shipper health report has no timestamp"
    try:
        checked = datetime.fromisoformat(checked_raw)
    except ValueError:
        return False, "shipper health report has an invalid timestamp"
    if checked.tzinfo is None or checked.utcoffset() is None:
        return False, "shipper health report timestamp has no time zone"
    age = ((now or datetime.now(timezone.utc)) - checked).total_seconds()
    if age < -MAX_CLOCK_AHEAD_SECONDS:
        return False, "shipper health report is dated in the future"
    if age > within_seconds:
        return False, f"shipper last reported {age:.0f}s ago"
    return True, "shipper reached the collector"


def probe_command(argv: list[str]) -> bool | None:
    """Run an operator-configured yes/no command: exit 0 is yes, any other
    exit is no, and a command that can't run or times out is unknown."""
    try:
        return subprocess.run(argv, capture_output=True, timeout=30, check=False).returncode == 0
    except (OSError, subprocess.TimeoutExpired) as e:
        log.error("command %s failed: %s", argv, e)
        return None


def on_root_filesystem(path: Path) -> bool:
    return os.stat(path).st_dev == os.stat("/").st_dev


def read_state(path: Path) -> tuple[bool, bool, str | None]:
    """``(cowrie_stopped, uncertain, problem)`` from the guard's state file,
    without changing anything. A missing file means the guard has never
    stopped Cowrie. A file that can't be trusted means Cowrie's state is
    unknown, which counts as stopped and uncertain."""
    try:
        raw = json.loads(path.read_text())
        if not isinstance(raw, dict) or not isinstance(raw.get("cowrie_stopped"), bool):
            raise ValueError("unexpected shape")
        uncertain = raw.get("uncertain", False)
        if not isinstance(uncertain, bool):
            raise ValueError("unexpected shape")
        return raw["cowrie_stopped"] or uncertain, uncertain, None
    except FileNotFoundError:
        return False, False, None
    except (OSError, ValueError) as e:
        return True, True, str(e)


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
    running_command: list[str] | None = None
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
        probe: Callable[[list[str]], bool | None] = probe_command,
    ):
        if not config.resume_percent < config.stop_percent:
            raise ValueError("resume threshold must be below the stop threshold")
        if not config.allow_shared_filesystem and on_root_filesystem(config.evidence_dir):
            raise ValueError(
                f"{config.evidence_dir} is on the root filesystem; the evidence volume must be its own filesystem"
            )
        self.config = config
        self.usage = usage
        self.runner = runner
        self.probe = probe
        self.uncertain = False
        """True when the saved state couldn't be trusted, so whether Cowrie is
        running is unknown. The guard then stops Cowrie at the stop
        threshold even if it may already be stopped, and starts it only by
        the normal resume rule (below resume, shipping healthy)."""
        self.stopped = self._load()
        self.level = "ok"

    def _load(self) -> bool:
        path = self.config.state_path
        stopped, uncertain, problem = read_state(path)
        if problem is not None:
            # Unknown whether Cowrie is running. Assume it may be stopped, so
            # nothing restarts it except a safe resume, and keep the bad file
            # for inspection.
            log.critical(
                "disk guard state %s is unreadable (%s); treating Cowrie's state as unknown: it will be stopped at "
                "the stop threshold and restarted only below the resume threshold with healthy shipping",
                path,
                problem,
            )
            try:
                os.replace(path, path.with_name(path.name + ".corrupt"))
            except OSError:
                pass
            self.uncertain = True
            # Save "unknown" at once, so the start gate (a separate process)
            # applies the same rule rather than seeing no state at all.
            self.stopped = True
            self._save()
            return True
        self.uncertain = uncertain
        return stopped

    def _save(self) -> None:
        write_private(
            self.config.state_path,
            json.dumps(
                {
                    "cowrie_stopped": self.stopped,
                    "uncertain": self.uncertain,
                    "at": datetime.now(timezone.utc).isoformat(),
                }
            ),
        )

    def _alert(self, message: str) -> None:
        if self.config.alert_command:
            self.runner([*self.config.alert_command, message])

    def _running(self) -> bool | None:
        """Whether Cowrie is really running: None without a running command,
        or when the command couldn't say."""
        if not self.config.running_command:
            return None
        return self.probe(self.config.running_command)

    def _stop_again(self, used: float, why: str) -> None:
        log.critical("Cowrie is running although %s: stopping it again", why)
        if self.runner(self.config.stop_command):
            self._alert(f"BearJug: Cowrie was running although {why}; stopped again ({used:.1f}% full)")
        else:
            log.critical("could not stop Cowrie; will try again")

    def check(self) -> str:
        """One check. Returns what the guard did: ``ok``, ``warn``,
        ``stopped``, ``held`` (stopped, waiting to resume) or ``resumed``."""
        c = self.config
        used = self.usage(c.evidence_dir)
        running = self._running()

        if used >= c.stop_percent:
            if not self.stopped or self.uncertain:
                log.critical("evidence volume %.1f%% full (stop at %.0f%%): stopping Cowrie", used, c.stop_percent)
                if self.runner(c.stop_command):
                    self.stopped = True
                    self.uncertain = False
                    self._save()
                    self._alert(f"BearJug: evidence volume {used:.1f}% full; Cowrie stopped")
                else:
                    log.critical("could not stop Cowrie; will try again")
            elif running is True or (c.running_command and running is None):
                self._stop_again(used, f"the evidence volume is {used:.1f}% full")
            return "stopped" if self.stopped else "warn"

        if self.stopped:
            if used >= c.resume_percent:
                log.warning("Cowrie stopped; volume %.1f%% full, resumes below %.0f%%", used, c.resume_percent)
                if running is True:
                    self._stop_again(used, f"the guard stopped it and the volume is still {used:.1f}% full")
                return "held"
            healthy, why = shipper_healthy(c.shipper_health, within_seconds=c.healthy_within_seconds)
            if not healthy:
                log.warning("Cowrie stopped; volume %.1f%% full but not resuming: %s", used, why)
                if running is True:
                    self._stop_again(used, f"the guard stopped it and shipping is unhealthy ({why})")
                return "held"
            log.warning("evidence volume %.1f%% full and shipping is healthy: starting Cowrie", used)
            if self.runner(c.start_command):
                if c.running_command and self.probe(c.running_command) is False:
                    # The start command succeeded but Cowrie isn't up (for
                    # example the start gate saw something change). Stay in
                    # the stopped state and try again on the next check.
                    log.error("start command succeeded but Cowrie is not running; will try again")
                    return "held"
                self.stopped = False
                self.uncertain = False
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


def may_start(config: GuardConfig, *, usage: Callable[[Path], float] = volume_usage_percent) -> tuple[bool, str]:
    """The start gate: would the guard let Cowrie run now? Read-only.

    * evidence on the root filesystem: no;
    * at or above the stop threshold: no;
    * the guard stopped Cowrie, or its state is unknown: only below the
      resume threshold with healthy shipping (the guard's own resume rule);
    * otherwise: yes.
    """
    c = config
    if not c.allow_shared_filesystem and on_root_filesystem(c.evidence_dir):
        return False, f"{c.evidence_dir} is on the root filesystem"
    used = usage(c.evidence_dir)
    if used >= c.stop_percent:
        return False, f"evidence volume {used:.1f}% full (stop at {c.stop_percent:.0f}%)"
    stopped, uncertain, problem = read_state(c.state_path)
    if stopped:
        why = "its state is unknown" if uncertain or problem else "the disk guard stopped it"
        if used >= c.resume_percent:
            return False, f"{why}; volume {used:.1f}% full, resumes below {c.resume_percent:.0f}%"
        healthy, reason = shipper_healthy(c.shipper_health, within_seconds=c.healthy_within_seconds)
        if not healthy:
            return False, f"{why}; {reason}"
        return True, f"{why}, but the volume is {used:.1f}% full and shipping is healthy"
    return True, f"evidence volume {used:.1f}% full"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="bearjug-diskguard", description=__doc__.split("\n")[0])
    p.add_argument("--evidence-dir", type=Path, required=True, help="a directory on the evidence volume")
    p.add_argument("--shipper-health", type=Path, required=True, help="the shipper's <state>.health.json")
    p.add_argument("--state", type=Path, default=Path("diskguard-state.json"))
    p.add_argument("--stop-command", help='e.g. "systemctl stop bearjug-cowrie.service" (required unless --gate)')
    p.add_argument("--start-command", help='e.g. "systemctl start bearjug-cowrie.service" (required unless --gate)')
    p.add_argument("--alert-command", help="run with the message appended as the last argument")
    p.add_argument(
        "--running-command",
        help='exits 0 while Cowrie runs, e.g. "systemctl is-active --quiet bearjug-cowrie.service"',
    )
    p.add_argument(
        "--gate",
        action="store_true",
        help="exit 0 if Cowrie may start now, 1 if not, changing nothing (for systemd ExecCondition)",
    )
    p.add_argument("--warn-percent", type=float, default=policy.VOLUME_WARN_PERCENT)
    p.add_argument("--stop-percent", type=float, default=policy.VOLUME_STOP_PERCENT)
    p.add_argument("--resume-percent", type=float, default=policy.VOLUME_RESUME_PERCENT)
    p.add_argument("--healthy-within", type=float, default=policy.SHIPPER_HEALTHY_WITHIN_SECONDS)
    p.add_argument("--interval", type=float, default=15.0)
    p.add_argument("--once", action="store_true")
    p.add_argument("--allow-shared-filesystem", action="store_true", help="local testing only")
    args = p.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    if not args.gate and not (args.stop_command and args.start_command):
        p.error("--stop-command and --start-command are required unless --gate is given")

    config = GuardConfig(
        evidence_dir=args.evidence_dir,
        shipper_health=args.shipper_health,
        state_path=args.state,
        stop_command=shlex.split(args.stop_command or ""),
        start_command=shlex.split(args.start_command or ""),
        alert_command=shlex.split(args.alert_command) if args.alert_command else None,
        running_command=shlex.split(args.running_command) if args.running_command else None,
        warn_percent=args.warn_percent,
        stop_percent=args.stop_percent,
        resume_percent=args.resume_percent,
        healthy_within_seconds=args.healthy_within,
        allow_shared_filesystem=args.allow_shared_filesystem,
    )
    if args.gate:
        # Any failure to decide (missing directory, unreadable volume) is a "no".
        try:
            allowed, why = may_start(config)
        except Exception as e:  # noqa: BLE001
            allowed, why = False, f"cannot decide: {type(e).__name__}: {e}"
        print(f"bearjug-diskguard gate: Cowrie {'may start' if allowed else 'must stay stopped'}: {why}", flush=True)
        return 0 if allowed else 1
    guard = DiskGuard(config)
    while True:
        guard.check()
        if args.once:
            return 0
        time.sleep(args.interval)


if __name__ == "__main__":
    sys.exit(main())
