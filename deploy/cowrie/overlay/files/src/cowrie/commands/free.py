# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Reuben Dennison
"""BearJug: free. Replaces Cowrie's free, which shows the real host's
/proc/meminfo. The figures come from the config (``[shell]
bearjug_mem_total_kb``), so the simulated machine never reveals the sensor's."""

from __future__ import annotations

import getopt

from cowrie.core.config import CowrieConfig
from cowrie.shell.command import HoneyPotCommand

commands = {}

HEADER = "               total        used        free      shared  buff/cache   available\n"


def _stats() -> dict[str, int]:
    """Kilobytes, deterministic for a given total, in plausible proportions."""
    total = CowrieConfig.getint("shell", "bearjug_mem_total_kb", fallback=16365916)
    swap = CowrieConfig.getint("shell", "bearjug_swap_total_kb", fallback=4194300)
    used = total * 41 // 100
    shared = total * 2 // 100
    cache = total * 33 // 100
    free = total - used - cache
    return {
        "total": total,
        "used": used,
        "free": free,
        "shared": shared,
        "cache": cache,
        "available": free + cache * 9 // 10,
        "swap_total": swap,
        "swap_used": swap * 3 // 100,
        "swap_free": swap - swap * 3 // 100,
    }


def _human(kb: int) -> str:
    value, units = float(kb) * 1024, ["B", "Ki", "Mi", "Gi", "Ti"]
    i = 0
    while value >= 1024 and i < len(units) - 1:
        value /= 1024
        i += 1
    return f"{value:.0f}{units[i]}" if value >= 10 or i == 0 else f"{value:.1f}{units[i]}"


class Command_free(HoneyPotCommand):
    def call(self) -> None:
        try:
            opts, _ = getopt.getopt(self.args, "bkmght", ["human", "total"])
        except getopt.GetoptError as e:
            self.errorWrite(f"free: invalid option -- '{e.opt}'\n")
            self.exit_code = 1
            return
        flags = {o for o, _ in opts}
        if flags & {"-h", "--human"}:
            fmt = _human
        elif "-g" in flags:
            fmt = lambda kb: str(kb // 1048576)  # noqa: E731
        elif "-m" in flags:
            fmt = lambda kb: str(kb // 1024)  # noqa: E731
        elif "-b" in flags:
            fmt = lambda kb: str(kb * 1024)  # noqa: E731
        else:
            fmt = str
        s = _stats()
        out = HEADER
        out += "Mem:   " + "".join(
            f"{fmt(s[k]):>12}" for k in ("total", "used", "free", "shared", "cache", "available")
        ) + "\n"
        out += "Swap:  " + "".join(f"{fmt(s[k]):>12}" for k in ("swap_total", "swap_used", "swap_free")) + "\n"
        if flags & {"-t", "--total"}:
            out += "Total: " + "".join(
                f"{fmt(v):>12}"
                for v in (s["total"] + s["swap_total"], s["used"] + s["swap_used"], s["free"] + s["swap_free"])
            ) + "\n"
        self.write(out)


commands["/usr/bin/free"] = Command_free
commands["free"] = Command_free
