# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Reuben Dennison
"""BearJug: simulated wget. Replaces Cowrie's wget, which fetches for real.

Records each URL and fails the way GNU wget does on a host with no DNS and no
route out. Never opens a socket and never writes a file."""

from __future__ import annotations

import getopt
import time

from cowrie.commands._bearjug_outbound import SimulatedOutboundCommand, parse_url

commands = {}

VERSION = "GNU Wget 1.21.4 built on linux-gnu."

USAGE = """GNU Wget 1.21.4, a non-interactive network retriever.
Usage: wget [OPTION]... [URL]...

Try `wget --help' for more options.
"""

SHORT = "VhbdqvnNSciO:o:a:t:T:w:P:U:e:Y:Q:"
LONG = [
    "version", "help", "background", "debug", "quiet", "verbose", "no-verbose", "spider",
    "continue", "no-check-certificate", "output-document=", "output-file=", "append-output=",
    "tries=", "timeout=", "wait=", "directory-prefix=", "user-agent=", "execute=", "header=",
    "user=", "password=", "http-user=", "http-password=", "post-data=", "method=", "body-data=",
    "limit-rate=", "quota=", "proxy=", "no-proxy", "inet4-only", "inet6-only", "content-disposition",
    "no-clobber", "timestamping", "recursive", "level=", "mirror", "no-parent",
]


class Command_wget(SimulatedOutboundCommand):
    tool = "wget"

    def start(self) -> None:
        try:
            opts, urls = getopt.gnu_getopt(self.args, SHORT, LONG)
        except getopt.GetoptError as e:
            self.errorWrite(f"wget: {e.msg}\n{USAGE}")
            self.exit(2)
            return
        flags = {o for o, _ in opts}
        if "-V" in flags or "--version" in flags:
            self.write(VERSION + "\n")
            self.exit(0)
            return
        if "-h" in flags or "--help" in flags:
            self.write(USAGE)
            self.exit(0)
            return
        if not urls:
            self.errorWrite("wget: missing URL\n" + USAGE)
            self.exit(1)
            return
        quiet = "-q" in flags or "--quiet" in flags
        password = next((v for o, v in opts if o in ("--password", "--http-password")), None)

        output, delay = "", 0.0
        for raw in urls:
            u = parse_url(raw)
            outcome = self.outcome_for(u["host"])
            self.record(host=u["host"], port=u["port"], url=u["url"], outcome=outcome, password=u["password"] or password)
            delay += self.delay_for(outcome)
            if quiet:
                continue
            stamp = time.strftime("%Y-%m-%d %H:%M:%S")
            output += f"--{stamp}--  {u['url']}\n"
            if outcome == "bad_address":
                output += f"{u['url']}: Invalid host name.\n"
            elif outcome == "resolve_failed":
                output += (
                    f"Resolving {u['host']} ({u['host']})... failed: Temporary failure in name resolution.\n"
                    f"wget: unable to resolve host address ‘{u['host']}’\n"
                )
            else:
                output += f"Connecting to {u['host']}:{u['port']}... failed: Connection timed out.\nGiving up.\n\n"
        self.finish_later(delay, "", output, 4)


commands["/usr/bin/wget"] = Command_wget
commands["wget"] = Command_wget
commands["/usr/bin/dget"] = Command_wget
commands["dget"] = Command_wget
