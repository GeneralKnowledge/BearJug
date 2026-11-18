# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Reuben Dennison
"""BearJug: simulated BusyBox ftpget. Replaces Cowrie's ftpget, which
connects for real. Never opens a socket and never writes a file."""

from __future__ import annotations

import getopt

from cowrie.commands._bearjug_outbound import SimulatedOutboundCommand

commands = {}

USAGE = """BusyBox v1.36.1 (Ubuntu 1:1.36.1-6ubuntu3.1) multi-call binary.

Usage: ftpget [OPTIONS] HOST [LOCAL_FILE] REMOTE_FILE

Download a file via FTP

\t-c\tContinue previous transfer
\t-v\tVerbose
\t-u USER\tUsername
\t-p PASS\tPassword
\t-P PORT\tPort
"""


class Command_ftpget(SimulatedOutboundCommand):
    tool = "ftpget"

    def start(self) -> None:
        try:
            opts, args = getopt.getopt(self.args, "cvu:p:P:")
        except getopt.GetoptError:
            self.errorWrite(USAGE)
            self.exit(1)
            return
        if len(args) < 2:
            self.errorWrite(USAGE)
            self.exit(1)
            return
        values = dict(opts)
        host = args[0]
        try:
            port = int(values.get("-P", "21"))
        except ValueError:
            port = 21
        outcome = self.outcome_for(host)
        self.record(
            host=host,
            port=port,
            outcome=outcome,
            url=f"ftp://{host}:{port}/{args[-1].lstrip('/')}",
            password=values.get("-p"),
            username=values.get("-u"),
        )
        if outcome == "connect_timeout":
            message = f"ftpget: can't connect to remote host ({host}): Connection timed out\n"
        else:
            message = f"ftpget: bad address '{host}'\n"
        self.finish_later(self.delay_for(outcome), "", message, 1)


commands["/usr/bin/ftpget"] = Command_ftpget
commands["ftpget"] = Command_ftpget
