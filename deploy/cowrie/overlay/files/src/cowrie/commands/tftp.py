# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Reuben Dennison
"""BearJug: simulated BusyBox tftp. Replaces Cowrie's tftp, which connects
for real. Never opens a socket and never writes a file."""

from __future__ import annotations

import getopt

from cowrie.commands._bearjug_outbound import SimulatedOutboundCommand

commands = {}

USAGE = """BusyBox v1.36.1 (Ubuntu 1:1.36.1-6ubuntu3.1) multi-call binary.

Usage: tftp [OPTIONS] HOST [PORT]

Transfer a file from/to tftp server

\t-l FILE\tLocal FILE
\t-r FILE\tRemote FILE
\t-g\tGet file
\t-p\tPut file
\t-b SIZE\tTransfer blocks in bytes
"""


class Command_tftp(SimulatedOutboundCommand):
    tool = "tftp"

    def start(self) -> None:
        try:
            opts, args = getopt.gnu_getopt(self.args, "gpl:r:b:")
        except getopt.GetoptError:
            self.errorWrite(USAGE)
            self.exit(1)
            return
        values = dict(opts)
        if not args or not ("-g" in values or "-p" in values):
            self.errorWrite(USAGE)
            self.exit(1)
            return
        host = args[0]
        try:
            port = int(args[1]) if len(args) > 1 else 69
        except ValueError:
            port = 69
        remote = values.get("-r") or values.get("-l") or ""
        outcome = self.outcome_for(host)
        self.record(
            host=host,
            port=port,
            outcome=outcome,
            protocol="udp",
            url=f"tftp://{host}:{port}/{remote.lstrip('/')}",
            direction="put" if "-p" in values else "get",
        )
        message = "tftp: timeout\n" if outcome == "connect_timeout" else f"tftp: bad address '{host}'\n"
        self.finish_later(self.delay_for(outcome), "", message, 1)


commands["/usr/bin/tftp"] = Command_tftp
commands["tftp"] = Command_tftp
