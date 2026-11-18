# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Reuben Dennison
"""BearJug: simulated nc (OpenBSD netcat). Replaces Cowrie's nc, which
connects for real.

Connections fail the way they do on a host with no DNS and no route out.
Listen mode waits, like a listener nobody connects to, until Ctrl-C. ``-e``
and ``-c`` are recorded and never run. Never opens a socket."""

from __future__ import annotations

import getopt

from cowrie.commands._bearjug_outbound import SimulatedOutboundCommand

commands = {}

USAGE = """usage: nc [-46CDdFhklNnrStUuvZz] [-I length] [-i interval] [-M ttl]
\t  [-m minttl] [-O length] [-P proxy_username] [-p source_port]
\t  [-q seconds] [-s sourceaddr] [-T keyword] [-V rtable] [-W recvlimit]
\t  [-w timeout] [-X proxy_protocol] [-x proxy_address[:port]]
\t  [destination] [port]
"""

SHORT = "46bCDdFhklNnrStUuvzZc:e:I:i:M:m:O:P:p:q:s:T:V:W:w:X:x:"


class Command_nc(SimulatedOutboundCommand):
    tool = "nc"

    def start(self) -> None:
        try:
            opts, args = getopt.getopt(self.args, SHORT)
        except getopt.GetoptError as e:
            self.errorWrite(f"nc: {e.msg}\n{USAGE}")
            self.exit(1)
            return
        flags = {o for o, _ in opts}
        if "-h" in flags:
            self.errorWrite(USAGE)
            self.exit(1)
            return
        protocol = "udp" if "-u" in flags else "tcp"
        execute = next((v for o, v in opts if o in ("-e", "-c")), None)
        extra = {"execute": execute} if execute else {}

        if "-l" in flags:
            port = args[-1] if args else next((v for o, v in opts if o == "-p"), "")
            self.record(host="", port=_port(port), outcome="listen_simulated", protocol=protocol, **extra)
            return  # waits like an idle listener; Ctrl-C ends it

        if len(args) < 2:
            self.errorWrite(USAGE)
            self.exit(1)
            return
        host, port = args[0], args[1]
        outcome = self.outcome_for(host)
        self.record(host=host, port=_port(port), outcome=outcome, protocol=protocol, **extra)
        if outcome == "resolve_failed":
            self.finish_later(
                self.delay_for(outcome),
                "",
                f'nc: getaddrinfo for host "{host}" port {port}: Temporary failure in name resolution\n',
                1,
            )
        elif protocol == "udp":
            # UDP "connects" without a handshake; nothing comes back.
            return
        else:
            message = f"nc: connect to {host} port {port} ({protocol}) failed: Connection timed out\n"
            self.finish_later(self.delay_for(outcome), "", message if "-v" in flags else "", 1)


def _port(value: str) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


commands["/bin/nc"] = Command_nc
commands["nc"] = Command_nc
commands["/usr/bin/nc"] = Command_nc
commands["netcat"] = Command_nc
commands["/bin/netcat"] = Command_nc
