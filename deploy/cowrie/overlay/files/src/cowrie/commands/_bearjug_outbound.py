# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Reuben Dennison
"""BearJug: shared code for the simulated outbound network tools.

The simulated host has no working DNS and its outbound connections time out,
like a locked-down server behind a firewall. Nothing in this module or the
commands that use it opens a socket, resolves a name or starts a process. Each
attempt is recorded as a ``bearjug.outbound.simulated`` event.

This is realism, not the safety guarantee: the sensor's firewall denies all
outbound traffic from the honeypot container whatever Cowrie does.
"""

from __future__ import annotations

import ipaddress
from typing import Any
from urllib.parse import urlsplit

from cowrie.shell.command import HoneyPotCommand

EVENT_ID = "bearjug.outbound.simulated"

CONNECT_TIMEOUT_SECONDS = 8.0
"""How long a simulated connection to an IP address hangs before it fails."""

RESOLVE_DELAY_SECONDS = 0.3
"""How long a simulated name lookup takes to fail."""

MAX_INPUT_CHARS = 4096

DEFAULT_PORTS = {"http": 80, "https": 443, "ftp": 21, "tftp": 69}


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def parse_url(raw: str, default_scheme: str = "http") -> dict[str, Any]:
    """Split a URL the way the real tools would, without resolving anything.
    Never raises."""
    text = raw if "://" in raw else f"{default_scheme}://{raw}"
    try:
        parts = urlsplit(text)
        scheme = (parts.scheme or default_scheme).lower()
        host = parts.hostname or ""
        try:
            port = parts.port or DEFAULT_PORTS.get(scheme, 80)
        except ValueError:
            port = DEFAULT_PORTS.get(scheme, 80)
        return {
            "url": text,
            "scheme": scheme,
            "host": host,
            "port": port,
            "path": parts.path or "/",
            "password": parts.password,
        }
    except ValueError:
        return {"url": text, "scheme": default_scheme, "host": "", "port": 80, "path": "/", "password": None}


class SimulatedOutboundCommand(HoneyPotCommand):
    """Base class: records each attempt and fails it the way a host without
    DNS or a route out would."""

    tool = "outbound"

    def record(
        self,
        *,
        host: str,
        port: int | None,
        outcome: str,
        url: str | None = None,
        protocol: str = "tcp",
        password: str | None = None,
        **extra: Any,
    ) -> None:
        fields: dict[str, Any] = {
            "tool": self.tool,
            "input": " ".join([self.tool, *self.args])[:MAX_INPUT_CHARS],
            "target_host": host,
            "target_port": port,
            "transport": protocol,
            "outcome": outcome,
            "simulated": True,
        }
        if url is not None:
            fields["url"] = url
        if password:
            # Marks the event sensitive at the collector, like a login attempt.
            fields["password"] = password
        fields.update(extra)
        self.protocol.events.dispatch(
            EVENT_ID,
            "BearJug simulated %(tool)s to %(target_host)s:%(target_port)s (%(outcome)s); no connection was made",
            **fields,
        )

    def outcome_for(self, host: str) -> str:
        if not host:
            return "bad_address"
        return "connect_timeout" if is_ip(host) else "resolve_failed"

    def delay_for(self, outcome: str) -> float:
        return CONNECT_TIMEOUT_SECONDS if outcome == "connect_timeout" else RESOLVE_DELAY_SECONDS

    def finish_later(self, delay: float, output: str, error: str, code: int) -> None:
        def done() -> None:
            if output:
                self.write(output)
            if error:
                self.errorWrite(error)
            self.exit(code)

        self.callLater(delay, done)
