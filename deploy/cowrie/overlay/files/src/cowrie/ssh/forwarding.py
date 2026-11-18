# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Reuben Dennison
"""BearJug: SSH direct-tcpip (``ssh -L``, ``ssh -D``) requests are recorded
and always refused.

Replaces Cowrie's forwarding module, which can relay traffic to the
requested address (or a configured redirect) and fingerprints it with the
vendored JA4+ code, which the overlay deletes. Nothing here opens a socket. Remote forwarding
(``ssh -R``, the ``tcpip-forward`` global request) is refused by Twisted
because Cowrie's avatar has no handler for it.
"""

from __future__ import annotations

from twisted.conch.error import ConchError
from twisted.conch.ssh import connection, forwarding


def cowrieOpenConnectForwardingClient(remoteWindow, remoteMaxPacket, data, avatar):
    try:
        remoteHP, origHP = forwarding.unpackOpen_direct_tcpip(data)
    except Exception:
        remoteHP, origHP = ("", 0), ("", 0)
    events = getattr(getattr(getattr(avatar, "conn", None), "transport", None), "events", None)
    if events:
        events.dispatch(
            "cowrie.direct-tcpip.request",
            "direct-tcp connection request to %(dst_ip)s:%(dst_port)s from %(orig_ip)s:%(orig_port)s refused",
            dst_ip=remoteHP[0],
            dst_port=remoteHP[1],
            orig_ip=origHP[0],
            orig_port=origHP[1],
            refused=True,
        )
    raise ConchError("administratively prohibited", connection.OPEN_ADMINISTRATIVELY_PROHIBITED)
