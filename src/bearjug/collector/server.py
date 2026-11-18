"""The collector's ingestion endpoint.

It accepts exactly one thing, ``POST /v1/evidence`` from an authenticated
sensor, and answers with a short status. It has no other routes, no way to
read evidence back over the network, and no client code: the collector never
connects to a sensor, it only answers requests sensors make.
"""

from __future__ import annotations

import json
import logging
import ssl
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from pydantic import ValidationError

from .. import wire
from .keys import load_sensor_keys
from .store import IngestError, Store

log = logging.getLogger("bearjug.collector")


class _Handler(BaseHTTPRequestHandler):
    server: CollectorServer
    timeout = 30
    server_version = "bearjug-collector"
    sys_version = ""

    def _reply(self, status: int, body: dict) -> None:
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:  # noqa: N802
        self._reply(404, {"error": "not found"})

    do_PUT = do_DELETE = do_PATCH = do_HEAD = do_GET  # noqa: N815

    def do_POST(self) -> None:  # noqa: N802
        if self.path != wire.PATH:
            return self._reply(404, {"error": "not found"})
        store = self.server.store
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            return self._reply(411, {"error": "Content-Length required"})
        if length < 0 or length > store.settings.max_evidence_bytes:
            return self._reply(413, {"error": "evidence too large"})

        meta_raw = self.headers.get(wire.META_HEADER, "")
        signature = self.headers.get(wire.SIGNATURE_HEADER, "")
        if not meta_raw or len(meta_raw) > wire.MAX_META_BYTES or not signature:
            return self._reply(401, {"error": "unauthenticated"})
        try:
            meta = wire.ShipMeta.model_validate_json(meta_raw)
        except ValidationError:
            return self._reply(400, {"error": "invalid metadata"})

        key = self.server.sensor_keys().get(meta.sensor_id)
        body = self.rfile.read(length)
        # The signature is checked before anything in the body is looked at.
        if key is None or not wire.verify(key, meta_raw, body, signature):
            log.warning("rejected unauthenticated upload claiming sensor %s from %s", meta.sensor_id, self.client_address[0])
            return self._reply(401, {"error": "unauthenticated"})
        skew = abs(wire.utcnow() - meta.sent_at)
        if skew > timedelta(seconds=wire.MAX_CLOCK_SKEW_SECONDS):
            return self._reply(401, {"error": "request too old or clock skew too large"})

        try:
            status, eid = store.ingest(meta, body)
        except IngestError as e:
            log.warning("sensor %s: %s rejected: %s", meta.sensor_id, meta.kind.value, e)
            return self._reply(e.status, {"error": str(e)})
        return self._reply(201 if status == "stored" else 200, {"status": status, "evidence_id": eid})

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        log.info("%s %s", self.client_address[0], format % args)


class CollectorServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], store: Store, tls: ssl.SSLContext | None = None):
        super().__init__(address, _Handler)
        self.store = store
        if tls is not None:
            self.socket = tls.wrap_socket(self.socket, server_side=True)

    def sensor_keys(self) -> dict[str, bytes]:
        # Re-read on each request so add-sensor takes effect without a restart.
        return load_sensor_keys(self.store.sensors_path)


def tls_context(cert: Path, key: Path) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert, key)
    return ctx
