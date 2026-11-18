"""The collector's ingestion endpoint.

It accepts exactly one thing, ``POST /v1/evidence`` from an authenticated
sensor, and answers with a short status. It has no other routes, no way to
read evidence back over the network, and no client code: the collector never
connects to a sensor, it only answers requests sensors make.

Someone without a sensor key can still connect, so the server limits what such
a client can cost it (see ``docs/ingestion.md``):

* at most ``max_concurrent_requests`` connections are served; extra ones are
  closed before anything is read;
* every connection has a hard deadline and a per-read idle timeout, so a
  client sending slowly can't hold a slot;
* each client IP has a request rate limit, and a much tighter limit on failed
  authentication;
* everything that can be checked before the body (path, size, metadata, a
  known active sensor, the request time) is checked before the body is read.

These are a last line of defence. A public-facing collector should also sit
behind a reverse proxy and a firewall that only admits sensor addresses.
"""

from __future__ import annotations

import json
import logging
import socket
import ssl
import threading
import time
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from pydantic import ValidationError

from .. import wire
from .store import IngestError, Store

log = logging.getLogger("bearjug.collector")

MAX_TRACKED_CLIENTS = 10_000
BODY_CHUNK = 64 * 1024


class _TokenBucket:
    __slots__ = ("tokens", "updated")

    def __init__(self, burst: float):
        self.tokens = burst
        self.updated = time.monotonic()

    def take(self, rate: float, burst: float, cost: float = 1.0) -> bool:
        now = time.monotonic()
        self.tokens = min(burst, self.tokens + (now - self.updated) * rate)
        self.updated = now
        if self.tokens >= cost:
            self.tokens -= cost
            return True
        return False


class RateLimiter:
    """Per-client-IP request and auth-failure buckets, bounded in memory."""

    def __init__(self, rate: float, burst: float, failures_per_minute: float):
        self.rate, self.burst = rate, burst
        self.fail_rate, self.fail_burst = failures_per_minute / 60.0, failures_per_minute
        self._requests: dict[str, _TokenBucket] = {}
        self._failures: dict[str, _TokenBucket] = {}
        self._lock = threading.Lock()

    def _bucket(self, table: dict[str, _TokenBucket], ip: str, burst: float) -> _TokenBucket:
        b = table.get(ip)
        if b is None:
            if len(table) >= MAX_TRACKED_CLIENTS:
                table.clear()
            b = table[ip] = _TokenBucket(burst)
        return b

    def allow(self, ip: str) -> bool:
        with self._lock:
            fail = self._failures.get(ip)
            if fail is not None:
                fail.take(self.fail_rate, self.fail_burst, cost=0)  # refill only
                if fail.tokens < 1:
                    return False
            return self._bucket(self._requests, ip, self.burst).take(self.rate, self.burst)

    def failed(self, ip: str) -> None:
        with self._lock:
            self._bucket(self._failures, ip, self.fail_burst).take(self.fail_rate, self.fail_burst)


class _Handler(BaseHTTPRequestHandler):
    server: CollectorServer
    server_version = "bearjug-collector"
    sys_version = ""

    def setup(self) -> None:
        # Per-read timeout on the socket, plus a hard deadline that closes the
        # connection however slowly the client trickles bytes in.
        self.timeout = self.server.store.settings.idle_timeout_seconds
        super().setup()
        self._deadline = threading.Timer(self.server.store.settings.request_deadline_seconds, self._expire)
        self._deadline.daemon = True
        self._deadline.start()

    def _expire(self) -> None:
        log.warning("closing connection from %s: request deadline passed", self.client_address[0])
        try:
            self.connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def finish(self) -> None:
        self._deadline.cancel()
        try:
            super().finish()
        except OSError:
            pass

    def _reply(self, status: int, body: dict) -> None:
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)
        self.close_connection = True

    def _unauthenticated(self, why: str) -> None:
        self.server.limiter.failed(self.client_address[0])
        log.warning("refused %s: %s", self.client_address[0], why)
        self._reply(401, {"error": "unauthenticated"})

    def do_GET(self) -> None:  # noqa: N802
        self._reply(404, {"error": "not found"})

    do_PUT = do_DELETE = do_PATCH = do_HEAD = do_GET  # noqa: N815

    def _read_body(self, length: int) -> bytes | None:
        chunks, remaining = [], length
        while remaining:
            chunk = self.rfile.read(min(BODY_CHUNK, remaining))
            if not chunk:
                return None
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def do_POST(self) -> None:  # noqa: N802
        ip = self.client_address[0]
        if not self.server.limiter.allow(ip):
            return self._reply(429, {"error": "too many requests"})
        if self.path != wire.PATH:
            return self._reply(404, {"error": "not found"})
        store = self.server.store
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            return self._reply(411, {"error": "Content-Length required"})
        if length < 0 or length > store.settings.max_evidence_bytes:
            return self._reply(413, {"error": "evidence too large"})

        # Everything checkable without the body is checked before reading it.
        meta_raw = self.headers.get(wire.META_HEADER, "")
        signature = self.headers.get(wire.SIGNATURE_HEADER, "")
        if not meta_raw or len(meta_raw) > wire.MAX_META_BYTES or len(signature) != 64:
            return self._unauthenticated("missing or malformed credentials")
        try:
            meta = wire.ShipMeta.model_validate_json(meta_raw)
        except ValidationError:
            return self._unauthenticated("invalid metadata")
        if meta.size_bytes != length:
            return self._reply(400, {"error": "size does not match Content-Length"})
        key = store.sensor_key(meta.sensor_id)
        if key is None:
            return self._unauthenticated(f"unknown or revoked sensor {meta.sensor_id}")
        if abs(wire.utcnow() - meta.sent_at) > timedelta(seconds=wire.MAX_CLOCK_SKEW_SECONDS):
            return self._unauthenticated("request too old or clock skew too large")

        body = self._read_body(length)
        if body is None:
            return  # client went away or the deadline closed the connection
        if not wire.verify(key, meta_raw, body, signature):
            return self._unauthenticated(f"bad signature for sensor {meta.sensor_id}")
        store.mark_seen(meta.sensor_id, ip)

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
    request_queue_size = 64

    def __init__(self, address: tuple[str, int], store: Store, tls: ssl.SSLContext | None = None):
        super().__init__(address, _Handler)
        self.store = store
        s = store.settings
        self.slots = threading.BoundedSemaphore(s.max_concurrent_requests)
        self.limiter = RateLimiter(s.rate_limit_per_second, s.rate_limit_burst, s.auth_failures_per_minute)
        self.tls = tls

    def process_request(self, request, client_address) -> None:
        # Over the concurrency limit: close at once, before reading anything
        # and before the TLS handshake.
        if not self.slots.acquire(blocking=False):
            log.warning("refused %s: too many concurrent connections", client_address[0])
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address) -> None:
        try:
            if self.tls is not None:
                request.settimeout(self.store.settings.idle_timeout_seconds)
                try:
                    request = self.tls.wrap_socket(request, server_side=True)
                except (ssl.SSLError, OSError) as e:
                    log.warning("TLS handshake with %s failed: %s", client_address[0], e)
                    self.shutdown_request(request)
                    return
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


def tls_context(cert: Path, key: Path) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert, key)
    return ctx
