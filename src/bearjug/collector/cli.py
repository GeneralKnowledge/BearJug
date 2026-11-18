"""``bearjug-collector``: set up, run and administer a collector data directory."""

from __future__ import annotations

import argparse
import logging
import os
import sys
import threading
import time
from pathlib import Path

from ..fsutil import write_private
from .server import CollectorServer, tls_context
from .store import HEARTBEAT_STALE_SECONDS, Store, init_data_dir

log = logging.getLogger("bearjug.collector")
HEARTBEAT_SECONDS = 2.0


def _write_key(path: Path, key: bytes) -> None:
    write_private(path, key.hex() + "\n", exclusive=True)


def _print_report(report) -> None:
    for label, items in (
        ("interrupted temp writes removed", report.temp_files_removed),
        ("orphaned blobs moved to orphans/", report.orphans_quarantined),
        ("interrupted deletions completed", report.deletions_completed),
        ("MISSING evidence (record without its encrypted bytes)", report.missing),
        ("CORRUPT evidence (does not decrypt or match its sha256)", report.corrupt),
    ):
        if items:
            print(f"{label}: {len(items)}")
            for eid in items:
                print(f"  {eid}")
    print("healthy" if report.healthy else "NOT HEALTHY")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="bearjug-collector")
    p.add_argument("--data", type=Path, required=True, help="collector data directory")
    p.add_argument("--actor", default=os.environ.get("USER", "operator"), help="who is acting, for the audit log")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init", help="create the data directory, config and evidence key")

    s = sub.add_parser("add-sensor", help="register a sensor and write its shipper key")
    s.add_argument("sensor_id")
    s.add_argument("--key-out", type=Path, required=True, help="file to write the sensor's key to (give it to the shipper)")

    s = sub.add_parser("replace-sensor-key", help="issue a sensor a new key; the old one stops working at once")
    s.add_argument("sensor_id")
    s.add_argument("--key-out", type=Path, required=True)
    s.add_argument("--reason", required=True)

    s = sub.add_parser("revoke-sensor", help="refuse all further uploads from a sensor")
    s.add_argument("sensor_id")
    s.add_argument("--reason", required=True)

    sub.add_parser("sensors", help="list sensors, their status and when each was last seen")

    s = sub.add_parser("rotate-key", help="encrypt new evidence under a new key, and confirm the running collector uses it")
    s.add_argument("--wait", type=float, default=10.0, help="seconds to wait for a running collector to confirm")

    sub.add_parser("key-status", help="show the active evidence key and the one a running collector is using")

    s = sub.add_parser("serve", help="run the ingestion endpoint")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8443)
    s.add_argument("--tls-cert", type=Path)
    s.add_argument("--tls-key", type=Path)

    s = sub.add_parser("check", help="reconcile blobs and records; exit 1 if any evidence is missing or corrupt")
    s.add_argument("--deep", action="store_true", help="also decrypt every blob and verify its sha256")

    sub.add_parser("list", help="list evidence records (metadata only)")

    s = sub.add_parser("show", help="decrypt one record to stdout (audited)")
    s.add_argument("evidence_id")
    s.add_argument("--reason", required=True)

    s = sub.add_parser("delete", help="delete one record's content, keeping a tombstone (audited)")
    s.add_argument("evidence_id")
    s.add_argument("--reason", required=True)

    sub.add_parser("purge", help="delete everything past its retention period (audited)")
    sub.add_parser("audit", help="print the audit log")

    args = p.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    data: Path = args.data

    if args.cmd == "init":
        init_data_dir(data)
        print(f"initialised {data}")
        return 0

    store = Store(data)
    if args.cmd == "add-sensor":
        _write_key(args.key_out, store.add_sensor(args.sensor_id, actor=args.actor))
        print(f"sensor {args.sensor_id} added; key written to {args.key_out}")
    elif args.cmd == "replace-sensor-key":
        _write_key(args.key_out, store.replace_sensor_key(args.sensor_id, actor=args.actor, reason=args.reason))
        print(f"sensor {args.sensor_id} has a new key in {args.key_out}; the old key no longer works")
    elif args.cmd == "revoke-sensor":
        store.revoke_sensor(args.sensor_id, actor=args.actor, reason=args.reason)
        print(f"sensor {args.sensor_id} revoked; its uploads are refused from now on")
    elif args.cmd == "sensors":
        for s in store.sensors():
            print(
                f"{s['sensor_id']:<20} {s['status']:<8} registered {s['registered_at']}"
                f"  last seen {s['last_seen_at'] or 'never'}"
                + (f" from {s['last_ip']}" if s["last_ip"] else "")
                + (f"  key replaced {s['key_replaced_at']}" if s["key_replaced_at"] else "")
                + (f"  revoked {s['revoked_at']}" if s["revoked_at"] else "")
            )
    elif args.cmd == "rotate-key":
        key_id = store.rotate_key(actor=args.actor)
        print(f"active evidence key is now {key_id}")
        if store.running_collector() is None:
            print("no collector is running; it will use the new key when it starts")
            return 0
        deadline = time.monotonic() + args.wait
        while time.monotonic() < deadline:
            state = store.running_collector()
            if state and state["encrypting_key_id"] == key_id:
                print(f"running collector (pid {state['pid']}) confirmed it is encrypting with {key_id}")
                return 0
            time.sleep(0.5)
        print(f"WARNING: the running collector has not confirmed {key_id}; restart it and run key-status", file=sys.stderr)
        return 1
    elif args.cmd == "key-status":
        state = store.running_collector()
        active = store.refresh_keyring().active
        print(f"active key in keyring: {active}")
        if state is None:
            print(f"no collector has reported in the last {HEARTBEAT_STALE_SECONDS}s")
            return 0
        print(f"running collector (pid {state['pid']}) encrypting with: {state['encrypting_key_id']}")
        return 0 if state["encrypting_key_id"] == active else 1
    elif args.cmd == "serve":
        tls = None
        if args.tls_cert or args.tls_key:
            if not (args.tls_cert and args.tls_key):
                p.error("--tls-cert and --tls-key go together")
            tls = tls_context(args.tls_cert, args.tls_key)
        elif args.host not in ("127.0.0.1", "::1", "localhost"):
            p.error("serving without TLS is only allowed on loopback")
        report = store.reconcile()
        if not report.healthy:
            log.error("evidence store is not healthy: %d records are missing their bytes; run check", len(report.missing))
        for name, items in (("temp files removed", report.temp_files_removed), ("orphans quarantined", report.orphans_quarantined),
                            ("deletions completed", report.deletions_completed)):
            if items:
                log.warning("startup reconcile: %s: %d", name, len(items))

        def beat() -> None:
            while True:
                try:
                    store.heartbeat()
                except Exception:  # noqa: BLE001
                    log.exception("heartbeat failed")
                time.sleep(HEARTBEAT_SECONDS)

        store.heartbeat()
        threading.Thread(target=beat, daemon=True).start()
        server = CollectorServer((args.host, args.port), store, tls)
        log.info("listening on %s://%s:%d", "https" if tls else "http", args.host, args.port)
        server.serve_forever()
    elif args.cmd == "check":
        report = store.reconcile(deep=args.deep)
        _print_report(report)
        return 0 if report.healthy else 1
    elif args.cmd == "list":
        for r in store.list(include_deleted=True):
            flag = "sensitive" if r["sensitive"] else "-"
            gone = f" deleted {r['deleted_at']}" if r["deleted_at"] else ""
            issue = f"  !! {r['issue'].upper()}" if r["issue"] else ""
            print(f"{r['evidence_id']}  {r['kind']:<12} {flag:<9} {r['size_bytes']:>9}  {r['sensor_id']}  {r['received_at']}{gone}{issue}")
    elif args.cmd == "show":
        sys.stdout.buffer.write(store.read(args.evidence_id, actor=args.actor, reason=args.reason))
    elif args.cmd == "delete":
        store.delete(args.evidence_id, actor=args.actor, reason=args.reason)
    elif args.cmd == "purge":
        print(f"deleted {len(store.purge())} records")
    elif args.cmd == "audit":
        for r in store.audit_log():
            print(f"{r['at']}  {r['actor']:<12} {r['action']:<20} {r['evidence_id'] or '-'}  {r['reason']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
