"""``bearjug-collector``: set up, run and administer a collector data directory."""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

from .keys import EVIDENCE_KEYS, EvidenceKeyring, add_sensor
from .server import CollectorServer, tls_context
from .store import Store, init_data_dir


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="bearjug-collector")
    p.add_argument("--data", type=Path, required=True, help="collector data directory")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init", help="create the data directory, config and evidence key")

    s = sub.add_parser("add-sensor", help="register a sensor and write its shipper key")
    s.add_argument("sensor_id")
    s.add_argument("--key-out", type=Path, required=True, help="file to write the sensor's key to (give it to the shipper)")

    sub.add_parser("rotate-key", help="start encrypting new evidence under a new key")

    s = sub.add_parser("serve", help="run the ingestion endpoint")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8443)
    s.add_argument("--tls-cert", type=Path)
    s.add_argument("--tls-key", type=Path)

    sub.add_parser("list", help="list evidence records (metadata only)")

    s = sub.add_parser("show", help="decrypt one record to stdout (audited)")
    s.add_argument("evidence_id")
    s.add_argument("--actor", required=True)
    s.add_argument("--reason", required=True)

    s = sub.add_parser("delete", help="delete one record's content, keeping a tombstone (audited)")
    s.add_argument("evidence_id")
    s.add_argument("--actor", required=True)
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
    if args.cmd == "add-sensor":
        key = add_sensor(data / "sensors.json", args.sensor_id)
        fd = os.open(args.key_out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(key.hex() + "\n")
        print(f"sensor {args.sensor_id} added; key written to {args.key_out}")
        return 0
    if args.cmd == "rotate-key":
        print(EvidenceKeyring.load(data / EVIDENCE_KEYS).rotate())
        return 0

    store = Store(data)
    if args.cmd == "serve":
        tls = None
        if args.tls_cert or args.tls_key:
            if not (args.tls_cert and args.tls_key):
                p.error("--tls-cert and --tls-key go together")
            tls = tls_context(args.tls_cert, args.tls_key)
        elif args.host not in ("127.0.0.1", "::1", "localhost"):
            p.error("serving without TLS is only allowed on loopback")
        server = CollectorServer((args.host, args.port), store, tls)
        logging.getLogger("bearjug.collector").info(
            "listening on %s://%s:%d", "https" if tls else "http", args.host, args.port
        )
        server.serve_forever()
    elif args.cmd == "list":
        for r in store.list(include_deleted=True):
            flag = "sensitive" if r["sensitive"] else "-"
            gone = f" deleted {r['deleted_at']}" if r["deleted_at"] else ""
            print(f"{r['evidence_id']}  {r['kind']:<12} {flag:<9} {r['size_bytes']:>9}  {r['sensor_id']}  {r['received_at']}{gone}")
    elif args.cmd == "show":
        sys.stdout.buffer.write(store.read(args.evidence_id, actor=args.actor, reason=args.reason))
    elif args.cmd == "delete":
        store.delete(args.evidence_id, actor=args.actor, reason=args.reason)
    elif args.cmd == "purge":
        print(f"deleted {len(store.purge())} records")
    elif args.cmd == "audit":
        for r in store.audit_log():
            print(f"{r['at']}  {r['actor']:<12} {r['action']:<12} {r['evidence_id'] or '-'}  {r['reason']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
