"""A test sink: listens on TCP and UDP ports and logs every connection or
datagram it receives, one JSON object per line. If the boundary holds,
nothing from the honeypot ever appears here."""

import json
import socket
import sys
import threading
import time

LOG = sys.argv[1]
TCP_PORTS = [int(p) for p in sys.argv[2].split(",")]
UDP_PORTS = [int(p) for p in sys.argv[3].split(",")]
lock = threading.Lock()


def log(**fields):
    with lock, open(LOG, "a") as f:
        f.write(json.dumps({"at": time.time(), **fields}) + "\n")


def tcp(port):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(64)
    while True:
        c, addr = s.accept()
        log(proto="tcp", port=port, src=addr[0])
        try:
            c.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: 18\r\n\r\n#!/bin/sh\necho pwn\n")
        finally:
            c.close()


def udp(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", port))
    while True:
        _, addr = s.recvfrom(65536)
        log(proto="udp", port=port, src=addr[0])


for p in TCP_PORTS:
    threading.Thread(target=tcp, args=(p,), daemon=True).start()
for p in UDP_PORTS:
    threading.Thread(target=udp, args=(p,), daemon=True).start()
log(proto="ready")
while True:
    time.sleep(3600)
