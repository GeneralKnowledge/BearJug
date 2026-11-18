"""The "external machine": an SSH client run inside the client network
namespace (``ip netns exec``), so its traffic reaches the sensor the way an
attacker's does. Reads one JSON request on argv[1], prints one JSON reply.

Requests:
  {"action": "login", ...}            -> {"ok": bool}
  {"action": "shell", "commands": [...]} -> {"results": [{"command", "output", "rc", "seconds"}]}
  {"action": "forward", "dst": [host, port]} -> {"direct_tcpip": str, "remote_forward": str}
"""

import json
import re
import sys
import time

import paramiko

ANSI = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]")


def connect(req):
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(
        req["host"], req["port"], username=req["user"], password=req["password"],
        look_for_keys=False, allow_agent=False, timeout=15, banner_timeout=15, auth_timeout=15,
    )
    return c


class Shell:
    def __init__(self, client):
        self.ch = client.invoke_shell(width=200)
        self.buf = ""
        self.until(re.compile(r"\$ $"), 15)

    def until(self, rx, timeout):
        end = time.time() + timeout
        while time.time() < end:
            while self.ch.recv_ready():
                self.buf += self.ch.recv(65536).decode(errors="replace")
            m = rx.search(self.buf)
            if m:
                out, self.buf = self.buf[: m.end()], self.buf[m.end():]
                return out, m
            if self.ch.closed:
                break
            time.sleep(0.05)
        raise TimeoutError(self.buf[-2000:])

    def run(self, command, timeout):
        self.ch.send(command + "; echo __RC=$?__\n")
        out, m = self.until(re.compile(r"__RC=(\d+)__[^\n]*\n[^\n]*\$ "), timeout)
        return ANSI.sub("", out), int(m.group(1))


def main():
    req = json.loads(sys.argv[1])
    action = req["action"]
    if action == "login":
        try:
            connect(req).close()
            print(json.dumps({"ok": True}))
        except paramiko.AuthenticationException:
            print(json.dumps({"ok": False}))
        return
    client = connect(req)
    if action == "shell":
        shell, results = Shell(client), []
        for command in req["commands"]:
            t = time.time()
            output, rc = shell.run(command, req.get("timeout", 60))
            results.append({"command": command, "output": output, "rc": rc, "seconds": round(time.time() - t, 2)})
        print(json.dumps({"results": results}))
    elif action == "forward":
        t = client.get_transport()
        reply = {}
        try:
            t.open_channel("direct-tcpip", tuple(req["dst"]), ("127.0.0.1", 40000), timeout=10)
            reply["direct_tcpip"] = "opened"
        except Exception as e:  # noqa: BLE001
            reply["direct_tcpip"] = f"refused: {e}"
        try:
            port = t.request_port_forward("0.0.0.0", req.get("remote_port", 8080))
            reply["remote_forward"] = f"opened on {port}"
        except Exception as e:  # noqa: BLE001
            reply["remote_forward"] = f"refused: {e}"
        print(json.dumps(reply))
    client.close()


if __name__ == "__main__":
    main()
