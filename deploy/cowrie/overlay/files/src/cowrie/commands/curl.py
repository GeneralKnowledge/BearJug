# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Reuben Dennison
"""BearJug: simulated curl. Replaces Cowrie's curl, which fetches for real.

Records each URL and fails the way curl does on a host with no DNS and no
route out. Never opens a socket and never writes a file."""

from __future__ import annotations

import getopt

from cowrie.commands._bearjug_outbound import SimulatedOutboundCommand, parse_url

commands = {}

VERSION = """curl 8.5.0 (x86_64-pc-linux-gnu) libcurl/8.5.0 OpenSSL/3.0.13 zlib/1.3 brotli/1.1.0 zstd/1.5.5 libidn2/2.3.7 libpsl/0.21.2 (+libidn2/2.3.7) libssh/0.10.6/openssl/zlib nghttp2/1.59.0 librtmp/2.3 OpenLDAP/2.6.7
Release-Date: 2023-12-06, security patched: 8.5.0-2ubuntu10.6
Protocols: dict file ftp ftps gopher gophers http https imap imaps ldap ldaps mqtt pop3 pop3s rtmp rtsp scp sftp smb smbs smtp smtps telnet tftp
Features: alt-svc AsynchDNS brotli GSS-API HSTS HTTP2 HTTPS-proxy IDN IPv6 Kerberos Largefile libz NTLM PSL SPNEGO SSL threadsafe TLS-SRP UnixSockets zstd
"""

USAGE = """Usage: curl [options...] <url>
 -d, --data <data>           HTTP POST data
 -f, --fail                  Fail fast with no output on HTTP errors
 -h, --help <category>       Get help for commands
 -i, --include               Include response headers in output
 -o, --output <file>         Write to file instead of stdout
 -O, --remote-name           Write output to file named as remote file
 -s, --silent                Silent mode
 -T, --upload-file <file>    Transfer local FILE to destination
 -u, --user <user:password>  Server user and password
 -A, --user-agent <name>     Send User-Agent <name> to server
 -v, --verbose               Make the operation more talkative
 -V, --version               Show version number and quit

This is not the full help, this menu is stripped into categories.
Use "--help category" to get an overview of all categories.
For all options use the manual or "--help all".
"""

SHORT = "VhsSfLkIiOvqd:o:u:A:H:X:T:e:x:m:F:b:c:w:K:"
LONG = [
    "version", "help", "silent", "show-error", "fail", "location", "insecure", "head", "include",
    "remote-name", "verbose", "data=", "data-binary=", "data-raw=", "output=", "user=", "user-agent=",
    "header=", "request=", "upload-file=", "referer=", "proxy=", "max-time=", "connect-timeout=",
    "form=", "cookie=", "cookie-jar=", "write-out=", "config=", "retry=", "compressed", "url=",
    "noproxy=", "ipv4", "ipv6", "create-dirs", "fail-with-body", "http1.1", "http2", "tlsv1.2",
]


class Command_curl(SimulatedOutboundCommand):
    tool = "curl"

    def start(self) -> None:
        try:
            opts, urls = getopt.gnu_getopt(self.args, SHORT, LONG)
        except getopt.GetoptError as e:
            self.errorWrite(f"curl: option {e.opt}: is unknown\ncurl: try 'curl --help' or 'curl --manual' for more information\n")
            self.exit(2)
            return
        flags = {o for o, _ in opts}
        if "-V" in flags or "--version" in flags:
            self.write(VERSION)
            self.exit(0)
            return
        if "-h" in flags or "--help" in flags:
            self.write(USAGE)
            self.exit(0)
            return
        urls = urls + [v for o, v in opts if o == "--url"]
        if not urls:
            self.errorWrite("curl: try 'curl --help' or 'curl --manual' for more information\n")
            self.exit(2)
            return
        silent = ("-s" in flags or "--silent" in flags) and not ("-S" in flags or "--show-error" in flags)
        user = next((v for o, v in opts if o in ("-u", "--user")), None)
        password = user.split(":", 1)[1] if user and ":" in user else None

        error, delay, code = "", 0.0, 0
        for raw in urls:
            u = parse_url(raw)
            outcome = self.outcome_for(u["host"])
            self.record(host=u["host"], port=u["port"], url=u["url"], outcome=outcome, password=u["password"] or password)
            step = self.delay_for(outcome)
            delay += step
            if outcome == "bad_address":
                code, line = 3, "curl: (3) URL rejected: No host part in the URL\n"
            elif outcome == "resolve_failed":
                code, line = 6, f"curl: (6) Could not resolve host: {u['host']}\n"
            else:
                code = 28
                line = f"curl: (28) Failed to connect to {u['host']} port {u['port']} after {int(step * 1000)} ms: Couldn't connect to server\n"
            if not silent:
                error += line
        self.finish_later(delay, "", error, code)


commands["/usr/bin/curl"] = Command_curl
commands["curl"] = Command_curl
