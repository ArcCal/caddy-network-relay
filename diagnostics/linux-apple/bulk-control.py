"""Compare an independent production macOS QUIC client on the same guest and TLS origin."""

import base64
import concurrent.futures
import contextlib
import hashlib
import http.client
import json
import os
from pathlib import Path
import plistlib
import signal
import socket
import ssl
import struct
import sys
import subprocess
import tempfile
import time


def cpu_seconds():
    pidfile = Path(os.environ.get("RUNNER_TEMP", "/tmp")) / "guest.pid"
    if not pidfile.is_file():
        return None
    stamp = subprocess.check_output(["ps", "-p", pidfile.read_text().strip(), "-o", "time="], text=True).strip()
    if "-" in stamp:
        days, stamp = stamp.split("-", 1)
    else:
        days = 0
    total = float(days) * 86400
    for exponent, item in enumerate(reversed(stamp.split(":"))):
        total += float(item) * 60 ** exponent
    return total


def receive(conn, size):
    data = bytearray()
    while len(data) < size:
        part = conn.recv(size - len(data))
        if not part:
            raise EOFError("short SOCKS response")
        data.extend(part)
    return data


def open_origin(port, size, trust, expected):
    with socket.create_connection(("127.0.0.1", port or 18443), timeout=30) as conn:
        if port:
            conn.sendall(bytes([5, 1, 0]))
            if receive(conn, 2) != bytes([5, 0]):
                raise RuntimeError("SOCKS negotiation failed")
            conn.sendall(bytes([5, 1, 0, 1, 127, 0, 0, 1]) + struct.pack("!H", 18444))
            version, reply, _, family = receive(conn, 4)
            if version != 5 or reply != 0:
                raise RuntimeError("SOCKS CONNECT failed")
            length = {1: 4, 4: 16}.get(family)
            if family == 3:
                length = receive(conn, 1)[0]
            if not length:
                raise ValueError("Unknown SOCKS address type")
            receive(conn, length + 2)
        with trust.wrap_socket(conn, server_hostname="relay.test") as secure:
            secure.settimeout(180)
            started = time.monotonic()
            secure.sendall(f"GET /{size} HTTP/1.1\r\nHost: relay.test\r\nConnection: close\r\n\r\n".encode())
            with http.client.HTTPResponse(secure) as response:
                response.begin()
                if response.status != 200 or response.getheader("Content-Length") != str(size):
                    raise ValueError("Unexpected response status or length")
                digest = hashlib.sha256()
                total = 0
                first, error = None, None
                marks = {}
                try:
                    while total < size:
                        elapsed = time.monotonic() - started
                        if elapsed >= 360:
                            raise TimeoutError("transfer deadline")
                        secure.settimeout(min(45, 360 - elapsed))
                        chunk = response.read(64 * 1024)
                        if not chunk:
                            error = "short_body"
                            break
                        total += len(chunk)
                        digest.update(chunk)
                        elapsed = time.monotonic() - started
                        if first is None:
                            first = elapsed
                        for mark in (60, 120, 180, 240, 300):
                            if mark not in marks and elapsed >= mark:
                                marks[mark] = total
                except (OSError, http.client.HTTPException) as exc:
                    error = type(exc).__name__
                valid = total == size and digest.hexdigest() == expected
                return {"ok": valid, "bytes": total, "first_64k_seconds": first, "elapsed": time.monotonic() - started,
                        "bytes_at_checkpoint": marks, "error": error}



@contextlib.contextmanager
def proxy(client, private, ca, fetch, kind, mode):
    if mode == "direct":
        yield None
        return
    profile = plistlib.loads(fetch(kind + ".mobileconfig"))
    relay = next(item for item in profile["PayloadContent"] if item["PayloadType"] == "com.apple.relay.managed")
    header = next(value for key, value in relay["Relays"][0]["AdditionalHTTPHeaderFields"].items()
                  if key.lower() in ("authorization", "proxy-authorization"))
    username, password = base64.b64decode(header.split()[1]).decode().split(":", 1)
    relay_port = {"rust": 14200, "caddy": 14201}[kind]
    with socket.socket() as test_socket:
        test_socket.bind(("127.0.0.1", 0))
        port = test_socket.getsockname()[1]
    config = private / "control.toml"
    config.write_text(f'uri_template = "https://127.0.0.1:{relay_port}/.well-known/masque/udp/{{target_host}}/{{target_port}}/"\n'
                      f'username = {json.dumps(username)}\npassword = {json.dumps(password)}\n'
                      f'server_name = "ingress.relay.test"\ntransport = "{mode}"\n'
                      f'mode = "socks"\nprobe_target = "127.0.0.1:18553"\n[socks]\nlisten = ["127.0.0.1:{port}"]\n')
    with subprocess.Popen([client, "--config", config, "--ca-file", ca, "--duration", "410"],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) as proc:
        try:
            limit = time.monotonic() + 35
            while time.monotonic() < limit and proc.poll() is None:
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=1):
                        break
                except OSError:
                    time.sleep(.1)
            else:
                raise RuntimeError("RS did not open the local listener")
            yield port
        finally:
            if proc.poll() is None:
                proc.send_signal(signal.SIGINT)
            try:
                proc.wait(timeout=12)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()


def run(client, fetch, kind, mode, size):
    block = bytes(range(256)) * 256
    expected = hashlib.sha256()
    for _ in range(size // len(block)):
        expected.update(block)
    expected.update(block[:size % len(block)])
    with tempfile.TemporaryDirectory() as name:
        private = Path(name)
        ca = private / "fixture.pem"
        ca.write_text(ssl.DER_cert_to_PEM_cert(fetch("ca.der")))
        trust = ssl.create_default_context(cafile=str(ca))
        if mode != "direct" and sys.platform == "darwin":
            with socket.socket() as local:
                if local.connect_ex(("127.0.0.1", 18444)) == 0:
                    raise RuntimeError("The guest-only TLS origin is reachable directly from the Mac")
        before = json.loads(fetch("counts"))
        with proxy(client, private, ca, fetch, kind, mode) as port:
            cpu = cpu_seconds()
            started = time.monotonic()
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as workers:
                jobs = [workers.submit(open_origin, port, size, trust, expected.hexdigest()) for _ in range(4)]
                samples = [job.result() for job in jobs]
            elapsed = time.monotonic() - started
            cpu = None if cpu is None else cpu_seconds() - cpu
        after = json.loads(fetch("counts"))
        delivered = after.get("download", 0) - before.get("download", 0)
        route = after.get(kind + "_tcp", 0) - before.get(kind + "_tcp", 0)
        private_hits = after.get("private_download", 0) - before.get("private_download", 0)
        return {"kind": kind, "mode": mode, "ok": all(row["ok"] for row in samples) and delivered == 4 and private_hits == (0 if mode == "direct" else 4),
                "guest_only_origin_count": private_hits,
                "origin_count": delivered, "relay_log_count": route, "elapsed": elapsed, "samples": samples,
                "guest_host_cpu_seconds": cpu}
