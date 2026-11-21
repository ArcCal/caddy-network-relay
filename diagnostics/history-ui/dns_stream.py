"""Verify fresh and persistent DNS-over-TCP and DNS-over-TLS connections."""
import contextlib
import ipaddress
import os
import secrets
import socket
import socketserver
import ssl
import struct
import threading
import time


def exact(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise EOFError("DNS stream ended before a complete frame")
        data.extend(chunk)
    return bytes(data)


def frame(sock):
    return exact(sock, int.from_bytes(exact(sock, 2), "big"))


def send_frame(sock, data):
    sock.sendall(len(data).to_bytes(2, "big") + data)


def listen(host, port, tls, answer, record):
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            secure = tls.wrap_socket(self.request, server_side=True) if tls else contextlib.nullcontext(self.request)
            with secure as stream:
                stream.settimeout(12)
                while True:
                    try:
                        request = frame(stream)
                    except EOFError:
                        return
                    response = answer(request)
                    if not response:
                        return
                    if request[13:].startswith(b"slow-"):
                        time.sleep(2.25)
                    send_frame(stream, response)
                    record("dns_tls" if tls else "dns_tcp")

    server = socketserver.ThreadingTCPServer((host, port), Handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def connect(target, port, proxy):
    sock = socket.create_connection(proxy or (target, port), timeout=10)
    if proxy:
        try:
            sock.sendall(b"\x05\x01\x00")
            assert exact(sock, 2) == b"\x05\x00"
            sock.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(target) + struct.pack("!H", port))
            version, status, reserved, kind = exact(sock, 4)
            assert (version, status, reserved) == (5, 0, 0)
            size = {1: 4, 4: 16}.get(kind)
            if size is None:
                assert kind == 3
                size = exact(sock, 1)[0]
            exact(sock, size + 2)
        except BaseException:
            sock.close()
            raise
    return sock


def exercise(target, port, tls, proxy, delayed):
    with connect(target, port, proxy) as raw:
        stream = tls.wrap_socket(raw, server_hostname="relay.test") if tls else contextlib.nullcontext(raw)
        with stream as conn:
            for slow in (False, delayed):
                label = (("slow-" if slow else "fast-") + secrets.token_hex(6)).encode()
                question = bytes([len(label)]) + label + b"\x0bdns-fixture\x04test\x00\x00\x01\x00\x01"
                txid = secrets.token_bytes(2)
                packet = txid + struct.pack("!5H", 0x0100, 1, 0, 0, 0) + question
                start = time.monotonic()
                send_frame(conn, packet)
                reply = frame(conn)
                assert reply[:12] == txid + struct.pack("!5H", 0x8180, 1, 1, 0, 0)
                assert reply[12:] == question + b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 120, 4) + ipaddress.ip_address("198.51.100.42").packed
                if slow:
                    elapsed = time.monotonic() - start
                    assert elapsed >= 2.20, elapsed
                    print("Delayed DoT answer verified on a reused connection", round(elapsed, 3), flush=True)


if __name__ == "__main__":
    ca = ssl.create_default_context(cafile="/tmp/relay-history-app/ca.pem")
    for proxy in (None, ("127.0.0.1", 1080)):
        for target in ("1.1.1.1", "1.0.0.1"):
            for port, tls in ((53, None), (853, ca)):
                for connection in range(2):
                    exercise(target, port, tls, proxy, delayed=bool(tls and target == "1.1.1.1" and connection == 0))
                print(os.environ.get("RELAY_UI_TRANSPORT"), "SOCKS" if proxy else "TUN", target, port,
                      "four unique DNS questions answered on two connections", flush=True)
