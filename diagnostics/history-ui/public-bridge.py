"""Forward only two fixed HTTPS origins from the isolated guest to the runner uplink."""
from pathlib import Path
import select
import socket
import subprocess
import threading

UPLINK = next(line.split(":", 1)[1].strip() for line in
              subprocess.check_output(["/sbin/route", "-n", "get", "default"], text=True).splitlines()
              if "interface:" in line)
INDEX = socket.if_nametoindex(UPLINK)


def copy(client, target):
    with client, socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.IPPROTO_IP, 25, INDEX)  # Darwin IP_BOUND_IF
        server.settimeout(10)
        server.connect(target)
        server.settimeout(None)
        readers = [client, server]
        while readers:
            ready, _, _ = select.select(readers, [], [], 45)
            if not ready:
                return
            for src in ready:
                dst = server if src is client else client
                data = src.recv(65536)
                if data:
                    dst.sendall(data)
                else:
                    readers.remove(src)
                    dst.shutdown(socket.SHUT_WR)


def listen(port, host):
    target = socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)[0][4]
    with Path("/tmp/relay-history-app/bridge-targets").open("a") as targets:
        print(host, target[0], file=targets)
    sock = socket.socket()
    sock.bind(("127.0.0.1", port))
    sock.listen()
    def forward(client):
        try:
            copy(client, target)
        except OSError as exc:
            print("Bridge", host, type(exc).__name__, str(exc), flush=True)
    def accept():
        while True:
            threading.Thread(target=forward, args=(sock.accept()[0],), daemon=True).start()
    threading.Thread(target=accept, daemon=True).start()


listen(18481, "www.google.com")
listen(18482, "github.com")
print("Both fixed HTTPS forwards are ready", flush=True)
threading.Event().wait()
