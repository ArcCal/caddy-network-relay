"""Isolated Linux origin and two real Relay servers. Only loopback ports are published by QEMU."""
import collections
import hashlib
import http.server
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import tempfile
import time
import threading

ROOT = Path(tempfile.mkdtemp(prefix="relay-guest-"))
os.chmod(ROOT, 0o700)
BIND = os.environ.get("FIXTURE_BIND", "127.0.0.1")
RUST = os.environ.get("RUST_RELAY", "/srv/network-relay")
CADDY = os.environ.get("CADDY_RELAY", "/srv/caddy")
CANDIDATE = os.environ.get("CADDY_CANDIDATE", "/srv/caddy-candidate")
BLOCK = bytes(range(256)) * 256
COUNTS = collections.Counter()
LOCK = threading.Lock()
BULK_WRITES = {}
PIDS = {}


def count(kind):
    with LOCK:
        COUNTS[kind] += 1


def command(*args, password=None):
    return subprocess.run(args, cwd=ROOT, text=True, input=password, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, check=True, timeout=30).stdout


def credentials():
    command("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
            "-nodes", "-keyout", "ca.key", "-out", "ca.pem", "-days", "1", "-subj", "/CN=Local Relay Fixture",
            "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    command("openssl", "req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
            "-keyout", "key.pem", "-out", "cert.csr", "-subj", "/CN=relay.test")
    (ROOT / "extensions").write_text("subjectAltName=DNS:relay.test,DNS:ingress.relay.test,IP:10.0.2.15,IP:127.0.0.1,IP:::1\nextendedKeyUsage=serverAuth\n"
                                     "basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\n")
    command("openssl", "x509", "-req", "-in", "cert.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
            "-out", "cert.pem", "-days", "1", "-extfile", "extensions")
    command("openssl", "x509", "-in", "ca.pem", "-outform", "DER", "-out", "ca.der")
    return secrets.token_urlsafe(32) + "\n"


def start_servers(secret):
    jobs = []
    for name, binary, port in (("rust", RUST, 14200), ("caddy", CADDY, 14201), ("candidate", CANDIDATE, 14202), ("nogso", CADDY, 14203)):
        cli = [binary] + (["network-relay"] if name != "rust" else [])
        account = command(*cli, "passwd", "--name", "alice", "--stdin", "--fast-hash", password=secret)
        if name == "rust":
            (ROOT / "relay.toml").write_text(f'listen = "{BIND}:{port}"\n[tls]\ncert = "{ROOT}/cert.pem"\n'
                f'key = "{ROOT}/key.pem"\n[relay]\nblocked_destinations = []\nblock_own_addresses = false\n'
                'max_tunnels = 128\nmax_connections = 128\n[debug]\nlog_requests = true\n' + account)
            args = [binary, "serve", "--config", str(ROOT / "relay.toml")]
        else:
            handler = {"handler": "network_relay", "relay_id": "linux-fixture", "log_requests": True,
                       "users": [{"name": "alice", "password_hash": account.strip().split()[2]}],
                       "blocked_destinations": [], "blocked_ports": []}
            cfg = {"logging": {"logs": {"default": {"level": "DEBUG"}}}, "admin": {"disabled": True}, "storage": {"module": "file_system", "root": str(ROOT/(name+"-storage"))},
                   "apps": {"http": {"servers": {"relay": {"listen": [f"{BIND}:{port}"],
                   "automatic_https": {"disable": True}, "tls_connection_policies": [{}],
                   "routes": [{"handle": [handler, {"handler":"static_response","status_code":404}]}]}}},
                   "tls": {"certificates": {"load_files": [{"certificate": str(ROOT/"cert.pem"),"key":str(ROOT/"key.pem")}]}}}}
            (ROOT / (name + ".json")).write_text(json.dumps(cfg))
            args = [binary, "run", "--config", str(ROOT / (name + ".json"))]
        profile = ROOT / (name + ".mobileconfig")
        command(*cli, "profile", "--host", "ingress.relay.test", "--port", str(port), "--user", "alice", "--out", str(profile),
                *(["--password-stdin"] if name != "rust" else []), password=secret)
        log = (ROOT / (name + ".log")).open("wb")
        trace = ROOT / ("trace-" + name); trace.mkdir()
        env = dict(os.environ, RELAY_STUDY_NUMERIC=str(trace))
        if name == "nogso": env["QUIC_GO_DISABLE_GSO"] = "true"
        child = subprocess.Popen(args, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
        PIDS[name] = child.pid
        jobs.append(child)
    return jobs


class Origin(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def reply(self, size, upload=None):
        self.send_response(200)
        self.send_header("Content-Length", str(size))
        self.send_header("Cache-Control", "no-store")
        if upload:
            self.send_header("X-Upload-Bytes", str(upload[0]))
            self.send_header("X-Upload-SHA256", upload[1])
        self.end_headers()
        transfer = None
        if size == 64 * 1024 * 1024:
            with LOCK:
                transfer = len(BULK_WRITES) + 1
                BULK_WRITES[transfer] = 0
        written = 0
        while size:
            chunk = min(size, len(BLOCK))
            self.wfile.write(BLOCK[:chunk])
            size -= chunk
            written += chunk
            if transfer is not None and written % (1024 * 1024) == 0:
                with LOCK:
                    BULK_WRITES[transfer] = written

    def do_GET(self):
        if self.path not in ("/4096", "/1048576", "/8388608", "/67108864"):
            return self.send_error(404)
        count("download")
        self.reply(int(self.path[1:]))

    def do_POST(self):
        size = int(self.headers.get("Content-Length", "-1"))
        if size not in (4096, 1048576, 8388608):
            return self.send_error(400)
        digest = hashlib.sha256()
        remaining = size
        while remaining:
            chunk = min(remaining, len(BLOCK))
            if self.rfile.read(chunk) != BLOCK[:chunk]:
                return self.send_error(400)
            digest.update(BLOCK[:chunk])
            remaining -= chunk
        count("upload")
        self.reply(4096, (size, digest.hexdigest()))


def environment_record():
    data = {"system": os.uname().sysname, "machine": os.uname().machine, "kernel": os.uname().release}
    for name, program in (("rust", RUST), ("caddy", CADDY), ("candidate", CANDIDATE)):
        digest = hashlib.sha256()
        with open(program, "rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
        data[name] = digest.hexdigest()
    return json.dumps(data).encode()


class Metadata(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.path == "/environment":
            body = self.server.environment_record
        elif self.path == "/progress":
            with LOCK:
                progress = dict(BULK_WRITES)
            latest = {}
            for path in ROOT.glob("trace-*/stream-*.jsonl"):
                with path.open("rb") as f:
                    f.seek(max(0, f.seek(0,2) - 4096)); lines=f.read().splitlines()
                for line in reversed(lines):
                    try: record=json.loads(line)
                    except (ValueError, UnicodeError): continue
                    latest[path.parent.name + "/" + path.name] = record; break
            cpu = {}
            for name,pid in PIDS.items():
                stat=Path(f"/proc/{pid}/stat").read_text().rsplit(")",1)[1].split()
                cpu[name]=(int(stat[11])+int(stat[12]))/os.sysconf("SC_CLK_TCK")
            body=json.dumps({"writes":progress,"streams":latest,"cpu":cpu}).encode()
        elif self.path == "/counts":
            with LOCK:
                data = dict(COUNTS)
            for name in ("rust", "caddy", "candidate", "nogso"):
                log = (ROOT / (name + ".log")).read_bytes().lower()
                data[name + "_udp"] = log.count(b"connect-udp")
                data[name + "_tcp"] = log.count(b"connect")
                data[name + "_auth"] = log.count(b"authentication failed")
            for server in ("caddy", "candidate"):
                data[server + "_limits"] = []
                for field in ("closed_udp", "closed_up", "closed_down", "budget_drops"):
                    data[server + "_" + field] = 0
                for line in (ROOT / (server + ".log")).read_bytes().splitlines():
                    if line.startswith(b"fixture_datagram_limit "):
                        fields = line.split()[1:]
                        if len(fields) == 4 and all(f.isdigit() for f in fields):
                            data[server + "_limits"].append([int(f) for f in fields])
                        continue
                    try:
                        event = json.loads(line)
                    except (ValueError, UnicodeError):
                        continue
                    if event.get("msg") == "tunnel closed" and event.get("kind") == "udp":
                        data[server + "_closed_udp"] += 1
                        data[server + "_closed_up"] += event.get("bytes_up", 0)
                        data[server + "_closed_down"] += event.get("bytes_down", 0)
                    if event.get("msg") == "UDP payloads dropped by per-user traffic budget":
                        data[server + "_budget_drops"] += event.get("dropped", 0)
            body = json.dumps(data).encode()
        elif self.path in ("/ca.der", "/rust.mobileconfig", "/caddy.mobileconfig", "/candidate.mobileconfig", "/nogso.mobileconfig"):
            body = (ROOT / self.path[1:]).read_bytes()
        else:
            return self.send_error(404)
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    assert os.uname().sysname == "Linux"
    os.umask(0o077)
    if BIND == "0.0.0.0":
        # Only loopback and the host forwarding gateway are reachable. There
        # is no default gateway, DNS egress or IPv6 route outside this fixture.
        addresses = json.loads(command("ip", "-j", "-4", "addr", "show"))
        iface = next(link["ifname"] for link in addresses
                     if any(a["local"] == "10.0.2.15" for a in link["addr_info"]))
        command("ip", "-4", "route", "replace", "10.0.2.2/32", "dev", iface, "scope", "link")
        command("ip", "-4", "route", "del", "10.0.2.0/24", "dev", iface)
        command("ip", "-4", "route", "replace", "prohibit", "default")
        if subprocess.run(["ip", "-4", "route", "get", "192.0.2.1"],
                          capture_output=True).returncode == 0:
            raise RuntimeError("Unexpected external guest route")
    identity = environment_record()
    jobs = start_servers(credentials())
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind((BIND, 18553))
    def echo():
        while True:
            data, addr = udp.recvfrom(65535)
            count("udp")
            udp.sendto(data, addr)
    threading.Thread(target=echo, daemon=True).start()
    origin = http.server.ThreadingHTTPServer((BIND, 18443), Origin)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(ROOT/"cert.pem", ROOT/"key.pem")
    origin.socket = tls.wrap_socket(origin.socket, server_side=True)
    threading.Thread(target=origin.serve_forever, daemon=True).start()
    for port in (14200, 14201, 14202, 14203):
        import time
        for attempt in range(200):
            if any(p.poll() is not None for p in jobs):
                raise RuntimeError("A Linux server exited during initialization")
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=.4):
                    break
            except OSError:
                time.sleep(.1)
        else:
            raise RuntimeError("A Linux server failed to listen")
    print("Linux Relay fixture ready", os.uname().machine, flush=True)
    server = http.server.ThreadingHTTPServer((BIND, 18080), Metadata)
    server.environment_record = identity
    server.serve_forever()


if __name__ == "__main__":
    main()
