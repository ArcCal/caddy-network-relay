"""Use the actual Mac product transports with two guest Linux servers."""
import concurrent.futures
import hashlib
import http.client
import base64
import shutil
import json
import os
import plistlib
import secrets
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.request import ProxyHandler, build_opener

direct = build_opener(ProxyHandler({}))
def fetch(path):
    with direct.open("http://127.0.0.1:18080/" + path, timeout=15) as h:
        return h.read()

def full(sock, n):
    data = bytearray()
    while len(data) < n:
        more = sock.recv(n-len(data))
        if not more:
            raise EOFError("early SOCKS EOF")
        data.extend(more)
    return bytes(data)

def socks(port, cmd, address, destination):
    conn = socket.create_connection(("127.0.0.1",port),timeout=15)
    try:
        conn.sendall(b"\x05\x01\x00")
        assert full(conn,2) == b"\x05\x00"
        conn.sendall(bytes((5,cmd,0)) + address + struct.pack("!H",destination))
        ver, result, _, kind = full(conn,4)
        if (ver,result) != (5,0):
            raise OSError(f"SOCKS result {ver}/{result}")
        if kind == 1:
            host = socket.inet_ntop(socket.AF_INET,full(conn,4))
        elif kind == 4:
            host = socket.inet_ntop(socket.AF_INET6,full(conn,16))
        else:
            host = full(conn,full(conn,1)[0]).decode()
        return conn,(host,struct.unpack("!H",full(conn,2))[0])
    except BaseException:
        conn.close()
        raise

def traffic(port, ctx):
    target=b"\x03\x09localhost"
    with socks(port,1,target,18443)[0] as raw, ctx.wrap_socket(raw,server_hostname="relay.test") as stream:
        stream.sendall(b"GET /4096 HTTP/1.1\r\nHost: relay.test\r\nConnection: close\r\n\r\n")
        with stream.makefile("rb") as f:
            assert b" 200 " in f.readline()
            while f.readline() not in (b"\r\n", b""):
                pass
            assert f.read() == bytes(range(256))*16
    ctl, peer=socks(port,3,b"\x01"+bytes(4),0)
    with ctl, socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as udp:
        udp.settimeout(10)
        udp.connect(("127.0.0.1" if peer[0]=="0.0.0.0" else peer[0],peer[1]))
        for size in (0,63,1200,8192):
            payload=secrets.token_bytes(size)
            udp.send(bytes(3)+b"\x01\x7f\x00\x00\x01"+struct.pack("!H",18553)+payload)
            reply=udp.recv(65535)
            assert reply[:3] == bytes(3)
            k=reply[3]; alen={1:4,4:16}.get(k,1+reply[4]); pos=4+alen
            assert struct.unpack("!H",reply[pos:pos+2])[0] == 18553 and reply[pos+2:] == payload

def bulk_requests(port, ctx, style, size):
    expected = hashlib.sha256(bytes(range(256))*(size//256)).digest()
    def connection():
        raw = socks(port,1,b"\x03\x09localhost",18443)[0]
        raw.settimeout(90)
        return ctx.wrap_socket(raw,server_hostname="relay.test")
    def request(stream, keep):
        stream.sendall(f'GET /{size} HTTP/1.1\r\nHost: relay.test\r\nConnection: {keep}\r\n\r\n'.encode("ascii"))
        response=http.client.HTTPResponse(stream)
        response.begin()
        assert response.status==200 and int(response.getheader("Content-Length"))==size
        received=0; digest=hashlib.sha256()
        with response:
            while block:=response.read(64*1024):
                digest.update(block); received+=len(block)
        if received!=size or digest.digest()!=expected: raise ValueError("Transfer digest or byte count")
    def separate(_):
        with connection() as stream: request(stream,"close")
    before=time.monotonic()
    if style=="reuse-inner":
        with connection() as stream:
            for i in range(4): request(stream,"close" if i==3 else "keep-alive")
    elif style=="fresh-inner":
        for i in range(4): separate(i)
    else:
        active={"concurrent-two":2,"concurrent-four":4}[style]
        with concurrent.futures.ThreadPoolExecutor(max_workers=active) as pool: list(pool.map(separate,range(4)))
    return {"style":style,"elapsed":time.monotonic()-before,"bytes_each":size,"hashes":4,"sha256":expected.hex()}

def case(product,server,relayport,mode,secret,ca,ctx,out):
    with tempfile.TemporaryDirectory() as private:
        root=Path(private)
        with socket.socket() as free:
            free.bind(("127.0.0.1",0)); port=free.getsockname()[1]
        stop=root/"stop"; report=root/"report.json"
        if product=="rs":
            settings=root/"client.toml"
            settings.write_text(f'uri_template = "https://127.0.0.1:{relayport}/.well-known/masque/udp/{{target_host}}/{{target_port}}/"\n'
              f'username = "alice"\npassword = {json.dumps(secret)}\nserver_name = "relay.test"\ntransport = "{mode}"\n'
              f'mode = "socks"\nprobe_target = "127.0.0.1:18553"\n[socks]\nlisten = ["127.0.0.1:{port}"]\n')
            args=[str(bins/product),"--config",str(settings),"--ca-file",str(ca),"--duration","500"]
        else:
            settings=root/"settings.json"
            settings.write_text(json.dumps(dict(serverPort=relayport,socksPort=port,probePort=18443,mode=mode,
                password=secret,seconds=500,stopFile=str(stop),reportFile=str(report),ownershipToken=secrets.token_hex(16))))
            args=[str(bins/product),str(settings)]
        with (root/"log").open("w") as log, subprocess.Popen(args,stdout=log,stderr=log) as child:
            try:
                until=time.monotonic()+35
                while time.monotonic()<until and child.poll() is None:
                    if product=="rs":
                        with socket.socket() as probe:
                            if probe.connect_ex(("127.0.0.1",port))==0:break
                    elif report.exists():
                        state=json.loads(report.read_text())["status"]
                        if state=="connected":break
                        if state.startswith("failed("):raise RuntimeError(state)
                    time.sleep(.2)
                else:
                    state=json.loads(report.read_text())["status"] if report.exists() else "no report"
                    raise RuntimeError(f"admission timeout or child exit {child.poll()}: {state}")
                before=json.loads(fetch("counts"))
                traffic(port,ctx)
                styles=["fresh-inner","reuse-inner","concurrent-two","concurrent-four"]
                if (product=="rs") ^ (mode=="h3"): styles.reverse()
                arms=[]
                for round in range(2):
                    for style in styles if round==0 else reversed(styles):
                        sample=bulk_requests(port,ctx,style,1048576)
                        sample["round"]=round
                        arms.append(sample)
                after=json.loads(fetch("counts"))
                udp=after.get("udp",0)-before.get("udp",0)
                downloads=after.get("download",0)-before.get("download",0)
                assert udp>=4 and downloads==33
                return {"ok":True,"origin_udp":udp,"origin_download":downloads,"bulk":arms}
            finally:
                if product=="rs": child.send_signal(2)
                else: stop.touch()
                try:child.wait(timeout=25)
                except subprocess.TimeoutExpired:
                    child.kill(); child.wait(); raise
                finally:
                    if product in ("nf","tun"):
                        folder=Path.home()/"Library/Application Support"/("NetworkRelayNF" if product=="nf" else "NetworkRelayTun")
                        marker=folder/"diagnostic-owner"
                        if marker.is_file() and marker.read_text()==json.loads(settings.read_text())["ownershipToken"]:
                            shutil.rmtree(folder)
                if child.returncode!=0:
                    raise RuntimeError(f"{product} exited {child.returncode}")
                if product!="rs":
                    final=json.loads(report.read_text()); assert final["finished"] and final["status"]=="stopped"

def system_certificates():
    result = subprocess.run(["security", "find-certificate", "-a", "-Z", "/Library/Keychains/System.keychain"],
                            capture_output=True, check=True, timeout=20)
    return sorted(line for line in result.stdout.splitlines() if line.startswith(b"SHA-256 hash:"))


if __name__=="__main__":
    os.umask(0o077)
    bins=Path(sys.argv[1]).resolve(); result=Path(sys.argv[2]); result.mkdir(exist_ok=True)
    rows=[]
    (result/"environment.json").write_bytes(fetch("environment"))
    with tempfile.TemporaryDirectory() as folder:
        ca=Path(folder)/"fixture.pem"; ca.write_text(ssl.DER_cert_to_PEM_cert(fetch("ca.der")))
        ctx=ssl.create_default_context(cafile=str(ca))
        der = Path(folder) / "fixture.der"
        der.write_bytes(fetch("ca.der"))
        os.environ["RELAY_FIXTURE_CA_DER"] = str(der)
        original_certificates = system_certificates()
        try:
            for kind,relayport in (("rust",14200),("caddy",14201)):
                cfg=plistlib.loads(fetch(kind+".mobileconfig"))
                h=next(p for p in cfg['PayloadContent'] if p.get('PayloadType')=='com.apple.relay.managed')['Relays'][0]['AdditionalHTTPHeaderFields']
                secret=base64.b64decode(next(v for k,v in h.items() if k.lower() in ('authorization','proxy-authorization')).split()[1]).decode().split(':',1)[1]
                for prod in ("nf","rs","tun"):
                    for mode in ("h2","h3"):
                        row={"server":kind,"product":prod,"transport":mode}
                        try: row.update(case(prod,kind,relayport,mode,secret,ca,ctx,result))
                        except Exception as err: row.update(ok=False,error=str(err).replace(secret,"<redacted>"))
                        rows.append(row);print(json.dumps(row),flush=True)
                        (result/"summary.json").write_text(json.dumps(rows,indent=2))
            # A valid but unrelated root must reject the same verified Linux
            # peer, with zero application data reaching either origin.
            wrong_pem = Path(folder) / "unrelated.pem"
            wrong_der = Path(folder) / "unrelated.der"
            subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                            "-nodes", "-subj", "/CN=Unrelated Fixture", "-days", "1", "-keyout",
                            str(Path(folder) / "unrelated.key"), "-out", str(wrong_pem)],
                           check=True, capture_output=True)
            subprocess.run(["openssl", "x509", "-in", str(wrong_pem), "-outform", "DER", "-out", str(wrong_der)],
                           check=True)
            os.environ["RELAY_FIXTURE_CA_DER"] = str(wrong_der)
            negatives = []
            for prod in ("nf", "rs", "tun"):
                positive = any(row["product"] == prod and row["server"] == "caddy" and
                               row["transport"] == "h2" and row["ok"] for row in rows)
                before = json.loads(fetch("counts"))
                rejected = False
                try:
                    case(prod, "caddy", 14201, "h2", secret, wrong_pem, ctx, result)
                except (OSError, RuntimeError):
                    rejected = True
                after = json.loads(fetch("counts"))
                unchanged = all(before.get(key, 0) == after.get(key, 0) for key in ("udp", "download"))
                negatives.append({"product": prod, "positive_control": positive,
                                  "rejected": rejected, "origin_unchanged": unchanged})
            (result / "negative-trust.json").write_text(json.dumps(negatives, indent=2))
            if not all(row["positive_control"] and row["rejected"] and row["origin_unchanged"] for row in negatives):
                raise RuntimeError("A Linux relay certificate negative control failed")
        finally:
            if system_certificates() != original_certificates:
                raise RuntimeError("The system keychain certificate list changed during the test")
            (result / "trust-cleanup.json").write_text(json.dumps(
                {"scope": "per-SecTrust private root; RS explicit CA", "system_certificates_unchanged": True}))
    sys.exit(any(not row['ok'] for row in rows))
