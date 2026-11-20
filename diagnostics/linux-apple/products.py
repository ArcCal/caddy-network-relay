"""Use the actual Mac product transports with two guest Linux servers."""
import base64
import capture
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
            args=[str(bins/product),"--config",str(settings),"--ca-file",str(ca),"--duration","55"]
        else:
            settings=root/"settings.json"
            settings.write_text(json.dumps(dict(serverPort=relayport,socksPort=port,probePort=18443,mode=mode,
                password=secret,seconds=55,stopFile=str(stop),reportFile=str(report),ownershipToken=secrets.token_hex(16))))
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
                status = capture.run(port)
                after = json.loads(fetch("counts"))
                expected = {"capture_tcp4": 1, "capture_tcp6": 1, "capture_udp4": 3,
                            "capture_udp6": 3, "capture_dns": 1}
                observed = {key: after.get(key, 0) - before.get(key, 0) for key in expected}
                if observed != expected:
                    raise RuntimeError("Linux capture origin counts differ: " + str(observed))
                return {"ok": True, **status, **observed}
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

def remove_anchor(ca, fingerprint):
    keychain="/Library/Keychains/System.keychain"
    parts=["sudo","security"]
    # Preserve other administrative trust entries on this disposable machine.
    current=ca.parent/"trust-current.plist"
    reduced=ca.parent/"trust-without-fixture.plist"
    check=ca.parent/"trust-check.plist"
    try:
        subprocess.run(parts+["trust-settings-export","-d",current],check=True,timeout=20,capture_output=True)
        trust=plistlib.loads(subprocess.check_output(["sudo", "/bin/cat", str(current)], timeout=10))
        entries=trust["trustList"]
        owned=[key for key in entries if key.upper()==fingerprint]
        if len(owned)!=1:raise RuntimeError("Fixture trust entry could not be uniquely identified")
        del entries[owned[0]]
        reduced.write_bytes(plistlib.dumps(trust))
        subprocess.run(parts+["trust-settings-import","-d",reduced],check=True,timeout=35,capture_output=True)
        subprocess.run(parts+["trust-settings-export","-d",check],check=True,timeout=20,capture_output=True)
        if plistlib.loads(subprocess.check_output(["sudo", "/bin/cat", str(check)], timeout=10))["trustList"]!=entries:
            raise RuntimeError("Administrative trust cleanup could not be verified")
    finally:
        subprocess.run(parts+["delete-certificate","-Z",fingerprint,keychain],check=True,timeout=30,capture_output=True)

if __name__=="__main__":
    os.umask(0o077)
    bins=Path(sys.argv[1]).resolve(); result=Path(sys.argv[2]); result.mkdir(exist_ok=True)
    rows=[]
    (result/"environment.json").write_bytes(fetch("environment"))
    with tempfile.TemporaryDirectory() as folder:
        ca=Path(folder)/"fixture.pem"; ca.write_text(ssl.DER_cert_to_PEM_cert(fetch("ca.der")))
        ctx=ssl.create_default_context(cafile=str(ca))
        fingerprint=subprocess.check_output(["openssl","x509","-in",ca,"-noout","-fingerprint","-sha1"],text=True).strip().split("=")[1].replace(":","")
        present=subprocess.check_output(["security","find-certificate","-a","-Z","/Library/Keychains/System.keychain"],text=True)
        assert fingerprint not in present
        subprocess.run(["sudo","security","add-trusted-cert","-d","-r","trustRoot","-p","ssl","-s","relay.test","-k","/Library/Keychains/System.keychain",ca],check=True,timeout=30)
        try:
            for kind,relayport in (("rust",14200),("caddy",14201)):
                cfg=plistlib.loads(fetch(kind+".mobileconfig"))
                h=next(p for p in cfg['PayloadContent'] if p.get('PayloadType')=='com.apple.relay.managed')['Relays'][0]['AdditionalHTTPHeaderFields']
                secret=base64.b64decode(next(v for k,v in h.items() if k.lower() in ('authorization','proxy-authorization')).split()[1]).decode().split(':',1)[1]
                for prod in ("tun",):
                    for mode in ("h2","h3"):
                        row={"server":kind,"product":prod,"transport":mode}
                        try: row.update(case(prod,kind,relayport,mode,secret,ca,ctx,result))
                        except Exception as err: row.update(ok=False,error=str(err).replace(secret,"<redacted>"))
                        rows.append(row);print(json.dumps(row),flush=True)
                        (result/"summary.json").write_text(json.dumps(rows,indent=2))
        finally:
            try:
                remove_anchor(ca,fingerprint)
                (result/"trust-cleanup.json").write_text(json.dumps({"removed":True}))
            except Exception as exc:
                (result/"trust-cleanup.json").write_text(json.dumps({"removed":False,"error":type(exc).__name__}))
                raise
    sys.exit(any(not row['ok'] for row in rows))
