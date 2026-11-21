import base64
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import socketserver
import struct
import subprocess
import sys
import threading
import time
import products

def serve(root):
    import guest
    secret=guest.credentials()
    jobs=guest.start_servers(secret)
    class TCP(socketserver.BaseRequestHandler):
        def handle(self):
            with self.request.makefile('rb') as f:
                while data:=f.read(32768):
                    self.request.sendall(data)
    class UDP(socketserver.BaseRequestHandler):
        def handle(self):
            body,sock=self.request
            sock.sendto(body,self.client_address)
    for cls,handler,port in [(socketserver.ThreadingTCPServer,TCP,18220),(socketserver.ThreadingUDPServer,UDP,18221)]:
        srv=cls(('127.0.0.1',port),handler)
        threading.Thread(target=srv.serve_forever,daemon=True).start()
    (root/'ca.pem').write_bytes((guest.ROOT/'ca.pem').read_bytes())
    (root/'secret').write_text(secret.strip())
    (root/'ready').touch()
    try:
        while all(p.poll() is None for p in jobs):time.sleep(.5)
        raise RuntimeError("Linux relay exited")
    finally:
        for p in jobs:p.terminate()

def client(root, binary):
    target=b'\x01\x7f\0\0\x01'
    expected=bytes(range(256))*256
    for relay,relayport in [('rust',14200),('caddy',14201)]:
        for mode in ['h2','h3']:
            settings=root/'rs.toml'
            settings.write_text(f'uri_template = "https://relay.test:{relayport}/.well-known/masque/udp/{{target_host}}/{{target_port}}/"\nusername = "alice"\npassword = {json.dumps((root/"secret").read_text())}\ntransport = "{mode}"\nmode = "socks"\nprobe_target = "127.0.0.1:18221"\n[socks]\nlisten = ["127.0.0.1:18888"]\n')
            with subprocess.Popen([binary,'--config',str(settings),'--ca-file',str(root/'ca.pem'),'--duration','55'],stdout=subprocess.DEVNULL) as proc:
                try:
                    for _ in range(80):
                        try:
                            conn=products.socks(18888,1,target,18220)[0]
                            break
                        except (OSError,EOFError):
                            if proc.poll() is not None: raise
                            time.sleep(.15)
                    else:raise RuntimeError("No SOCKS admission")
                    with conn:
                        conn.sendall(expected)
                        assert products.full(conn,len(expected))==expected
                    ctl,peer=products.socks(18888,3,b'\x01'+bytes(4),0)
                    with ctl,socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as u:
                        u.settimeout(8)
                        u.connect(('127.0.0.1',peer[1]))
                        for n in [0,63,1200]:
                            payload=bytes(range(256))*5
                            wire=bytes(3)+target+struct.pack('!H',18221)+payload[:n]
                            u.send(wire); assert u.recv(65535)==wire
                    print(relay,mode,'TCP 65536 verified; UDP 0,63,1200 verified',flush=True)
                finally:
                    if proc.poll() is None:proc.send_signal(signal.SIGINT)
                    proc.wait(timeout=12)
if __name__=='__main__':
    os.umask(0o077)
    root=Path(sys.argv[2])
    if sys.argv[1]=='serve':serve(root)
    else:client(root,sys.argv[3])
