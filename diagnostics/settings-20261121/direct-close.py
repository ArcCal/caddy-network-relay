"""RS SOCKS results with the TLS peer on the same machine, without forwarding."""
import base64, collections, hashlib, os, pathlib, signal, socket, socketserver, ssl, struct, subprocess, sys, tempfile, threading, time
from pathlib import Path
blob = bytes(range(256)) * 32768
expected = hashlib.sha256(blob).digest()
results = collections.Counter()
reports = collections.Counter()
lock = threading.Lock()
def drain(raw):
    for _ in range(200):
        if raw.getsockopt(socket.SOL_SOCKET, 0x1024) == 0: return
        time.sleep(.002)

def exact(sock, size):
    b = bytearray()
    while len(b) < size:
        chunk = sock.recv(size - len(b))
        if not chunk: raise EOFError("short socket read")
        b.extend(chunk)
    return bytes(b)
class Peer(socketserver.BaseRequestHandler):
    def handle(self):
        with ctx.wrap_socket(self.request,server_side=True) as s:
            s.settimeout(30)
            h = bytearray()
            while not h.endswith(b'\r\n\r\n'):
                h.extend(exact(s,1))
                assert len(h)<8192
            if h.startswith(b'GET '):
                s.sendall(b'HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\nCapsule-Protocol: ?1\r\n\r\n')
                try: s.recv(32)
                except OSError: pass
                return
            assert h.startswith(b'CONNECT ') and s.selected_alpn_protocol()=='http/1.1'
            s.sendall(b'HTTP/1.1 200 OK\r\n\r\n')
            mode=exact(s,1)
            s.sendall(blob)
            with lock: reports[mode]+=1
            if mode==b'C':
                try: s.unwrap().close()
                except OSError: pass
                return
            with socket.socket(fileno=s.detach()) as raw:
                if mode==b'R':
                    if os.getenv('TRACE_DRAIN_PEER')=='1': drain(raw)
                    raw.setsockopt(socket.SOL_SOCKET,socket.SO_LINGER,struct.pack('ii',1,0))
                else: raw.shutdown(socket.SHUT_WR)
class Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    def shutdown_request(self, request): request.close()
with tempfile.TemporaryDirectory() as d:
    root=Path(d)
    def cmd(*args): subprocess.run(args,cwd=d,check=True,capture_output=True)
    (root/'ca.cnf').write_text('[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=ca\n[dn]\nCN=Local Test CA\n[ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n')
    cmd('openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-config','ca.cnf','-keyout','ca.key','-out','ca.pem')
    cmd('openssl','req','-new','-newkey','rsa:2048','-nodes','-subj','/CN=relay.test','-keyout','key.pem','-out','leaf.csr')
    (root/'san').write_text('subjectAltName=DNS:relay.test\nextendedKeyUsage=serverAuth\n')
    cmd('openssl','x509','-req','-in','leaf.csr','-CA','ca.pem','-CAkey','ca.key','-set_serial','3','-days','1','-extfile','san','-out','cert.pem')
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(root/'cert.pem',root/'key.pem');ctx.set_alpn_protocols(['http/1.1'])
    with Server(('127.0.0.1',0),Peer) as server:
        threading.Thread(target=server.serve_forever,daemon=True).start()
        client=ssl.create_default_context(cafile=str(root/'ca.pem'))
        client.set_alpn_protocols(['http/1.1'])
        for draining in ('0','1'):
            os.environ['TRACE_DRAIN_PEER']=draining
            results.clear()
            for mode in [b'C',b'F',b'R'] * 16:
                with socket.create_connection(server.server_address,timeout=3) as raw:
                    with client.wrap_socket(raw,server_hostname='relay.test',suppress_ragged_eofs=False) as tls:
                        tls.sendall(b'CONNECT localhost:7 HTTP/1.1\r\nHost: localhost:7\r\n\r\n')
                        assert exact(tls,19)==b'HTTP/1.1 200 OK\r\n\r\n'
                        tls.sendall(mode)
                        digest=hashlib.sha256();n=0
                        try:
                            while data:=tls.recv(65536): n+=len(data);digest.update(data)
                            outcome='EOF'
                        except ssl.SSLEOFError: outcome='TRUNCATED'
                        except ConnectionResetError: outcome='RESET'
                        except TimeoutError: outcome='TIMEOUT'
                        results[(mode,outcome)]+=1
                        if mode==b'C': assert digest.digest()==expected and outcome=='EOF'
            print('Python/OpenSSL direct macOS socket, drain',draining,'results',results,flush=True)
        server.shutdown()
