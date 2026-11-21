"""RS SOCKS results with the TLS peer on the same machine, without forwarding."""
import base64, collections, hashlib, os, pathlib, signal, socket, socketserver, ssl, struct, subprocess, sys, tempfile, threading, time
from pathlib import Path
blob = bytes(range(256)) * 32768
expected = hashlib.sha256(blob).digest()
results = collections.Counter()
reports = collections.Counter()
lock = threading.Lock()
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
                if mode==b'R': raw.setsockopt(socket.SOL_SOCKET,socket.SO_LINGER,struct.pack('ii',1,0))
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
    with Server(('127.0.0.1',0),Peer) as peer:
        threading.Thread(target=peer.serve_forever,daemon=True).start()
        with socket.socket() as pick:
            pick.bind(('127.0.0.1',0)); port=pick.getsockname()[1]
        cfg=root/'client.toml'
        cfg.write_text(f'uri_template="https://127.0.0.1:{peer.server_address[1]}/.well-known/masque/udp/{{target_host}}/{{target_port}}/"\nusername="alice"\npassword="disposable"\nserver_name="relay.test"\ntransport="http/1.1"\nmode="socks"\n[socks]\nlisten=["127.0.0.1:{port}"]\n')
        child=subprocess.Popen([sys.argv[1],'--config',str(cfg),'--ca-file',str(root/'ca.pem'),'--duration','600'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            for _ in range(100):
                assert child.poll() is None, 'RS process exited'
                try: socket.create_connection(('127.0.0.1',port),timeout=.2).close();break
                except OSError: time.sleep(.1)
            for mode in [b'C',b'F',b'R'] * 20:
                with socket.create_connection(('127.0.0.1',port),timeout=20) as ch:
                    ch.sendall(b'\x05\x01\x00');assert exact(ch,2)==b'\x05\x00'
                    ch.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01\x00\x07')
                    assert exact(ch,10)[:2]==b'\x05\x00'
                    ch.sendall(mode)
                    digest=hashlib.sha256();n=0
                    try:
                        while data:=ch.recv(65536): digest.update(data);n+=len(data)
                        terminal='EOF'
                    except ConnectionResetError: terminal='RESET'
                    except TimeoutError: terminal='TIMEOUT'
                    results[(mode,terminal)]+=1
                    if mode==b'C': assert n==len(blob) and digest.digest()==expected and terminal=='EOF'
            print('Target completed writes',reports,'SOCKS results',results,flush=True)
            assert results=={(b'C','EOF'):20,(b'F','RESET'):20,(b'R','RESET'):20}
        finally:
            child.send_signal(signal.SIGINT);child.wait(timeout=20);peer.shutdown()
