import base64
import errno
import hashlib
import json
import os
from pathlib import Path
import plistlib
import socket
import struct
import sys
import tempfile
import time

import products as p
out = Path(os.environ['RUNNER_TEMP']) / 'evidence'
rows = []
payload_hash = hashlib.sha256(bytes(range(256)) * 32768).digest()
def sample(connect,label):
    import ssl
    rows=[]

    before = json.loads(p.fetch('counts'))
    for mode in ['C','R','R','R'] * 5:
        prior = json.loads(p.fetch('counts')).get('reverse_ping',0)
        with connect() as channel:
            channel.settimeout(40)
            channel.sendall(mode.encode())
            h = hashlib.sha256()
            total = 0
            try:
                while data := channel.recv(65536):
                    total += len(data)
                    h.update(data)
                terminal = 'EOF'
            except ConnectionResetError:
                terminal = 'ECONNRESET'
            except ssl.SSLEOFError:
                terminal='TLS_UNEXPECTED_EOF'
            if mode == 'C' and terminal == 'EOF':
                channel.sendall(b'ping')
                for i in range(40):
                    if json.loads(p.fetch('counts')).get('reverse_ping',0)>prior: break
                    time.sleep(.1)
            rows.append(dict(mode=mode,terminal=terminal,size=total,complete=h.digest()==payload_hash))
    for _ in range(30):
        after = json.loads(p.fetch('counts'))
        if after.get('reverse_ping',0)-before.get('reverse_ping',0)==5: break
        time.sleep(.1)
    counts = {key:after.get(key,0)-before.get(key,0) for key in ('attempt_abort','reverse_ping')}
    print(json.dumps(dict(label=label,rows=rows,counts=counts)),flush=True)
    (out/(label+'.json')).write_text(json.dumps(dict(rows=rows,counts=counts),indent=2))
    return rows,counts
cfg=plistlib.loads(p.fetch('caddy.mobileconfig'))
entry=next(x for x in cfg['PayloadContent'] if x.get('PayloadType')=='com.apple.relay.managed')
headers=entry['Relays'][0]['AdditionalHTTPHeaderFields']
secret=base64.b64decode(next(v for k,v in headers.items() if k.lower() in ('authorization','proxy-authorization')).split()[1]).decode().split(':',1)[1]
p.bins = Path(os.environ['RUNNER_TEMP'])/'products'
with tempfile.TemporaryDirectory() as d:
    root=Path(d)/'ca.der'
    root.write_bytes(p.fetch('ca.der'))
    os.environ['RELAY_FIXTURE_CA_DER']=str(root)
    import ssl
    ctx=ssl.create_default_context(cadata=ssl.DER_cert_to_PEM_cert(root.read_bytes()))
    ctx.set_alpn_protocols(['http/1.1'])
    def raw(host):
        sock=ctx.wrap_socket(socket.create_connection((host,14201),timeout=15),server_hostname='relay.test',suppress_ragged_eofs=False)
        auth=base64.b64encode(('alice:'+secret).encode()).decode()
        sock.sendall((f'CONNECT 127.0.0.1:18449 HTTP/1.1\r\nHost: 127.0.0.1:18449\r\nAuthorization: Basic {auth}\r\n\r\n').encode())
        header=b''
        while not header.endswith(b'\r\n\r\n'):
            b=sock.recv(1)
            if not b or len(header)>8192: raise ValueError('Incomplete CONNECT')
            header+=b
        assert sock.selected_alpn_protocol()=='http/1.1' and header.startswith(b'HTTP/1.1 200')
        return sock
    def boundary(port, ctx):
        return sample(lambda:p.socks(port,1,b'\x01\x7f\0\0\x01',18449)[0],'native-nf-packet')
    control=sample(lambda:raw('127.0.0.1'),'openssl-port-forward')
    packet=sample(lambda:raw('192.0.2.2'),'openssl-packet')
    native=p.case('nf','caddy',14201,'http/1.1',secret,root,None,out)

    for name,(rows,counts) in [('openssl-packet',packet),('nf',native)]:
        assert counts == dict(attempt_abort=15,reverse_ping=5),(name,counts)
        assert all(r['complete'] and r['terminal']=='EOF' for r in rows if r['mode']=='C'),name
        assert all(r['terminal'] in ('ECONNRESET','TLS_UNEXPECTED_EOF') for r in rows if r['mode']=='R'),name
