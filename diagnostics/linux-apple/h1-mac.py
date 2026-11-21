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
def boundary(port, ctx):
    before = json.loads(p.fetch('counts'))
    for mode in ['C','R','R','R'] * 5:
        with p.socks(port,1,b'\x01\x7f\0\0\x01',18449)[0] as channel:
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
            if mode == 'C' and terminal == 'EOF':
                channel.sendall(b'ping')
            rows.append(dict(mode=mode,terminal=terminal,size=total,complete=h.digest()==payload_hash))
    for _ in range(30):
        after = json.loads(p.fetch('counts'))
        if after.get('reverse_ping',0)-before.get('reverse_ping',0)==5: break
        time.sleep(.1)
    counts = {key:after.get(key,0)-before.get(key,0) for key in ('attempt_abort','reverse_ping')}
    print(json.dumps(dict(rows=rows,counts=counts)),flush=True)
    (out/'h1-nf.json').write_text(json.dumps(dict(rows=rows,counts=counts),indent=2))
    assert counts == dict(attempt_abort=15,reverse_ping=5), counts
    assert all(r['terminal']=='EOF' and r['complete'] if r['mode']=='C' else r['terminal']=='ECONNRESET' for r in rows), rows

cfg=plistlib.loads(p.fetch('caddy.mobileconfig'))
entry=next(x for x in cfg['PayloadContent'] if x.get('PayloadType')=='com.apple.relay.managed')
headers=entry['Relays'][0]['AdditionalHTTPHeaderFields']
secret=base64.b64decode(next(v for k,v in headers.items() if k.lower() in ('authorization','proxy-authorization')).split()[1]).decode().split(':',1)[1]
p.bins = Path(os.environ['RUNNER_TEMP'])/'products'
with tempfile.TemporaryDirectory() as d:
    root=Path(d)/'ca.der'
    root.write_bytes(p.fetch('ca.der'))
    os.environ['RELAY_FIXTURE_CA_DER']=str(root)
    p.case('nf','caddy',14201,'http/1.1',secret,root,None,out)
