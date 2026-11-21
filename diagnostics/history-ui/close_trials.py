"""Record the effect of normal completion, a local FIN or a caller cancellation on DoT."""
import ipaddress
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import struct
from dns_stream import connect, exercise, frame, send_frame

stage = Path('/tmp/relay-history-app')
ca = ssl.create_default_context(cafile=str(stage/'ca.pem'))
proxy = ('127.0.0.1',1080)

def query(slow):
    label = (('slow-' if slow else 'fast-') + secrets.token_hex(6)).encode()
    question = bytes([len(label)]) + label + b'\x0bdns-fixture\x04test\0' + struct.pack('!2H',1,1)
    txid = secrets.token_bytes(2)
    expected = txid + struct.pack('!5H',0x8180,1,1,0,0) + question + b'\xc0\x0c' + struct.pack('!HHIH',1,1,120,4) + ipaddress.ip_address('198.51.100.42').packed
    return txid + struct.pack('!5H',256,1,0,0,0) + question, expected

observed = []
for mode in ('complete','fin','cancel'):
    with connect('1.1.1.1',853,proxy) as raw:
        with ca.wrap_socket(raw,server_hostname='relay.test') as secure:
            observed.append({'mode':mode,'port':secure.getsockname()[1]})
            packet, answer = query(False)
            send_frame(secure,packet)
            assert frame(secure) == answer
            packet, answer = query(True)
            send_frame(secure,packet)
            if mode == 'cancel':
                secure.setsockopt(socket.SOL_SOCKET,socket.SO_LINGER,struct.pack('ii',1,0))
            else:
                if mode == 'fin':
                    with socket.socket(fileno=os.dup(secure.fileno())) as underlying:
                        underlying.shutdown(socket.SHUT_WR)
                assert frame(secure) == answer
    exercise('1.1.1.1',853,ca,proxy,delayed=False)
    print('Controlled local DoT socket',mode,'verified an independent DNS answer',flush=True)
(stage/('close-'+os.environ['CLOSE_CYCLE']+'.json')).write_text(json.dumps(observed))
