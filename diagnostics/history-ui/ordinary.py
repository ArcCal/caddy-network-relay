import os
import socket
for family, host in ((socket.AF_INET, "198.51.100.42"), (socket.AF_INET6, "2001:db8::42")):
    for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
        cookie = os.urandom(32)
        with socket.socket(family, kind) as ch:
            ch.settimeout(8)
            ch.connect((host,443))
            ch.sendall(cookie)
            if kind == socket.SOCK_DGRAM:
                payload = ch.recv(256)
            else:
                payload = b""
                while len(payload)<len(cookie):
                    data=ch.recv(256)
                    assert data
                    payload+=data
            assert payload==cookie
print("4 plain sockets echoed")
