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

# Identical A queries over each transport isolate DNS reachability from
# the address family of the HTTP origin. A closed fixture port is the control.
def dns(family, host, available):
    txid = os.urandom(2)
    header = txid + bytes.fromhex("01000001000000000000")
    question = b"\x0bgit-fixture\x04test\0\0\1\0\1"
    with socket.socket(family, socket.SOCK_DGRAM) as channel:
        channel.settimeout(2 if not available else 6)
        channel.connect((host, 53))
        channel.send(header + question)
        try:
            response = channel.recv(4096)
        except (socket.timeout, ConnectionRefusedError):
            if available:
                raise
        else:
            assert available and response.startswith(txid + bytes.fromhex("8180"))
            assert response.endswith(socket.inet_aton("198.51.100.42"))
    print("DNS", host, "answer verified" if available else "closed-port control produced no answer")

dns(socket.AF_INET6, "2001:db8::53", True)
dns(socket.AF_INET6, "2001:db8::42", False)
dns(socket.AF_INET, "1.1.1.1", True)
