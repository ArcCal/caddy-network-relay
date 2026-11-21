"""Read-only Git HTTP fixture and authoritative answers for one test name."""
import hashlib
import socket
import struct
import zlib

NAME = "git-fixture.test"
ADDRESS = "198.51.100.42"
CONTENT = hashlib.shake_256(b"ordinary HTTPS clone fixture").digest(256 * 1024)


def git_files():
    files = {}

    def add(kind, data):
        raw = kind + b" " + str(len(data)).encode() + b"\0" + data
        oid = hashlib.sha1(raw).hexdigest()
        files["objects/" + oid[:2] + "/" + oid[2:]] = zlib.compress(raw)
        return oid

    blob = add(b"blob", CONTENT)
    tree = add(b"tree", b"100644 payload\0" + bytes.fromhex(blob))
    person = b"Anonymous <anonymous@example.invalid> 1700000000 +0000"
    head = add(b"commit", b"tree " + tree.encode() + b"\nauthor " + person
               + b"\ncommitter " + person + b"\n\nFixture\n")
    files["HEAD"] = b"ref: refs/heads/main\n"
    files["info/refs"] = head.encode() + b"\trefs/heads/main\n"
    return files


def dns_reply(query):
    if len(query) < 17 or query[4:6] != b"\0\1":
        return None
    i, labels = 12, []
    while i < len(query) and 0 < query[i] <= 63:
        length = query[i]
        labels.append(query[i+1:i+1+length].lower())
        i += length + 1
    if i + 5 > len(query) or query[i] != 0:
        return None
    qtype, qclass = struct.unpack("!HH", query[i+1:i+5])
    known = b".".join(labels) == NAME.encode()
    answer = known and qclass == 1 and qtype == 1
    header = query[:2] + struct.pack("!5H", 0x8180 if known else 0x8183, 1, int(answer), 0, 0)
    rdata = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 1, 4) + socket.inet_aton(ADDRESS)
    return header + query[12:i+5] + (rdata if answer else b"")
