"""Forward the disposable runner's loopback alias to the QEMU loopback UDP port."""
import selectors
import socket

with selectors.DefaultSelector() as selector, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as incoming:
    incoming.bind(("198.51.100.254", 14201))
    selector.register(incoming, selectors.EVENT_READ, None)
    peers = {}
    print("UDP forward ready", flush=True)
    while True:
        for key, _ in selector.select():
            if key.data is None:
                data, source = incoming.recvfrom(65535)
                peer = peers.get(source)
                if peer is None:
                    if len(peers) >= 32:
                        raise RuntimeError("unexpected QUIC peer count in fixture")
                    peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    peer.connect(("127.0.0.1", 14201))
                    peers[source] = peer
                    selector.register(peer, selectors.EVENT_READ, source)
                peer.send(data)
            else:
                incoming.sendto(key.fileobj.recv(65535), key.data)
