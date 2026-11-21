import socketserver
import struct

class Boundary(socketserver.BaseRequestHandler):
    def handle(self):
        mode = self.request.recv(1)
        if mode not in (b'R', b'C'):
            return
        self.request.settimeout(25)
        tag=mode.decode()
        count("entered_"+tag)
        try:
            self.request.sendall(BLOCK * 128)
        except OSError:
            count("write_failed_"+tag)
            raise
        count("queued_"+tag)
        if mode == b'R':
            self.request.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
            count('attempt_abort')
        else:
            self.request.shutdown(socket.SHUT_WR)
            if self.request.recv(4, socket.MSG_WAITALL) == b'ping':
                count('reverse_ping')

boundary = socketserver.ThreadingTCPServer(('127.0.0.1', 18449), Boundary)
# TCPServer's normal teardown uses shutdown(SHUT_WR) and would mask the reset.
boundary.shutdown_request = lambda sock: sock.close()
threading.Thread(target=boundary.serve_forever, daemon=True).start()
