"""Build the diagnostic variant through a Go overlay, without changing the released sources."""

import json
from pathlib import Path
import sys

root, out = Path.cwd(), Path(sys.argv[1]).resolve()
out.mkdir(parents=True, exist_ok=True)
replacements = {}


def write(relative, source):
    source_path = root / relative
    target = out / source_path.name
    target.write_text(source)
    replacements[str(source_path)] = str(target)


path = "third_party/quic-go/connection.go"
text = (root / path).read_text()
marker = "// ReceiveDatagram gets a message"
assert text.count(marker) == 1
write(path, text.replace(marker, '''// RequestDatagramPathMTUDiscovery schedules normal, congestion-controlled
// probes after application admission. Only acknowledged probes change the MTU.
func (c *Conn) RequestDatagramPathMTUDiscovery() {
    if !c.config.DisablePathMTUDiscovery && c.datagramMTUProbeRequested.CompareAndSwap(false, true) {
        c.scheduleSending()
    }
}

''' + marker))
path = "handler.go"
text = (root / path).read_text()
marker = "u.h3 = cc.(*h3Client).str"
assert text.count(marker) == 1
write(path, text.replace(marker, marker + '''
        if conn, _ := r.Context().Value(quicConnKey{}).(*quic.Conn); conn != nil {
            conn.RequestDatagramPathMTUDiscovery()
        }'''))
path = "readiness_protocol_test.go"
text = (root / path).read_text()
first = text.index("func TestIdleDatagramPathMTUDiscovery(")
last = text.index("\nfunc ", first + 6)
test = text[first:last].replace("TestIdleDatagramPathMTUDiscovery", "TestAuthenticatedDatagramProbeHint")
start = test.index("            if err := conn.SendDatagram(payload)".replace("            ", "\t\t\t"))
end = test.index("\t\t\t} else {", start)
test = test[:start] + '''            conn.RequestDatagramPathMTUDiscovery()
            conn.RequestDatagramPathMTUDiscovery()
            time.Sleep(time.Second)
            if limit == 0 {
                if err := conn.SendDatagram(payload); err != nil {
                    t.Fatalf("first application datagram after idle path discovery: %v", err)
                }
''' + test[end:]
write(path, text + "\n" + test)
(out / "overlay.json").write_text(json.dumps({"Replace": replacements}))
