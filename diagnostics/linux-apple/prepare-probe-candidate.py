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

# Only refine an existing acknowledged search when an actual application
# datagram fits in the final interval and exceeds the current proven limit.
path = "third_party/quic-go/connection.go"
text = (out / "connection.go").read_text()
marker = "datagramMTUProbeRequested atomic.Bool"
assert text.count(marker) == 1
text = text.replace(marker, marker + "\n    rejectedDatagramSize atomic.Uint32")
marker = "\t\t\tc.datagramMTUProbeRequested.Store(true)"
assert text.count(marker) == 1
text = text.replace(marker, '''            if protocol.ByteCount(len(p)) <= estimateMaxPayloadSize(protocol.MaxPacketBufferSize) {
                c.rejectedDatagramSize.Store(uint32(len(p)))
            }
''' + marker)
marker = "\t\treturn &DatagramTooLargeError{MaxDatagramPayloadSize: int64(maxDataLen)}"
assert text.count(marker) == 1
text = text.replace(marker, '''        fmt.Printf("fixture_datagram_limit %d %d %d %d\\n", len(p), maxDataLen, c.peerParams.MaxDatagramFrameSize, c.peerParams.MaxUDPPayloadSize)
''' + marker)
marker = "c.mtuDiscoverer = newMTUDiscoverer("
assert text.count(marker) == 1
start = text.index(marker)
end = text.index("\n\t)", start) + 3
text = text[:end] + "\n    c.mtuDiscoverer.rejectedDatagramSize = &c.rejectedDatagramSize" + text[end:]
write(path, text)

path = "third_party/quic-go/mtu_discoverer.go"
text = (root / path).read_text().replace("import (", 'import (\n    "sync/atomic"', 1)
text = text.replace("type mtuFinder struct {", "type mtuFinder struct {\n    rejectedDatagramSize *atomic.Uint32", 1)
marker = "return f.max()-f.min <= maxMTUDiff+1"
assert text.count(marker) == 1
text = text.replace(marker, '''upper := f.max()
    if f.rejectedDatagramSize != nil {
        target := protocol.ByteCount(f.rejectedDatagramSize.Load())
        if target > estimateMaxPayloadSize(f.min) && target <= estimateMaxPayloadSize(upper) {
            return upper-f.min <= 1
        }
    }
    return upper-f.min <= maxMTUDiff+1''')
write(path, text)

# This test uses a real UDP path with and without the restrictive MTU. The
# exercised size includes an HTTP/3 flow identifier and a MASQUE context ID.
path = "readiness_protocol_test.go"
text = (out / "readiness_protocol_test.go").read_text()
start = text.index("func TestIdleDatagramPathMTUDiscovery(")
end = text.index("\nfunc ", start + 6)
test = text[start:end].replace("TestIdleDatagramPathMTUDiscovery", "TestRequestedDatagramNearSearchCeiling")
test = test.replace("bytes.Repeat([]byte{0xa5}, 1200)", "bytes.Repeat([]byte{0xa5}, 1402)")
write(path, text + "\n" + test)
(out / "overlay.json").write_text(json.dumps({"Replace": replacements}))
