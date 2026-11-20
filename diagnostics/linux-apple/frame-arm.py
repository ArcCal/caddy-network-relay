"""Apply the same read-only numeric sampler to both arms; optionally bound H3 DATA frames."""
import sys
from pathlib import Path

root = Path(sys.argv[1]); variant = sys.argv[2]
assert variant in ('stock', 'frame')

def substitute(p, before, after):
    f = root / p; source = f.read_text(); assert source.count(before) == 1, p; f.write_text(source.replace(before, after))

def append(p, text):
    with (root / p).open('a') as f: f.write(text)

append('third_party/quic-go/connection.go', '''
// Diagnostic snapshot of peer-advertised connection credit and accounted bytes.
func (c *Conn) RelayStudyCredit() (int64, int64) {
    f := c.connFlowController
    f.sendMutex.Lock()
    defer f.sendMutex.Unlock()
    return int64(f.sendWindow), int64(f.bytesSent)
}
''')
append('third_party/quic-go/stream.go', '''
// Sample the established send stream under its normal packetization mutex.
func (s *Stream) RelayStudyCredit() (int64, int64, int) {
    f := s.sendStr
    f.mutex.Lock()
    defer f.mutex.Unlock()
    return int64(f.flowController.sendWindow), int64(f.flowController.bytesSent), len(f.dataForWriting)
}
''')
substitute('h3.go','import (','import (\n "encoding/json"\n "os"\n "time"\n "sync"\n "sync/atomic"')
substitute('h3.go','return withConnState(context.WithValue(ctx, quicConnKey{}, c))', '''if os.Getenv("RELAY_STUDY_NUMERIC") != "" {
        relayStudyIDs.Store(c, relayStudySequence.Add(1))
        go func() { <-c.Context().Done(); relayStudyIDs.Delete(c) }()
    }
    return withConnState(context.WithValue(ctx, quicConnKey{}, c))''')
substitute('h3.go','return &h3Body{r:', '''if dir := os.Getenv("RELAY_STUDY_NUMERIC"); dir != "" && conn != nil {
        go relayStudyStream(dir, conn, str.QUICStream())
    }
    return &h3Body{r:''')
append('h3.go','''
var relayStudyIDs sync.Map
var relayStudySequence atomic.Uint64

func relayStudyStream(dir string, c *quic.Conn, s *quic.Stream) {
    file, err := os.CreateTemp(dir, "stream-*.jsonl")
    if err != nil { return }
    defer file.Close()
    connID, _ := relayStudyIDs.Load(c)
    enc := json.NewEncoder(file)
    tick := time.NewTicker(time.Second)
    defer tick.Stop()
    for {
        cl, cs := c.RelayStudyCredit()
        sl, ss, pending := s.RelayStudyCredit()
        st := c.ConnectionStats()
        if err := enc.Encode(map[string]any{
            "conn_id": connID, "stream_id": uint64(s.StreamID()), "conn_limit":cl, "conn_sent":cs, "stream_limit":sl,
            "stream_sent":ss,"pending":pending,"gso":c.ConnectionState().GSO,"wire_bytes":st.BytesSent,
            "packets_sent":st.PacketsSent,"packets_lost":st.PacketsLost,"rtt_us":st.SmoothedRTT.Microseconds(),
        }); err!=nil { return }
        select { case <-s.Context().Done(): return; case <-c.Context().Done(): return; case <-tick.C: }
    }
}
''')
if variant == 'frame':
    substitute('client.go','func (c *h3Client) Write(p []byte) (int, error) { return c.str.Write(p) }', '''func (c *h3Client) Write(p []byte) (int, error) {
    const maxPayload = 16383
    total := 0
    for len(p) > maxPayload {
        n, err := c.str.Write(p[:maxPayload]); total += n
        if err != nil { return total, err }
        if n != maxPayload { return total, io.ErrShortWrite }
        p = p[n:]
    }
    n, err := c.str.Write(p)
    return total+n, err
}''')
