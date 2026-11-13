package networkrelay

import (
	"bytes"
	"testing"
)

// Native HTTP Datagrams still keep a Capsule reader alive so both encodings
// can be mixed. The idle case measures its cost before any Capsule arrives.
func BenchmarkCapsuleReader(b *testing.B) {
	for _, tc := range []struct {
		name   string
		stream []byte
	}{
		{name: "idle"},
		{name: "unknown", stream: capsule(0x1234, bytes.Repeat([]byte{1}, 1200))},
		{name: "empty", stream: appendDatagramCapsule(nil, nil)},
		{name: "1200", stream: appendDatagramCapsule(nil, bytes.Repeat([]byte{1}, 1200))},
		{name: "65527", stream: appendDatagramCapsule(nil, bytes.Repeat([]byte{1}, maxUDPPayload))},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(tc.stream)))
			for b.Loop() {
				if err := readCapsules(bytes.NewReader(tc.stream), func([]byte) {}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
