package networkrelay

import (
	"bytes"
	"errors"
	"testing"
	"testing/iotest"
)

func TestCapsulePayloadAcrossReaderBoundary(t *testing.T) {
	sizes := []int{0, 63, 64, 1200, 16383, 16384, 16385, maxUDPPayload, 1}
	var stream []byte
	for i, size := range sizes {
		stream = appendDatagramCapsule(stream, bytes.Repeat([]byte{byte(i)}, size))
	}
	for _, truncate := range []bool{false, true} {
		data, want := stream, len(sizes)
		if truncate {
			data, want = data[:len(data)-1], want-1
		}
		count := 0
		err := readCapsules(iotest.OneByteReader(bytes.NewReader(data)), func(p []byte) {
			if count >= want || !bytes.Equal(p, bytes.Repeat([]byte{byte(count)}, sizes[count])) {
				t.Fatalf("corrupted or unexpected payload %d", count)
			}
			count++
		})
		if count != want || (truncate && !errors.Is(err, errMalformed)) || (!truncate && err != nil) {
			t.Fatalf("truncate=%v: delivered %d, want %d, err %v", truncate, count, want, err)
		}
	}
}

// Native HTTP Datagrams still keep a Capsule reader alive so both encodings
// can be mixed. The idle case measures its cost before any Capsule arrives.
func BenchmarkCapsuleReader(b *testing.B) {
	small := appendDatagramCapsule(nil, bytes.Repeat([]byte{1}, 1200))
	large := appendDatagramCapsule(nil, bytes.Repeat([]byte{1}, maxUDPPayload))
	for _, tc := range []struct {
		name   string
		stream []byte
	}{
		{name: "idle"},
		{name: "unknown", stream: capsule(0x1234, bytes.Repeat([]byte{1}, 1200))},
		{name: "empty", stream: appendDatagramCapsule(nil, nil)},
		{name: "1200", stream: small},
		{name: "65527", stream: large},
		{name: "64x1200", stream: bytes.Repeat(small, 64)},
		{name: "64x65527", stream: bytes.Repeat(large, 64)},
		{name: "mixed", stream: bytes.Join([][]byte{small, large, small, large}, nil)},
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
