package networkrelay

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"testing/iotest"
)

// Native Relay diagnostics observed this exact boundary: a 63-byte UDP
// payload needs a 64-byte Capsule value and a two-byte length encoding.
// RFC 9297 sections 3.2-3.3 require the complete declared value. A receiver
// cannot recover a missing application byte by guessing the next boundary.
func TestReviewNativeCapsule63ByteBoundary(t *testing.T) {
	payload := make([]byte, 63)
	for i := range payload {
		payload[i] = byte(i)
	}
	valid := append([]byte{0x00, 0x40, 0x40, 0x00}, payload...)
	if len(valid) != 67 {
		t.Fatal("invalid independent wire fixture")
	}
	t.Run("truncated value is not delivered", func(t *testing.T) {
		delivered := 0
		err := readCapsules(bytes.NewReader(valid[:66]), func([]byte) { delivered++ })
		if !errors.Is(err, errMalformed) || delivered != 0 {
			t.Fatalf("err=%v delivered=%d", err, delivered)
		}
	})
	for _, tc := range []struct {
		name   string
		prefix []byte
	}{
		{"minimal", []byte{0x00, 0x40, 0x40, 0x00}},
		{"wide type", []byte{0x40, 0x00, 0x40, 0x40, 0x00}},
		{"wide length", []byte{0x00, 0x80, 0x00, 0x00, 0x40, 0x00}},
		{"wide context", []byte{0x00, 0x40, 0x41, 0x40, 0x00}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire := append(append([]byte{}, tc.prefix...), payload...)
			// Unknown type 1450, empty value, then another valid DATAGRAM.
			// An observed misaligned header must not become a rejection rule.
			wire = append(wire, 0x45, 0xaa, 0x00)
			wire = append(wire, valid...)
			for _, split := range []bool{false, true} {
				var reader io.Reader = bytes.NewReader(wire)
				if split {
					reader = iotest.OneByteReader(reader)
				}
				var delivered [][]byte
				err := readCapsules(reader, func(p []byte) { delivered = append(delivered, bytes.Clone(p)) })
				if err != nil || len(delivered) != 2 {
					t.Fatalf("split=%v err=%v deliveries=%d", split, err, len(delivered))
				}
				for _, p := range delivered {
					if !bytes.Equal(p, payload) {
						t.Fatalf("split=%v payload changed: %x", split, p)
					}
				}
			}
		})
	}
}
