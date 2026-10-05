package networkrelay

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

// RFC 9780 allocated a second non-global prefix in April 2025. It is
// adjacent to, but outside, the older RFC 6666 discard-only prefix.
func TestReviewDefaultPolicyRejectsDummyIPv6(t *testing.T) {
	p, err := newPolicy(DefaultBlockedDestinations, DefaultBlockedPorts)
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"100:0:0:1::", "100:0:0:1::1", "100::1:ffff:ffff:ffff:ffff"} {
		if p.allows(netip.MustParseAddr(host)) {
			t.Fatalf("RFC 9780 dummy address %s was allowed", host)
		}
		if _, err := p.resolve(context.Background(), target{host: host, port: 443}); !errors.Is(err, refuseAddress) {
			t.Fatalf("dummy literal %s: %v, want destination_ip_prohibited", host, err)
		}
	}
	p.resolver = fakeResolver{
		"dummy.example": {netip.MustParseAddr("100:0:0:1::1")},
		"mixed.example": {netip.MustParseAddr("100:0:0:1::1"), netip.MustParseAddr("2606:4700:4700::1111")},
	}
	if _, err := p.resolve(context.Background(), target{host: "dummy.example", port: 443}); !errors.Is(err, refuseAddress) {
		t.Fatalf("dummy DNS answer: %v, want destination_ip_prohibited", err)
	}
	got, err := p.resolve(context.Background(), target{host: "mixed.example", port: 443})
	if err != nil || len(got) != 1 || got[0].Addr() != netip.MustParseAddr("2606:4700:4700::1111") {
		t.Fatalf("mixed DNS answers: %v, %v", got, err)
	}
	for _, host := range []string{"2001:1::1", "2001:1::2", "2001:1::3", "2001:3::1", "2001:4:112::1", "2001:30::1", "2620:4f:8000::1", "2606:4700:4700::1111"} {
		if !p.allows(netip.MustParseAddr(host)) {
			t.Fatalf("public IPv6 exception %s was blocked", host)
		}
	}
}
