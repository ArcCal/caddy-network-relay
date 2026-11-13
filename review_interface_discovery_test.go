package networkrelay

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestInterfaceDiscoveryFailureAfterWarmCache(t *testing.T) {
	hostAddrCache.Lock()
	savedAddrs, savedFetched := hostAddrCache.addrs, hostAddrCache.fetched
	hostAddrCache.addrs, hostAddrCache.fetched = nil, time.Time{}
	hostAddrCache.Unlock()
	defer func() {
		hostAddrCache.Lock()
		hostAddrCache.addrs, hostAddrCache.fetched = savedAddrs, savedFetched
		hostAddrCache.Unlock()
	}()
	expire := func() {
		hostAddrCache.Lock()
		hostAddrCache.fetched = time.Now().Add(-hostAddrsTTL - time.Second)
		hostAddrCache.Unlock()
	}
	oldOwn := netip.MustParseAddr("11.0.0.1")
	newOwn := netip.MustParseAddr("11.0.0.2")
	public := netip.MustParseAddr("8.8.8.8")
	iface := func(ip netip.Addr) []net.Addr {
		return []net.Addr{&net.IPNet{IP: net.IP(ip.AsSlice()), Mask: net.CIDRMask(ip.BitLen(), ip.BitLen())}}
	}
	reads := 0
	fetch := func() ([]net.Addr, error) { reads++; return iface(oldOwn), nil }
	p, err := newPolicy(DefaultBlockedDestinations, DefaultBlockedPorts)
	if err != nil {
		t.Fatal(err)
	}
	p.hostAddrs = func() []netip.Addr { return interfaceAddrsWith(fetch) }
	if p.allows(oldOwn) || !p.allows(public) || reads != 1 {
		t.Fatal("healthy cache did not preserve own-address blocking/public access")
	}
	expire()
	fetch = func() ([]net.Addr, error) {
		reads++
		return nil, errors.New("injected interface-discovery failure")
	}
	if p.allows(newOwn) {
		t.Error("interface-discovery failure allowed a newly assigned own public address")
	}
	if p.allows(public) {
		t.Error("unavailable own-address discovery did not fail closed")
	}
	if _, err := p.resolve(context.Background(), target{host: newOwn.String(), port: 443}); !errors.Is(err, refuseAddress) {
		t.Errorf("unavailable discovery got %v, want destination_ip_prohibited", err)
	}
	if reads != 2 {
		t.Errorf("failed discovery was not cached for its bounded TTL: reads=%d", reads)
	}
	expire()
	fetch = func() ([]net.Addr, error) { reads++; return iface(newOwn), nil }
	if p.allows(newOwn) || !p.allows(public) || !p.allows(oldOwn) {
		t.Error("successful refresh did not restore correct current-address policy")
	}
}
