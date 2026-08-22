package dns

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/edsilegx/netping/pkg/stats"
)

func TestDNSDialAddress(t *testing.T) {
	tests := []struct {
		name      string
		dnsServer string
		want      string
	}{
		{"empty input", "", ""},
		{"ipv4 with port", "8.8.8.8:53", "8.8.8.8:53"},
		{"ipv4 without port uses default", "8.8.8.8", "8.8.8.8:" + DefaultPort},
		{"ipv6 without port uses default", "2001:4860:4860::8888", "[2001:4860:4860::8888]:" + DefaultPort},
		{"ipv6 with port", "[2001:4860:4860::8888]:53", "[2001:4860:4860::8888]:53"},
		{"hostname is ignored (not an IP)", "dns.google:53", ""},
		{"garbage input is ignored", "not-an-address", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getDialAddress(tt.dnsServer)
			if got != tt.want {
				t.Errorf("dnsDialAddress(%q) = %q, want %q", tt.dnsServer, got, tt.want)
			}
		})
	}
}

func TestCreateDNSResolver_Defaults(t *testing.T) {
	resolver := createDNSResolver("")
	if !resolver.PreferGo {
		t.Error("expected PreferGo to be true")
	}
	if resolver.Dial == nil {
		t.Fatal("expected Dial to be set")
	}
}

// Spins up a local TCP listener as a stand-in DNS server and checks that
// Dial connects to it regardless of the address it's called with.
func TestCreateDNSResolver_OverridesAddress(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start listener: %v", err)
	}
	defer ln.Close()

	accepted := make(chan struct{}, 1)
	go func() {
		if conn, err := ln.Accept(); err == nil {
			accepted <- struct{}{}
			conn.Close()
		}
	}()

	resolver := createDNSResolver(ln.Addr().String())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conn, err := resolver.Dial(ctx, "tcp", "this-address-should-be-ignored:53")
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	conn.Close()

	select {
	case <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("listener never received a connection: override didn't happen")
	}
}

// When no DNS server is configured, Dial should fall through to whatever
// address it's given.
func TestCreateDNSResolver_NoOverride(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start listener: %v", err)
	}
	defer ln.Close()

	accepted := make(chan struct{}, 1)
	go func() {
		if conn, err := ln.Accept(); err == nil {
			accepted <- struct{}{}
			conn.Close()
		}
	}()

	resolver := createDNSResolver("")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conn, err := resolver.Dial(ctx, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	conn.Close()

	select {
	case <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("listener never received a connection")
	}
}

func TestFilterIPv4(t *testing.T) {
	ip4 := netip.MustParseAddr("8.8.8.8")
	ip6 := netip.MustParseAddr("2001:4860:4860::8888")

	filtered := filterIPv4([]netip.Addr{ip4, ip6})
	if len(filtered) != 1 || filtered[0] != ip4 {
		t.Errorf("filterIPv4() = %v, want [%v]", filtered, ip4)
	}
}

func TestFilterIPv6(t *testing.T) {
	ip4 := netip.MustParseAddr("8.8.8.8")
	ip6 := netip.MustParseAddr("2001:4860:4860::8888")

	filtered := filterIPv6([]netip.Addr{ip4, ip6})
	if len(filtered) != 1 || filtered[0] != ip6 {
		t.Errorf("filterIPv6() = %v, want [%v]", filtered, ip6)
	}
}

func TestSelectRandomIP(t *testing.T) {
	t.Run("empty list", func(t *testing.T) {
		_, err := selectRandomIP(nil)
		if err != ErrNoIPAddresses {
			t.Errorf("expected ErrNoIPAddresses, got %v", err)
		}
	})

	t.Run("valid list", func(t *testing.T) {
		ip1 := netip.MustParseAddr("1.1.1.1")
		ip2 := netip.MustParseAddr("8.8.8.8")
		selected, err := selectRandomIP([]netip.Addr{ip1, ip2})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if selected != ip1 && selected != ip2 {
			t.Errorf("unexpected selected IP: %v", selected)
		}
	})
}

func TestResolveHostname_DirectIP(t *testing.T) {
	r := NewResolver("", time.Second, false, false)
	ip, err := r.ResolveHostname("192.168.1.50")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ip.String() != "192.168.1.50" {
		t.Errorf("expected 192.168.1.50, got %v", ip)
	}
}

func TestResolveHostname_Localhost(t *testing.T) {
	r := NewResolver("", time.Second, true, false)
	ip, err := r.ResolveHostname("localhost")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ip.IsLoopback() {
		t.Errorf("expected loopback IP for localhost, got %v", ip)
	}

	// Test default dual-stack resolution
	rDual := NewResolver("", time.Second, false, false)
	_, _ = rDual.ResolveHostname("localhost")

	// Test IPv6 resolution
	r6 := NewResolver("", time.Second, false, true)
	_, _ = r6.ResolveHostname("localhost")
}

func TestRetryResolveHostname(t *testing.T) {
	r := NewResolver("", time.Second, false, false)
	s := stats.NewStatistics(stats.Options{
		Hostname: "127.0.0.1",
		IP:       netip.MustParseAddr("127.0.0.1"),
		Port:     80,
	})

	err := r.RetryResolveHostname(s)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.IP.String() != "127.0.0.1" {
		t.Errorf("expected 127.0.0.1, got %v", s.IP)
	}
}

func TestHasGlobalIPv6(t *testing.T) {
	// Must run cleanly on both IPv4-only and IPv6-enabled systems
	_ = HasGlobalIPv6()
}

func TestUnmapAddresses(t *testing.T) {
	ip4 := netip.MustParseAddr("192.168.1.1")
	mapped := netip.MustParseAddr("::ffff:192.168.1.1")
	unmapped := unmapAddresses([]netip.Addr{mapped})
	if len(unmapped) != 1 || unmapped[0] != ip4 {
		t.Errorf("expected %v, got %v", ip4, unmapped)
	}
}

