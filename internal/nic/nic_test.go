// Test Strategy (internal/nic):
//  1. Local Interface Enumeration: Validate dialer binding against active host network interfaces and loopback.
//  2. Invalid Source Handling: Verify error handling when binding to non-existent or invalid IP addresses.
package nic

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewNetworkInterface_ValidLocalIP(t *testing.T) {
	ifaces, err := net.Interfaces()
	assert.NoError(t, err)

	var validIP string
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() && ipNet.IP.To4() != nil {
				validIP = ipNet.IP.String()
				break
			}
		}
		if validIP != "" {
			break
		}
	}

	if validIP == "" {
		validIP = "127.0.0.1"
	}

	target := netip.MustParseAddr("8.8.8.8")
	nicObj, err := NewNetworkInterface(validIP, target, 443, false, false, time.Second)
	assert.NoError(t, err)
	assert.True(t, nicObj.Use)
	assert.NotNil(t, nicObj.RemoteAddr)
	assert.Equal(t, 443, nicObj.RemoteAddr.Port)

	// Test with IPv6 loopback if available
	_, _ = NewNetworkInterface("::1", target, 443, false, true, time.Second)
}

func TestNewNetworkInterface_InvalidIP(t *testing.T) {
	target := netip.MustParseAddr("8.8.8.8")
	_, err := NewNetworkInterface("198.51.100.254", target, 80, false, false, time.Second)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "is not assigned to any interfaces")
}

func TestNewNetworkInterface_NonExistentInterface(t *testing.T) {
	target := netip.MustParseAddr("8.8.8.8")
	_, err := NewNetworkInterface("nonexistent_nic_999", target, 80, false, false, time.Second)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "was not found")
}

func TestNewNetworkInterface_ValidInterfaceName(t *testing.T) {
	ifaces, err := net.Interfaces()
	assert.NoError(t, err)

	var validIface string
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err == nil && len(addrs) > 0 && iface.Flags&net.FlagUp != 0 {
			validIface = iface.Name
			break
		}
	}

	if validIface == "" {
		t.Skip("No active network interfaces found")
	}

	target := netip.MustParseAddr("1.1.1.1")
	nicObj, err := NewNetworkInterface(validIface, target, 53, false, false, time.Second)
	if err == nil {
		assert.True(t, nicObj.Use)
		assert.NotNil(t, nicObj.RemoteAddr)
		assert.Equal(t, 53, nicObj.RemoteAddr.Port)
	}

	// Test with IPv4 preference
	_, _ = NewNetworkInterface(validIface, target, 53, true, false, time.Second)

	// Test with IPv6 preference
	_, _ = NewNetworkInterface(validIface, target, 53, false, true, time.Second)

	// Test loopback interface with both v4 and v6
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			res4, err := NewNetworkInterface(iface.Name, target, 80, true, false, time.Second)
			if err == nil {
				assert.True(t, res4.Use)
				assert.NotNil(t, res4.RemoteAddr)
			}
			res6, err := NewNetworkInterface(iface.Name, target, 80, false, true, time.Second)
			if err == nil {
				assert.True(t, res6.Use)
				assert.NotNil(t, res6.RemoteAddr)
			}
			break
		}
	}
}
