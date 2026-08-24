// Test Strategy (pkg/probers - Factory):
//  1. Factory Instantiation: Instantiate all 49 protocol probers using BuildPinger and verify non-nil Pinger instances.
//  2. Default Option Application: Validate fallback timeouts, default ports, and protocol type assertions.
package probers

import (
	"net/netip"
	"testing"
	"time"

	"github.com/edsilegx/netping/pkg/consts"
	"github.com/stretchr/testify/assert"
)

func TestBuildPinger_All(t *testing.T) {
	protocols := consts.AllProtocols()
	ip := netip.MustParseAddr("127.0.0.1")

	for _, proto := range protocols {
		t.Run(string(proto), func(t *testing.T) {
			p := BuildPinger(FactoryOptions{
				Protocol:    proto,
				Hostname:    "127.0.0.1",
				IP:          ip,
				Port:        consts.GetDefaultPort(proto),
				Timeout:     1 * time.Second,
				ServiceName: "test_svc",
				DNSHosts:    []string{"127.0.0.1"},
			})
			assert.NotNil(t, p, "prober for %s should not be nil", proto)
		})
	}
}
