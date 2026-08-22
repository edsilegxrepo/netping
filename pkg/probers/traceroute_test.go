package probers

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/edsilegx/netping/pkg/consts"
	"github.com/stretchr/testify/assert"
)

func TestTraceroute_Localhost(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer ln.Close()

	parts := strings.Split(ln.Addr().String(), ":")
	portNum, _ := strconv.Atoi(parts[len(parts)-1])

	var hopsRecorded []TraceHop
	hops, err := RunTraceroute(context.Background(), TracerouteOptions{
		Target:   "127.0.0.1",
		IP:       netip.MustParseAddr("127.0.0.1"),
		Port:     uint16(portNum),
		Protocol: consts.TCP,
		MaxHops:  5,
		Probes:   1,
		Timeout:  500 * time.Millisecond,
	}, func(hop TraceHop) {
		hopsRecorded = append(hopsRecorded, hop)
	})

	assert.NoError(t, err)
	assert.NotEmpty(t, hops)
	assert.NotEmpty(t, hopsRecorded)
}
