package probers

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/edsilegx/netping/pkg/stats"
	"github.com/stretchr/testify/assert"
)

func TestMultiProber_Execution(t *testing.T) {
	ln1, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer ln1.Close()

	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer ln2.Close()

	parts1 := strings.Split(ln1.Addr().String(), ":")
	port1, _ := strconv.Atoi(parts1[len(parts1)-1])

	parts2 := strings.Split(ln2.Addr().String(), ":")
	port2, _ := strconv.Atoi(parts2[len(parts2)-1])

	pinger1 := NewTcping(TCPOptions{
		IP:      netip.MustParseAddr("127.0.0.1"),
		Port:    uint16(port1),
		Timeout: 1 * time.Second,
	})
	pinger2 := NewTcping(TCPOptions{
		IP:      netip.MustParseAddr("127.0.0.1"),
		Port:    uint16(port2),
		Timeout: 1 * time.Second,
	})

	workers := []TargetWorker{
		{
			Target: ln1.Addr().String(),
			Pinger: pinger1,
			Stats:  &stats.Statistics{},
		},
		{
			Target: ln2.Addr().String(),
			Pinger: pinger2,
			Stats:  &stats.Statistics{},
		},
	}

	multi := NewMultiProber(workers, MultiProberOptions{
		ProbeCount: 2,
		Interval:   5 * time.Millisecond,
		Timeout:    1 * time.Second,
		NoColor:    true,
	})
	multi.Run(context.Background())

	assert.Equal(t, uint(2), workers[0].Stats.TotalSuccessfulProbes)
	assert.Equal(t, uint(2), workers[1].Stats.TotalSuccessfulProbes)
}
