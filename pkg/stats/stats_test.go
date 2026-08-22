package stats

import (
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/edsilegx/netping/pkg/consts"
	"github.com/stretchr/testify/assert"
)

func TestNewStatistics_Defaults(t *testing.T) {
	ip := netip.MustParseAddr("192.168.1.1")
	stats := NewStatistics(Options{
		Hostname:   "example.com",
		IP:         ip,
		Port:       443,
		TargetIsIP: false,
	})

	assert.Equal(t, "example.com", stats.Hostname)
	assert.Equal(t, ip, stats.IP)
	assert.Equal(t, uint16(443), stats.Port)
	assert.Equal(t, consts.TCP, stats.Protocol)
	assert.Equal(t, "192.168.1.1", stats.IPStr())
	assert.Equal(t, "443", stats.PortStr())
	assert.Equal(t, "TCP", stats.ProtocolStr())
	assert.NotEmpty(t, stats.StartTimeFormatted())
}

func TestStatistics_MethodsAndFormatting(t *testing.T) {
	ip := netip.MustParseAddr("10.0.0.1")
	localAddr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:54321")
	assert.NoError(t, err)

	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	stats := NewStatistics(Options{
		Hostname:          "db.local",
		IP:                ip,
		Port:              5432,
		Protocol:          consts.POSTGRES,
		LocalAddr:         localAddr,
		WithTimestamp:     true,
		WithSourceAddress: true,
		WithDiags:         true,
	})

	stats.StartTime = now
	stats.EndTime = now.Add(10 * time.Minute)
	stats.LatestRTT = 12.3456

	assert.Equal(t, "db.local", stats.Hostname)
	assert.Equal(t, "10.0.0.1", stats.IPStr())
	assert.Equal(t, "5432", stats.PortStr())
	assert.Equal(t, "127.0.0.1:54321", stats.SourceAddr())
	assert.Equal(t, "POSTGRES", stats.ProtocolStr())
	assert.Equal(t, "12.346", stats.RTTStr())
	assert.Equal(t, "2026-08-21 12:00:00", stats.StartTimeFormatted())
	assert.Equal(t, "2026-08-21 12:10:00", stats.EndTimeFormatted())
}

func TestNewLongestTime(t *testing.T) {
	start := time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)
	duration := 5 * time.Minute
	lt := NewLongestTime(start, duration)

	assert.Equal(t, start, lt.Start)
	assert.Equal(t, start.Add(duration), lt.End)
	assert.Equal(t, duration, lt.Duration)
}

func TestStatistics_ConcurrentAccess(t *testing.T) {
	stats := NewStatistics(Options{
		Hostname: "test.local",
		IP:       netip.MustParseAddr("127.0.0.1"),
		Port:     8080,
	})

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			stats.Mu.Lock()
			stats.Successful++
			stats.TotalSuccessfulProbes++
			stats.RTT = append(stats.RTT, float32(idx)*1.5)
			stats.LatestRTT = float32(idx) * 1.5
			stats.Mu.Unlock()

			_ = stats.SourceAddr()
			_ = stats.RTTStr()
			_ = stats.IPStr()
			_ = stats.PortStr()
		}(i)
	}

	wg.Wait()
	assert.Equal(t, 50, stats.Successful)
	assert.Equal(t, uint(50), stats.TotalSuccessfulProbes)
	assert.Equal(t, 50, len(stats.RTT))
}
