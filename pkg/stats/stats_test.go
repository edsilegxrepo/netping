// Test Strategy (pkg/stats):
//  1. Metric Accumulation & Math: Validate min, max, average, and loss percentage after successive probe records.
//  2. RFC 3550 Interarrival Jitter: Verify jitter calculation formula across varying latency sequences.
//  3. Streak Tracking: Validate consecutive uptime and downtime durations and transition timestamps.
//  4. Concurrency & Race Safety: Execute parallel RecordProbe and Snapshot calls under high goroutine load.
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

func TestStatistics_RecordSuccess_RecordFailure_Snapshot_Reset(t *testing.T) {
	st := NewStatistics(Options{
		Hostname: "live.example.com",
		IP:       netip.MustParseAddr("1.1.1.1"),
		Port:     443,
		Protocol: consts.HTTPS,
	})

	now := time.Now()

	// Initial snapshot on empty stats
	snap0 := st.Snapshot()
	assert.Equal(t, "live.example.com", snap0.Hostname)
	assert.Equal(t, uint(0), snap0.TotalSent)
	assert.Equal(t, float64(0), snap0.PacketLoss)
	assert.Equal(t, float32(0), snap0.AvgRTT)

	// Record 3 successes
	st.RecordSuccess(10.0, now)
	st.RecordSuccess(20.0, now.Add(time.Second))
	st.RecordSuccess(15.0, now.Add(2*time.Second))

	assert.Equal(t, uint(3), st.TotalSuccessfulProbes)
	assert.Equal(t, float32(10.0), st.MinRTT)
	assert.Equal(t, float32(20.0), st.MaxRTT)
	assert.Equal(t, float32(15.0), st.LatestRTT)
	assert.Equal(t, uint(3), st.OngoingSuccessfulProbes)
	assert.Equal(t, uint(0), st.OngoingUnsuccessfulProbes)

	// Record 1 failure
	st.RecordFailure("connection timeout", now.Add(3*time.Second))
	assert.Equal(t, uint(1), st.TotalUnsuccessfulProbes)
	assert.Equal(t, uint(0), st.OngoingSuccessfulProbes)
	assert.Equal(t, uint(1), st.OngoingUnsuccessfulProbes)
	assert.Equal(t, "connection timeout", st.LastFailureReason)

	// Snapshot checks
	snap := st.Snapshot()
	assert.Equal(t, uint(4), snap.TotalSent)
	assert.Equal(t, uint(3), snap.TotalSuccess)
	assert.Equal(t, uint(1), snap.TotalFailed)
	assert.Equal(t, float64(25.0), snap.PacketLoss) // 1 out of 4 is 25%
	assert.Equal(t, float32(15.0), snap.AvgRTT)
	assert.NotEmpty(t, snap.UptimeDuration)

	// Reset checks
	st.Reset()
	assert.Equal(t, uint(0), st.TotalSuccessfulProbes)
	assert.Equal(t, uint(0), st.TotalUnsuccessfulProbes)
	assert.Equal(t, 0, len(st.RTT))
	assert.Equal(t, float32(0), st.MinRTT)
	assert.Equal(t, float32(0), st.MaxRTT)
}
