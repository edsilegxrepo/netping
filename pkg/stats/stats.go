// Package stats provides thread-safe statistical telemetry tracking, RFC 3550 network jitter calculation,
// running latency aggregates, uptime/downtime streak tracking, and immutable snapshot generation for netping.
//
// Objectives:
//   - Calculate real-time latency aggregates (min, max, average, percentiles, packet loss) in O(1) time.
//   - Compute statistical interarrival network jitter compliant with RFC 3550.
//   - Expose thread-safe immutable snapshots for TUI rendering, file exports, and REST APIs.
//
// Core Components:
//   - Statistics: Thread-safe operational state accumulating probe history, streaks, and metrics.
//   - Snapshot: Immutable point-in-time representation safe for consumption without lock retention.
//   - RecordProbe: Atomically updates counters, streak intervals, and jitter estimates.
//
// Data Flow:
//
//	Probe Execution -> Statistics.RecordProbe -> Mutex Write -> Jitter/Loss Math -> Snapshot() -> UI / Exporters.
package stats

import (
	"fmt"
	"math"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/edsilegx/netping/pkg/consts"
)

type Statistics struct {
	Mu                        sync.RWMutex
	IP                        netip.Addr
	Port                      uint16
	Protocol                  consts.Protocol
	Hostname                  string
	DestWasDown               bool
	DestIsIP                  bool
	LocalAddr                 net.Addr
	StartTime                 time.Time
	EndTime                   time.Time
	UpTime                    time.Duration
	DownTime                  time.Duration
	Successful                int
	Failed                    int
	TotalSuccessfulProbes     uint
	TotalUnsuccessfulProbes   uint
	LastSuccessfulProbe       time.Time     // Timestamp of the last successful probe.
	LastUnsuccessfulProbe     time.Time     // Timestamp of the last unsuccessful probe.
	TotalDowntime             time.Duration // Total accumulated downtime.
	TotalUptime               time.Duration // Total accumulated uptime.
	StartOfUptime             time.Time     // Timestamp when the current uptime started.
	StartOfDowntime           time.Time     // Timestamp when the current downtime started.
	LongestUptime             LongestTime   // Data structure holding information about the longest uptime.
	LongestDowntime           LongestTime   // Data structure holding information about the longest downtime.
	HostnameChanges           []HostnameChange
	RetriedHostnameLookups    uint
	OngoingSuccessfulProbes   uint // Count of ongoing successful probes.
	OngoingUnsuccessfulProbes uint // Count of ongoing unsuccessful probes.
	LongestUp                 LongestTime
	LongestDown               LongestTime
	RTT                       []float32
	LatestRTT                 float32
	MinRTT                    float32
	MaxRTT                    float32
	SumRTT                    float64
	CountRTT                  uint
	Jitter                    float32
	LastFailureReason         string
	RTTResults                RTTResult
	HostChanges               []HostnameChange
	HasResults                bool
	WithTimestamp             bool
	WithSourceAddress         bool
	WithDiags                 bool
	LatestDiagnostics         string
	LatestDNSTime             time.Duration
	LatestTCPTime             time.Duration
	LatestTLSTime             time.Duration
	LatestTTFB                time.Duration
	LatestHTTPStatus          int
	LatestCertExpiry          time.Time
}

type Options struct {
	Hostname          string
	IP                netip.Addr
	Port              uint16
	Protocol          consts.Protocol
	TargetIsIP        bool
	LocalAddr         net.Addr
	WithTimestamp     bool
	WithSourceAddress bool
	WithDiags         bool
}

func NewStatistics(opts Options) *Statistics {
	proto := opts.Protocol
	if proto == "" {
		proto = consts.TCP
	}

	return &Statistics{
		Hostname:          opts.Hostname,
		IP:                opts.IP,
		Port:              opts.Port,
		DestIsIP:          opts.TargetIsIP,
		LocalAddr:         opts.LocalAddr,
		WithTimestamp:     opts.WithTimestamp,
		WithSourceAddress: opts.WithSourceAddress,
		WithDiags:         opts.WithDiags,
		Protocol:          proto,
		RTTResults:        RTTResult{HasResults: false},
		LongestUptime:     LongestTime{},
		LongestDowntime:   LongestTime{},
		HostnameChanges: []HostnameChange{{
			Addr: opts.IP,
			When: time.Now(),
		}},
		StartTime: time.Now(),
	}
}

func (s *Statistics) IPStr() string {
	return s.IP.String()
}

func (s *Statistics) PortStr() string {
	return fmt.Sprint(s.Port)
}

func (s *Statistics) SourceAddr() string {
	s.Mu.RLock()
	defer s.Mu.RUnlock()
	if s.LocalAddr == nil {
		return ""
	}
	return s.LocalAddr.String()
}

func (s *Statistics) StartTimeFormatted() string {
	return s.StartTime.Format(time.DateTime)
}

func (s *Statistics) EndTimeFormatted() string {
	return s.EndTime.Format(time.DateTime)
}

func (s *Statistics) ProtocolStr() string {
	return string(s.Protocol)
}

func (s *Statistics) RTTStr() string {
	s.Mu.RLock()
	defer s.Mu.RUnlock()
	return fmt.Sprintf("%.3f", s.LatestRTT)
}

// RTTResult holds statistics for round-trip times (RTT) results.
type RTTResult struct {
	Min        float32 // Minimum RTT value.
	Max        float32 // Maximum RTT value.
	Average    float32 // Average RTT value.
	Jitter     float32 // Jitter value (RFC 3550).
	P95        float32 // 95th percentile RTT.
	P99        float32 // 99th percentile RTT.
	HasResults bool    // Flag indicating whether RTT results are available.
}

// LongestTime holds information about the longest period of uptime or downtime.
type LongestTime struct {
	Start    time.Time     // Start time of the longest period.
	End      time.Time     // End time of the longest period.
	Duration time.Duration // Duration of the longest period.
}

// NewLongestTime creates and returns a LongestTime instance with the provided start time and duration.
func NewLongestTime(startTime time.Time, duration time.Duration) LongestTime {
	return LongestTime{
		Start:    startTime,
		End:      startTime.Add(duration),
		Duration: duration,
	}
}

// HostnameChange represents changes in the IP address associated with a hostname.
type HostnameChange struct {
	Addr netip.Addr // New IP address associated with the hostname.
	When time.Time  // Timestamp of when the change occurred.
}

// Snapshot provides an immutable point-in-time snapshot of target statistics.
type Snapshot struct {
	Hostname              string    `json:"hostname"`
	IP                    string    `json:"ip"`
	Port                  uint16    `json:"port"`
	Protocol              string    `json:"protocol"`
	TotalSent             uint      `json:"total_sent"`
	TotalSuccess          uint      `json:"total_success"`
	TotalFailed           uint      `json:"total_failed"`
	PacketLoss            float64   `json:"packet_loss"`
	LatestRTT             float32   `json:"latest_rtt"`
	MinRTT                float32   `json:"min_rtt"`
	AvgRTT                float32   `json:"avg_rtt"`
	MaxRTT                float32   `json:"max_rtt"`
	Jitter                float32   `json:"jitter"`
	LastSuccessfulProbe   time.Time `json:"last_successful_probe,omitempty"`
	LastUnsuccessfulProbe time.Time `json:"last_unsuccessful_probe,omitempty"`
	LastFailureReason     string    `json:"last_failure_reason,omitempty"`
	UptimeDuration        string    `json:"uptime_duration"`
	StartTime             time.Time `json:"start_time"`
}

// RecordSuccess updates statistics for a successful probe in O(1) time.
func (s *Statistics) RecordSuccess(rtt float32, now time.Time) {
	s.Mu.Lock()
	defer s.Mu.Unlock()

	s.TotalSuccessfulProbes++
	s.Successful++
	s.HasResults = true
	s.OngoingSuccessfulProbes++
	s.OngoingUnsuccessfulProbes = 0
	s.LastSuccessfulProbe = now

	if s.CountRTT == 0 {
		s.MinRTT = rtt
		s.MaxRTT = rtt
		s.SumRTT = float64(rtt)
		s.CountRTT = 1
		s.Jitter = 0
	} else {
		if rtt < s.MinRTT {
			s.MinRTT = rtt
		}
		if rtt > s.MaxRTT {
			s.MaxRTT = rtt
		}
		s.SumRTT += float64(rtt)
		s.CountRTT++
		// RFC 3550 interarrival jitter algorithm:
		// D(i-1, i) = |RTT_i - RTT_{i-1}|
		// J_i = J_{i-1} + (|D(i-1, i)| - J_{i-1}) / 16
		d := math.Abs(float64(rtt - s.LatestRTT))
		s.Jitter += float32((d - float64(s.Jitter)) / 16.0)
	}
	s.LatestRTT = rtt
	s.RTT = append(s.RTT, rtt)
	if len(s.RTT) > 5000 {
		s.RTT = s.RTT[len(s.RTT)-5000:]
	}
}

// RecordFailure updates statistics for a failed probe in O(1) time.
func (s *Statistics) RecordFailure(reason string, now time.Time) {
	s.Mu.Lock()
	defer s.Mu.Unlock()

	s.TotalUnsuccessfulProbes++
	s.Failed++
	s.OngoingUnsuccessfulProbes++
	s.OngoingSuccessfulProbes = 0
	s.LastUnsuccessfulProbe = now
	s.LastFailureReason = reason
}

// Snapshot returns an immutable point-in-time snapshot of the statistics.
func (s *Statistics) Snapshot() Snapshot {
	s.Mu.RLock()
	defer s.Mu.RUnlock()

	total := s.TotalSuccessfulProbes + s.TotalUnsuccessfulProbes
	loss := float64(0)
	if total > 0 {
		loss = float64(s.TotalUnsuccessfulProbes) / float64(total) * 100.0
	}

	avg := float32(0)
	if s.CountRTT > 0 {
		avg = float32(s.SumRTT / float64(s.CountRTT))
	}

	uptimeStr := ""
	if !s.StartTime.IsZero() {
		uptimeStr = time.Since(s.StartTime).Round(time.Second).String()
	}

	return Snapshot{
		Hostname:              s.Hostname,
		IP:                    s.IP.String(),
		Port:                  s.Port,
		Protocol:              string(s.Protocol),
		TotalSent:             total,
		TotalSuccess:          s.TotalSuccessfulProbes,
		TotalFailed:           s.TotalUnsuccessfulProbes,
		PacketLoss:            loss,
		LatestRTT:             s.LatestRTT,
		MinRTT:                s.MinRTT,
		AvgRTT:                avg,
		MaxRTT:                s.MaxRTT,
		Jitter:                s.Jitter,
		LastSuccessfulProbe:   s.LastSuccessfulProbe,
		LastUnsuccessfulProbe: s.LastUnsuccessfulProbe,
		LastFailureReason:     s.LastFailureReason,
		UptimeDuration:        uptimeStr,
		StartTime:             s.StartTime,
	}
}

// Reset clears historical RTT and counter metrics while preserving target identity.
func (s *Statistics) Reset() {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	s.RTT = make([]float32, 0, 500)
	s.MinRTT = 0
	s.MaxRTT = 0
	s.SumRTT = 0
	s.CountRTT = 0
	s.LatestRTT = 0
	s.Jitter = 0
	s.TotalSuccessfulProbes = 0
	s.TotalUnsuccessfulProbes = 0
	s.Successful = 0
	s.Failed = 0
	s.OngoingSuccessfulProbes = 0
	s.OngoingUnsuccessfulProbes = 0
	s.StartTime = time.Now()
}
