package utils

import (
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/edsilegx/netping/pkg/stats"
)

// NanoToMillisecond returns an amount of milliseconds from nanoseconds.
func NanoToMillisecond(nano int64) float32 {
	return float32(nano) / float32(time.Millisecond)
}

// SecondsToDuration returns the corresponding duration from seconds expressed with a float.
func SecondsToDuration(seconds float64) time.Duration {
	return time.Duration(1000*seconds) * time.Millisecond
}

// MaxDuration returns the longest duration of x or y.
func MaxDuration(x, y time.Duration) time.Duration {
	if x > y {
		return x
	}
	return y
}

// DurationToString creates a human-readable string for a given duration
func DurationToString(duration time.Duration) string {
	hours := math.Floor(duration.Hours())
	if hours > 0 {
		duration -= time.Duration(hours * float64(time.Hour))
	}

	minutes := math.Floor(duration.Minutes())
	if minutes > 0 {
		duration -= time.Duration(minutes * float64(time.Minute))
	}

	seconds := duration.Seconds()

	switch {
	case hours >= 2:
		return fmt.Sprintf("%.0f hours %.0f minutes %.0f seconds", hours, minutes, seconds)
	case hours == 1 && minutes == 0 && seconds == 0:
		return fmt.Sprintf("%.0f hour", hours)
	case hours == 1:
		return fmt.Sprintf("%.0f hour %.0f minutes %.0f seconds", hours, minutes, seconds)
	case minutes >= 2:
		return fmt.Sprintf("%.0f minutes %.0f seconds", minutes, seconds)
	case minutes == 1 && seconds == 0:
		return fmt.Sprintf("%.0f minute", minutes)
	case minutes == 1:
		return fmt.Sprintf("%.0f minute %.0f seconds", minutes, seconds)
	case seconds == 0 || seconds == 1 || seconds >= 1 && seconds < 1.1:
		return fmt.Sprintf("%.0f second", seconds)
	case seconds < 1:
		return fmt.Sprintf("%.1f seconds", seconds)
	default:
		return fmt.Sprintf("%.0f seconds", seconds)
	}
}

// SetLongestDuration updates the longest uptime or downtime based on the given type.
func SetLongestDuration(start time.Time, duration time.Duration, longest *stats.LongestTime) {
	if start.IsZero() || duration == 0 {
		return
	}

	newLongest := stats.NewLongestTime(start, duration)

	if longest.End.IsZero() || newLongest.Duration >= longest.Duration {
		*longest = newLongest
	}
}

// CalculatePercentile computes the p-th percentile (0 <= p <= 100) of the samples.
func CalculatePercentile(samples []float32, percentile float64) float32 {
	if len(samples) == 0 {
		return 0
	}
	sorted := slices.Clone(samples)
	slices.Sort(sorted)

	if percentile <= 0 {
		return sorted[0]
	}
	if percentile >= 100 {
		return sorted[len(sorted)-1]
	}

	rank := (percentile / 100.0) * float64(len(sorted)-1)
	lowerIndex := int(math.Floor(rank))
	upperIndex := int(math.Ceil(rank))
	weight := float32(rank - float64(lowerIndex))

	if lowerIndex == upperIndex {
		return sorted[lowerIndex]
	}

	return sorted[lowerIndex]*(1.0-weight) + sorted[upperIndex]*weight
}

// CalculateJitter computes the average packet jitter (RFC 3550 statistical variance).
func CalculateJitter(samples []float32) float32 {
	if len(samples) < 2 {
		return 0
	}
	var jitter float64
	for i := 1; i < len(samples); i++ {
		d := math.Abs(float64(samples[i] - samples[i-1]))
		jitter += (d - jitter) / 16.0
	}
	return float32(jitter)
}

// ClassifyError returns a standardized, user-friendly taxonomy classification for connection errors.
func ClassifyError(err error) string {
	if err == nil {
		return ""
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "Timeout"
	}

	var sysErr *os.SyscallError
	if errors.As(err, &sysErr) {
		var errno syscall.Errno
		if errors.As(sysErr.Err, &errno) {
			switch int(errno) {
			case 10061, 111: // WSAECONNREFUSED, ECONNREFUSED
				return "Connection Refused"
			case 10065, 113: // WSAEHOSTUNREACH, EHOSTUNREACH
				return "Host Unreachable"
			case 10051, 101: // WSAENETUNREACH, ENETUNREACH
				return "Network Unreachable"
			case 10060, 110: // WSAETIMEDOUT, ETIMEDOUT
				return "Connection Timed Out"
			}
		}
	}

	errStr := strings.ToLower(err.Error())
	switch {
	case strings.Contains(errStr, "refused"):
		return "Connection Refused"
	case strings.Contains(errStr, "unreachable"):
		return "Host Unreachable"
	case strings.Contains(errStr, "timeout") || strings.Contains(errStr, "deadline exceeded"):
		return "Timeout"
	case strings.Contains(errStr, "no such host") || strings.Contains(errStr, "dns"):
		return "DNS Resolution Failed"
	default:
		return "Probe Failed"
	}
}

// GenerateSparkline creates a Unicode sparkline string for a slice of RTT samples.
func GenerateSparkline(samples []float32, maxBlocks int) string {
	if len(samples) == 0 {
		return ""
	}
	if maxBlocks > 0 && len(samples) > maxBlocks {
		samples = samples[len(samples)-maxBlocks:]
	}

	blocks := []rune{' ', '▂', '▃', '▄', '▅', '▆', '▇', '█'}
	minVal := slices.Min(samples)
	maxVal := slices.Max(samples)

	if minVal == maxVal {
		return strings.Repeat("▄", len(samples))
	}

	var sb strings.Builder
	for _, v := range samples {
		normalized := (v - minVal) / (maxVal - minVal)
		index := int(normalized * float32(len(blocks)-1))
		if index < 0 {
			index = 0
		}
		if index >= len(blocks) {
			index = len(blocks) - 1
		}
		sb.WriteRune(blocks[index])
	}
	return sb.String()
}
