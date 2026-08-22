package utils

import (
	"errors"
	"testing"
	"time"

	"github.com/edsilegx/netping/pkg/stats"
	"github.com/stretchr/testify/assert"
)

func TestNanoToMillisecond(t *testing.T) {
	tests := []struct {
		d    time.Duration
		want float32
	}{
		{d: time.Millisecond, want: 1},
		{d: 100 * time.Millisecond, want: 100},
		{d: time.Second, want: 1000},
	}
	for _, tt := range tests {
		got := NanoToMillisecond(tt.d.Nanoseconds())
		assert.Equal(t, tt.want, got)
	}
}

func TestSecondsToDuration(t *testing.T) {
	assert.Equal(t, time.Second, SecondsToDuration(1.0))
	assert.Equal(t, 500*time.Millisecond, SecondsToDuration(0.5))
	assert.Equal(t, 2*time.Millisecond, SecondsToDuration(0.002))
}

func TestMaxDuration(t *testing.T) {
	assert.Equal(t, 2*time.Second, MaxDuration(2*time.Second, 1*time.Second))
	assert.Equal(t, 2*time.Second, MaxDuration(1*time.Second, 2*time.Second))
	assert.Equal(t, time.Second, MaxDuration(time.Second, time.Second))
}

func TestDurationToString(t *testing.T) {
	tests := []struct {
		name     string
		duration time.Duration
		want     string
	}{
		{"1 second", time.Second, "1 second"},
		{"59 seconds", 59 * time.Second, "59 seconds"},
		{"1 minute", time.Minute, "1 minute"},
		{"1 minute 5 seconds", time.Minute + 5*time.Second, "1 minute 5 seconds"},
		{"59 minutes 5 seconds", 59*time.Minute + 5*time.Second, "59 minutes 5 seconds"},
		{"1 hour", time.Hour, "1 hour"},
		{"1 hour 10 minutes 5 seconds", time.Hour + 10*time.Minute + 5*time.Second, "1 hour 10 minutes 5 seconds"},
		{"2 hours 10 minutes 5 seconds", 2*time.Hour + 10*time.Minute + 5*time.Second, "2 hours 10 minutes 5 seconds"},
		{"0.5 seconds", 500 * time.Millisecond, "0.5 seconds"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DurationToString(tt.duration)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSetLongestDuration(t *testing.T) {
	var longest stats.LongestTime
	start := time.Now()

	// Initial set
	SetLongestDuration(start, 5*time.Second, &longest)
	assert.Equal(t, 5*time.Second, longest.Duration)

	// Shorter duration does not overwrite
	SetLongestDuration(start, 3*time.Second, &longest)
	assert.Equal(t, 5*time.Second, longest.Duration)

	// Longer duration overwrites
	SetLongestDuration(start, 10*time.Second, &longest)
	assert.Equal(t, 10*time.Second, longest.Duration)
}

func TestCalculatePercentile(t *testing.T) {
	samples := []float32{10, 20, 30, 40, 50, 60, 70, 80, 90, 100}

	p50 := CalculatePercentile(samples, 50)
	assert.Equal(t, float32(55), p50)

	p0 := CalculatePercentile(samples, 0)
	assert.Equal(t, float32(10), p0)

	p100 := CalculatePercentile(samples, 100)
	assert.Equal(t, float32(100), p100)

	empty := CalculatePercentile(nil, 50)
	assert.Equal(t, float32(0), empty)
}

func TestCalculateJitter(t *testing.T) {
	samples := []float32{10, 12, 11, 13, 10, 14}
	jitter := CalculateJitter(samples)
	assert.True(t, jitter > 0)

	assert.Equal(t, float32(0), CalculateJitter([]float32{10}))
	assert.Equal(t, float32(0), CalculateJitter(nil))
}

func TestClassifyError(t *testing.T) {
	assert.Equal(t, "Connection Refused", ClassifyError(errors.New("dial tcp 127.0.0.1:80: connectex: No connection could be made because the target machine actively refused it.")))
	assert.Equal(t, "Host Unreachable", ClassifyError(errors.New("dial tcp: host unreachable")))
	assert.Equal(t, "Timeout", ClassifyError(errors.New("context deadline exceeded")))
	assert.Equal(t, "DNS Resolution Failed", ClassifyError(errors.New("lookup example.com: no such host")))
	assert.Equal(t, "", ClassifyError(nil))
}

func TestGenerateSparkline(t *testing.T) {
	samples := []float32{10, 20, 50, 80, 100}
	sl := GenerateSparkline(samples, 10)
	assert.Equal(t, 5, len([]rune(sl)))

	assert.Equal(t, "", GenerateSparkline(nil, 10))
	assert.Equal(t, "▄", GenerateSparkline([]float32{10}, 10))
}
