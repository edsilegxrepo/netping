package utils

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCalculateBackoff(t *testing.T) {
	cfg := BackoffConfig{
		InitialDelay: 50 * time.Millisecond,
		MaxDelay:     1 * time.Second,
		Multiplier:   2.0,
		Jitter:       false,
	}

	b0 := CalculateBackoff(0, cfg)
	assert.Equal(t, 50*time.Millisecond, b0)

	b1 := CalculateBackoff(1, cfg)
	assert.Equal(t, 100*time.Millisecond, b1)

	b2 := CalculateBackoff(2, cfg)
	assert.Equal(t, 200*time.Millisecond, b2)

	b5 := CalculateBackoff(5, cfg) // 50 * 32 = 1600ms -> capped at 1000ms
	assert.Equal(t, 1*time.Second, b5)
}

func TestCalculateBackoff_WithJitter(t *testing.T) {
	cfg := BackoffConfig{
		InitialDelay: 100 * time.Millisecond,
		MaxDelay:     1 * time.Second,
		Multiplier:   2.0,
		Jitter:       true,
	}

	b := CalculateBackoff(1, cfg) // 200ms -> with jitter should be between 100ms and 200ms
	assert.GreaterOrEqual(t, b, 100*time.Millisecond)
	assert.LessOrEqual(t, b, 200*time.Millisecond)
}

func TestSleepWithContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err := SleepWithContext(ctx, 1*time.Second)
	assert.ErrorIs(t, err, context.Canceled)
}
