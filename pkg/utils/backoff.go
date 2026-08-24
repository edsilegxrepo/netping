package utils

import (
	"context"
	crand "crypto/rand"
	"math"
	"math/big"
	"time"
)

type BackoffConfig struct {
	InitialDelay time.Duration
	MaxDelay     time.Duration
	Multiplier   float64
	Jitter       bool
}

// DefaultBackoffConfig returns standard exponential backoff defaults.
func DefaultBackoffConfig() BackoffConfig {
	return BackoffConfig{
		InitialDelay: 50 * time.Millisecond,
		MaxDelay:     2 * time.Second,
		Multiplier:   2.0,
		Jitter:       true,
	}
}

// CalculateBackoff computes exponential backoff with optional full jitter for retry attempts.
func CalculateBackoff(attempt int, cfg BackoffConfig) time.Duration {
	if cfg.InitialDelay <= 0 {
		cfg.InitialDelay = 50 * time.Millisecond
	}
	if cfg.Multiplier <= 1.0 {
		cfg.Multiplier = 2.0
	}

	if attempt < 0 {
		attempt = 0
	}

	delay := float64(cfg.InitialDelay) * math.Pow(cfg.Multiplier, float64(attempt))
	if cfg.MaxDelay > 0 && delay > float64(cfg.MaxDelay) {
		delay = float64(cfg.MaxDelay)
	}

	if cfg.Jitter && delay > 0 {
		// Full jitter: randomized between 50% and 100% of the computed backoff
		randFraction := 0.5
		if n, err := crand.Int(crand.Reader, big.NewInt(10000)); err == nil {
			randFraction = float64(n.Int64()) / 10000.0
		}
		factor := 0.5 + (0.5 * randFraction)
		delay = delay * factor
	}

	return time.Duration(delay)
}

// SleepWithContext sleeps for the specified duration or wakes early if ctx is cancelled.
func SleepWithContext(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
