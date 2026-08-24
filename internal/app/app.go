// Package app provides application-level lifecycle management and cross-platform OS signal handling.
//
// Objectives:
//   - Gracefully trap SIGINT (Ctrl+C) and SIGTERM OS signals across Windows and Linux.
//   - Propagate cancellation via standard context.Context to running probers, listeners, and TUI loops.
//
// Core Components:
//   - SetupSignalHandler: Constructs a signal-notified context for deterministic process shutdown.
package app

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

// SetupSignalHandler catches SIGINT and SIGTERM and returns a context that is cancelled on signal.
func SetupSignalHandler(ctx context.Context) (context.Context, context.CancelFunc) {
	return signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
}
