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
