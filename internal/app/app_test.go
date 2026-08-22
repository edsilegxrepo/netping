package app

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSetupSignalHandler(t *testing.T) {
	ctx, cancel := SetupSignalHandler(context.Background())
	defer cancel()

	assert.NotNil(t, ctx)
	assert.NoError(t, ctx.Err())

	// Test cancellation
	cancel()
	assert.ErrorIs(t, ctx.Err(), context.Canceled)
}
