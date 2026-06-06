package integration

import (
	"testing"

	"go.uber.org/goleak"
)

// TestMain runs all integration tests and then asserts no goroutines leaked.
// Each harness tears down its hub and HTTP server via t.Cleanup before this
// runs, so a leak here means a per-connection goroutine (read/write/monitor) or
// a close-path goroutine was not reaped — the failure mode the 24h soak guards
// against.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m,
		// coder/websocket and the Go HTTP server keep transient timers; the
		// default ignores cover testing/runtime internals.
		goleak.IgnoreTopFunction("internal/poll.runtime_pollWait"),
	)
}
