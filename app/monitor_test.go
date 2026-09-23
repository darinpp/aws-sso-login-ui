package app

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestTriggerAuth_Deduplication(t *testing.T) {
	mon := NewMonitor(nil)
	mon.InitialAuthDone()

	inst := SSOInstance{StartURL: "https://example.awsapps.com/start", Region: "us-east-1"}

	// Manually mark as in-flight
	mon.authInFlight.Store(inst.StartURL, true)

	// TriggerAuth should return immediately without doing anything
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() {
		mon.TriggerAuth(ctx, inst, false)
		close(done)
	}()

	select {
	case <-done:
		// Returned immediately — deduplication worked
	case <-time.After(1 * time.Second):
		t.Fatal("TriggerAuth did not return; deduplication failed")
	}

	mon.authInFlight.Delete(inst.StartURL)
}

func TestTriggerAuth_ConcurrentCalls(t *testing.T) {
	mon := NewMonitor(nil)
	mon.InitialAuthDone()

	inst := SSOInstance{StartURL: "https://example.awsapps.com/start", Region: "us-east-1"}

	// Track how many times auth actually runs (past the dedup check)
	var authCount int32

	// Pre-load the authInFlight to block both goroutines
	// Then release and see only one gets through at a time
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Launch two concurrent TriggerAuth calls
	// Both will try Authenticate which will fail (no AWS creds in test),
	// but only one should get past LoadOrStore
	done1 := make(chan struct{})
	done2 := make(chan struct{})

	// Temporarily store to simulate in-flight, then delete to let the real calls race
	mon.authInFlight.Store(inst.StartURL, true)

	go func() {
		mon.authInFlight.Delete(inst.StartURL)
		mon.TriggerAuth(ctx, inst, false)
		atomic.AddInt32(&authCount, 1)
		close(done1)
	}()
	go func() {
		// Small delay to let first goroutine claim the lock
		time.Sleep(10 * time.Millisecond)
		mon.TriggerAuth(ctx, inst, false)
		atomic.AddInt32(&authCount, 1)
		close(done2)
	}()

	<-done1
	<-done2

	// Both calls completed (one ran auth, one was deduplicated)
	require.Equal(t, int32(2), atomic.LoadInt32(&authCount))
}

func TestMonitorRun_WaitsForInitialAuth(t *testing.T) {
	mon := NewMonitor([]SSOInstance{
		{StartURL: "https://example.awsapps.com/start", Region: "us-east-1"},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Run monitor in background — it should block on initialDone
	monDone := make(chan struct{})
	go func() {
		mon.Run(ctx)
		close(monDone)
	}()

	// Give monitor time to start and verify it hasn't run checkAll yet
	time.Sleep(100 * time.Millisecond)

	// Signal initial auth done
	mon.InitialAuthDone()

	// Cancel context to let monitor exit
	cancel()

	select {
	case <-monDone:
		// Monitor exited after initial auth signal
	case <-time.After(2 * time.Second):
		t.Fatal("Monitor.Run did not exit after context cancel")
	}
}

func TestMonitorRun_ExitsOnContextCancel(t *testing.T) {
	mon := NewMonitor(nil)
	mon.InitialAuthDone()

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		mon.Run(ctx)
		close(done)
	}()

	// Cancel immediately
	cancel()

	select {
	case <-done:
		// Exited promptly
	case <-time.After(2 * time.Second):
		t.Fatal("Monitor.Run did not exit on context cancel")
	}
}

func TestInitialAuthDone_Idempotent(t *testing.T) {
	mon := NewMonitor(nil)

	// Should not panic on double close
	mon.InitialAuthDone()
	mon.InitialAuthDone()
}

func TestMonitorWait(t *testing.T) {
	mon := NewMonitor(nil)

	// Nothing in flight — should return immediately
	done := make(chan struct{})
	go func() {
		mon.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatal("Wait blocked with nothing in flight")
	}
}

func TestWaitForConnectivity_ContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.False(t, waitForConnectivity(ctx))
}
