package ratelimit

import (
	"errors"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
)

// fakeStore is a test double for the Store interface.
type fakeStore struct {
	allowResult bool
	retryAfter  int
	err         error
	callCount   int
}

func (f *fakeStore) Allow(_ echo.Context, _ string, _ int, _ time.Duration) (bool, int, error) {
	f.callCount++
	return f.allowResult, f.retryAfter, f.err
}

func TestCircuitBreaker_ClosedPassesThrough(t *testing.T) {
	inner := &fakeStore{allowResult: true}
	cb := NewCircuitBreakerStore(inner, 3, 100*time.Millisecond)

	allowed, _, err := cb.Allow(nil, "key", 10, time.Minute)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !allowed {
		t.Error("expected allowed=true in closed state")
	}
	if inner.callCount != 1 {
		t.Errorf("expected 1 call to inner, got %d", inner.callCount)
	}
}

func TestCircuitBreaker_ClosedDenied(t *testing.T) {
	inner := &fakeStore{allowResult: false, retryAfter: 5}
	cb := NewCircuitBreakerStore(inner, 3, 100*time.Millisecond)

	allowed, retry, err := cb.Allow(nil, "key", 10, time.Minute)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if allowed {
		t.Error("expected allowed=false when inner denies")
	}
	if retry != 5 {
		t.Errorf("expected retryAfter=5, got %d", retry)
	}
}

func TestCircuitBreaker_OpensAfterThreshold(t *testing.T) {
	inner := &fakeStore{err: errors.New("redis down")}
	cb := NewCircuitBreakerStore(inner, 3, 100*time.Millisecond)

	// Each failure should fail open (allow=true)
	for i := 0; i < 3; i++ {
		allowed, _, err := cb.Allow(nil, "key", 10, time.Minute)
		if err != nil {
			t.Fatalf("iteration %d: unexpected error: %v", i, err)
		}
		if !allowed {
			t.Errorf("iteration %d: expected fail-open (allowed=true)", i)
		}
	}

	// Circuit should now be open — inner should NOT be called
	prevCount := inner.callCount
	allowed, _, err := cb.Allow(nil, "key", 10, time.Minute)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !allowed {
		t.Error("expected fail-open in open state")
	}
	if inner.callCount != prevCount {
		t.Error("inner should not be called when circuit is open")
	}
}

func TestCircuitBreaker_RecoverAfterCooldown(t *testing.T) {
	inner := &fakeStore{err: errors.New("redis down")}
	cb := NewCircuitBreakerStore(inner, 2, 50*time.Millisecond)

	// Trip the circuit
	if _, _, err := cb.Allow(nil, "key", 10, time.Minute); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, _, err := cb.Allow(nil, "key", 10, time.Minute); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Wait for cooldown
	time.Sleep(60 * time.Millisecond)

	// Now fix the inner store
	inner.err = nil
	inner.allowResult = true

	allowed, _, err := cb.Allow(nil, "key", 10, time.Minute)
	if err != nil {
		t.Fatalf("unexpected error after recovery: %v", err)
	}
	if !allowed {
		t.Error("expected allowed=true after recovery")
	}

	// Circuit should be closed again
	cb.mu.Lock()
	state := cb.state
	cb.mu.Unlock()
	if state != CircuitClosed {
		t.Errorf("expected CircuitClosed after recovery, got %d", state)
	}
}

func TestCircuitBreaker_HalfOpenReOpensOnFailure(t *testing.T) {
	inner := &fakeStore{err: errors.New("still down")}
	cb := NewCircuitBreakerStore(inner, 1, 50*time.Millisecond)

	// Trip the circuit
	if _, _, err := cb.Allow(nil, "key", 10, time.Minute); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Wait for cooldown to enter half-open
	time.Sleep(60 * time.Millisecond)

	// Probe fails — should re-open
	allowed, _, err := cb.Allow(nil, "key", 10, time.Minute)
	if err != nil {
		t.Fatalf("unexpected error during half-open probe: %v", err)
	}
	if !allowed {
		t.Error("expected fail-open during half-open probe failure")
	}

	cb.mu.Lock()
	state := cb.state
	cb.mu.Unlock()
	if state != CircuitOpen {
		t.Errorf("expected CircuitOpen after failed probe, got %d", state)
	}
}

func TestCircuitBreaker_SuccessResetsFailures(t *testing.T) {
	inner := &fakeStore{err: errors.New("flaky")}
	cb := NewCircuitBreakerStore(inner, 3, time.Second)

	// 2 failures (below threshold)
	if _, _, err := cb.Allow(nil, "key", 10, time.Minute); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, _, err := cb.Allow(nil, "key", 10, time.Minute); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Now succeed
	inner.err = nil
	inner.allowResult = true
	if _, _, err := cb.Allow(nil, "key", 10, time.Minute); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cb.mu.Lock()
	failures := cb.failures
	cb.mu.Unlock()
	if failures != 0 {
		t.Errorf("expected failures=0 after success, got %d", failures)
	}
}

func TestNewCircuitBreakerStore_Defaults(t *testing.T) {
	inner := &fakeStore{}
	cb := NewCircuitBreakerStore(inner, 0, 0)
	if cb.threshold != 5 {
		t.Errorf("expected default threshold=5, got %d", cb.threshold)
	}
	if cb.cooldown != 10*time.Second {
		t.Errorf("expected default cooldown=10s, got %v", cb.cooldown)
	}
}
