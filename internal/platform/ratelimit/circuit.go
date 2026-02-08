package ratelimit

import (
	"sync"
	"time"

	"github.com/labstack/echo/v4"
)

// CircuitState represents the state of the circuit breaker.
type CircuitState int

const (
	CircuitClosed   CircuitState = iota // normal operation
	CircuitOpen                         // failing, skip store
	CircuitHalfOpen                     // probing
)

// CircuitBreakerStore wraps a Store with circuit breaker logic.
// After consecutiveFailureThreshold errors, it opens the circuit and fails open
// (allows all requests) for cooldownDuration, then enters half-open to probe.
type CircuitBreakerStore struct {
	inner     Store
	mu        sync.Mutex
	state     CircuitState
	failures  int
	threshold int
	cooldown  time.Duration
	openedAt  time.Time
}

// NewCircuitBreakerStore wraps a Store with a circuit breaker.
// threshold: number of consecutive failures before opening.
// cooldown: how long to stay open before probing.
func NewCircuitBreakerStore(inner Store, threshold int, cooldown time.Duration) *CircuitBreakerStore {
	if threshold <= 0 {
		threshold = 5
	}
	if cooldown <= 0 {
		cooldown = 10 * time.Second
	}
	return &CircuitBreakerStore{
		inner:     inner,
		state:     CircuitClosed,
		threshold: threshold,
		cooldown:  cooldown,
	}
}

func (cb *CircuitBreakerStore) Allow(c echo.Context, key string, limit int, window time.Duration) (bool, int, error) {
	cb.mu.Lock()
	switch cb.state {
	case CircuitOpen:
		if time.Since(cb.openedAt) >= cb.cooldown {
			cb.state = CircuitHalfOpen
			cb.mu.Unlock()
			return cb.probe(c, key, limit, window)
		}
		cb.mu.Unlock()
		// Fail open: allow the request
		return true, 0, nil

	case CircuitHalfOpen:
		cb.mu.Unlock()
		return cb.probe(c, key, limit, window)

	default: // CircuitClosed
		cb.mu.Unlock()
	}

	allowed, retryAfter, err := cb.inner.Allow(c, key, limit, window)
	if err != nil {
		cb.recordFailure()
		// Fail open on error
		return true, 0, nil
	}
	cb.recordSuccess()
	return allowed, retryAfter, nil
}

func (cb *CircuitBreakerStore) probe(c echo.Context, key string, limit int, window time.Duration) (bool, int, error) {
	allowed, retryAfter, err := cb.inner.Allow(c, key, limit, window)
	if err != nil {
		cb.mu.Lock()
		cb.state = CircuitOpen
		cb.openedAt = time.Now()
		cb.mu.Unlock()
		return true, 0, nil
	}
	cb.mu.Lock()
	cb.state = CircuitClosed
	cb.failures = 0
	cb.mu.Unlock()
	return allowed, retryAfter, nil
}

func (cb *CircuitBreakerStore) recordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures++
	if cb.failures >= cb.threshold {
		cb.state = CircuitOpen
		cb.openedAt = time.Now()
	}
}

func (cb *CircuitBreakerStore) recordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures = 0
}
