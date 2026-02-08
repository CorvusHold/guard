package ratelimit

import (
	"fmt"
	"sync/atomic"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
)

// slidingWindowCounter provides a unique suffix for sorted-set members to prevent collisions.
var slidingWindowCounter atomic.Uint64

// SlidingWindowStore implements a sliding window rate limiter using Redis sorted sets.
// More accurate than fixed-window counters — prevents burst at window boundaries.
type SlidingWindowStore struct {
	client *redis.Client
}

// NewSlidingWindowStore creates a sliding window rate limit store.
func NewSlidingWindowStore(client *redis.Client) *SlidingWindowStore {
	return &SlidingWindowStore{client: client}
}

func (s *SlidingWindowStore) Allow(c echo.Context, key string, limit int, window time.Duration) (bool, int, error) {
	ctx := c.Request().Context()
	now := time.Now()
	windowStart := now.Add(-window)
	seq := slidingWindowCounter.Add(1)
	member := fmt.Sprintf("%d-%d", now.UnixNano(), seq)

	pipe := s.client.Pipeline()
	// Remove expired entries
	pipe.ZRemRangeByScore(ctx, key, "-inf", fmt.Sprintf("%d", windowStart.UnixNano()))
	// Add current request
	pipe.ZAdd(ctx, key, redis.Z{Score: float64(now.UnixNano()), Member: member})
	// Count entries in window
	countCmd := pipe.ZCard(ctx, key)
	// Set expiry on the key
	pipe.Expire(ctx, key, window+time.Second)

	_, err := pipe.Exec(ctx)
	if err != nil {
		return true, 0, err // fail open
	}

	count := countCmd.Val()
	if count > int64(limit) {
		// Over limit — calculate retry-after
		retryAfter := int(window.Seconds())
		return false, retryAfter, nil
	}
	return true, 0, nil
}
