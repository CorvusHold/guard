//go:build integration
// +build integration

package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/corvusHold/guard/internal/config"
	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
)

func newEchoCtx() echo.Context {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	return e.NewContext(req, rec)
}

func TestNewRedisStore_AndAllowErrorPath(t *testing.T) {
	store := NewRedisStore(config.Config{RedisAddr: "127.0.0.1:0", RedisDB: 0})
	if _, ok := store.(*redisStore); !ok {
		t.Fatal("expected *redisStore")
	}

	allowed, retryAfter, err := store.Allow(newEchoCtx(), "tenant:key", 1, time.Second)
	if err == nil {
		t.Fatal("expected redis error for unreachable redis")
	}
	if allowed {
		t.Fatalf("expected denied on store error for redis fixed-window store, got allowed=%v", allowed)
	}
	if retryAfter != 0 {
		t.Fatalf("expected retryAfter=0 on store error, got %d", retryAfter)
	}
}

func TestNewSlidingWindowStore_AllowFailOpenOnRedisError(t *testing.T) {
	rc := redis.NewClient(&redis.Options{
		Addr:            "127.0.0.1:0",
		DB:              0,
		DialTimeout:     100 * time.Millisecond,
		ReadTimeout:     100 * time.Millisecond,
		WriteTimeout:    100 * time.Millisecond,
		MaxRetries:      0,
		MinRetryBackoff: 1 * time.Millisecond,
		MaxRetryBackoff: 5 * time.Millisecond,
	})
	defer rc.Close()
	store := NewSlidingWindowStore(rc)
	if _, ok := store.(*SlidingWindowStore); !ok {
		t.Fatal("expected *SlidingWindowStore")
	}

	allowed, retryAfter, err := store.Allow(newEchoCtx(), "tenant:key", 1, time.Second)
	if err == nil {
		t.Fatal("expected redis error for unreachable redis")
	}
	if !allowed {
		t.Fatalf("expected fail-open allowed=true on redis errors, got allowed=%v", allowed)
	}
	if retryAfter != 0 {
		t.Fatalf("expected retryAfter=0 on store error, got %d", retryAfter)
	}
}
