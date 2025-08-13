package ratelimit

import (
    "time"

    "github.com/labstack/echo/v4"
    "github.com/redis/go-redis/v9"

    "github.com/corvusHold/guard/internal/config"
)

// redisStore implements Store using Redis INCR/PEXPIRE and PTTL.
type redisStore struct{ rc *redis.Client }

// NewRedisStore creates a Store backed by Redis using app config.
func NewRedisStore(cfg config.Config) Store {
    rc := redis.NewClient(&redis.Options{Addr: cfg.RedisAddr, DB: cfg.RedisDB})
    return &redisStore{rc: rc}
}

var luaFixedWindow = redis.NewScript(`
local current = redis.call('INCR', KEYS[1])
if current == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end
local ttl = redis.call('PTTL', KEYS[1])
return {current, ttl}
`)

func (s *redisStore) Allow(c echo.Context, key string, limit int, window time.Duration) (bool, int, error) {
    ctx := c.Request().Context()
    // namespace keys for safety
    k := "rl:" + key
    ms := window.Milliseconds()
    res, err := luaFixedWindow.Run(ctx, s.rc, []string{k}, ms).Result()
    if err != nil {
        return false, 0, err
    }
    arr, ok := res.([]interface{})
    if !ok || len(arr) != 2 {
        return false, 0, nil
    }
    var current int64
    var ttlms int64
    switch v := arr[0].(type) {
    case int64:
        current = v
    case uint64:
        current = int64(v)
    default:
        current = 0
    }
    switch v := arr[1].(type) {
    case int64:
        ttlms = v
    case uint64:
        ttlms = int64(v)
    default:
        ttlms = 0
    }
    if current <= int64(limit) {
        return true, 0, nil
    }
    // compute retry-after seconds (ceil(ttl/1000))
    if ttlms <= 0 {
        return false, 0, nil
    }
    secs := int((ttlms + 999) / 1000)
    return false, secs, nil
}
