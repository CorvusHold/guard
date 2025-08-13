package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// dbUp is 1 when the last ping to the database succeeded, else 0.
	dbUp = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "guard",
		Subsystem: "db",
		Name:      "up",
		Help:      "Database availability (1=up, 0=down).",
	})
	// dbPingSeconds observes database ping latency in seconds.
	dbPingSeconds = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: "guard",
		Subsystem: "db",
		Name:      "ping_seconds",
		Help:      "Database ping latency in seconds.",
		Buckets:   prometheus.DefBuckets,
	})

	// redisUp is 1 when the last ping to Redis/Valkey succeeded, else 0.
	redisUp = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "guard",
		Subsystem: "redis",
		Name:      "up",
		Help:      "Redis/Valkey availability (1=up, 0=down).",
	})
	// redisPingSeconds observes redis ping latency in seconds.
	redisPingSeconds = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: "guard",
		Subsystem: "redis",
		Name:      "ping_seconds",
		Help:      "Redis/Valkey ping latency in seconds.",
		Buckets:   prometheus.DefBuckets,
	})
)

// SetDBUp sets the db_up gauge to 1/0.
func SetDBUp(up bool) {
	if up {
		dbUp.Set(1)
		return
	}
	dbUp.Set(0)
}

// ObserveDBPing records a database ping latency in seconds.
func ObserveDBPing(seconds float64) { dbPingSeconds.Observe(seconds) }

// SetRedisUp sets the redis_up gauge to 1/0.
func SetRedisUp(up bool) {
	if up {
		redisUp.Set(1)
		return
	}
	redisUp.Set(0)
}

// ObserveRedisPing records a redis ping latency in seconds.
func ObserveRedisPing(seconds float64) { redisPingSeconds.Observe(seconds) }
