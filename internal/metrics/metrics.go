package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// rateLimitExceeded counts HTTP 429 events from the rate limit middleware.
	// Labels:
	// - endpoint: short name like "auth:login", "auth:magic", ...
	// - source:   "tenant" or "ip"
	rateLimitExceeded = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "guard",
			Subsystem: "http",
			Name:      "rate_limit_exceeded_total",
			Help:      "Number of requests rejected due to rate limiting (HTTP 429)",
		},
		[]string{"endpoint", "source"},
	)
)

// IncRateLimitExceeded increments the 429 counter for the given endpoint and source.
func IncRateLimitExceeded(endpoint, source string) {
	if endpoint == "" {
		endpoint = "unknown"
	}
	if source == "" {
		source = "unknown"
	}
	rateLimitExceeded.WithLabelValues(endpoint, source).Inc()
}
