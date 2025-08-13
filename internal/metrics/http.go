package metrics

import (
	"strconv"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// httpRequestsTotal counts requests by method, route, and status.
	httpRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "guard",
			Subsystem: "http",
			Name:      "requests_total",
			Help:      "Total number of HTTP requests processed.",
		},
		[]string{"method", "route", "status"},
	)

	// httpRequestDurationSeconds observes request latency in seconds.
	httpRequestDurationSeconds = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "guard",
			Subsystem: "http",
			Name:      "request_duration_seconds",
			Help:      "HTTP request duration in seconds.",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"method", "route", "status"},
	)
)

// HTTPMiddleware instruments each request with Prometheus metrics.
func HTTPMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			start := time.Now()
			err := next(c)

			route := c.Path()
			if route == "" {
				route = "unknown"
			}
			method := c.Request().Method
			status := strconv.Itoa(c.Response().Status)

			httpRequestsTotal.WithLabelValues(method, route, status).Inc()
			httpRequestDurationSeconds.WithLabelValues(method, route, status).Observe(time.Since(start).Seconds())

			return err
		}
	}
}
