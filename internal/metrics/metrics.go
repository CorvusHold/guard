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

	// ssoInitiateCounter counts SSO initiation requests.
	// Labels:
	// - provider_type: "oidc" or "saml"
	// - provider_slug: the slug of the provider
	// - tenant_id: the tenant ID
	ssoInitiateCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "guard",
			Subsystem: "sso",
			Name:      "initiate_total",
			Help:      "Total number of SSO initiation requests",
		},
		[]string{"provider_type", "provider_slug", "tenant_id"},
	)

	// ssoCallbackCounter counts SSO callback requests.
	// Labels:
	// - provider_type: "oidc" or "saml"
	// - provider_slug: the slug of the provider
	// - status: "success" or "failure"
	ssoCallbackCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "guard",
			Subsystem: "sso",
			Name:      "callback_total",
			Help:      "Total number of SSO callbacks",
		},
		[]string{"provider_type", "provider_slug", "status"},
	)

	// ssoAuthDuration tracks the duration of SSO authentication flows.
	// Labels:
	// - provider_type: "oidc" or "saml"
	// - status: "success" or "failure"
	ssoAuthDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "guard",
			Subsystem: "sso",
			Name:      "auth_duration_seconds",
			Help:      "Duration of SSO authentication flow",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"provider_type", "status"},
	)

	// ssoProviderCount tracks the number of active SSO providers.
	// Labels:
	// - provider_type: "oidc" or "saml"
	// - enabled: "true" or "false"
	ssoProviderCount = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "guard",
			Subsystem: "sso",
			Name:      "providers_count",
			Help:      "Number of SSO providers by type and status",
		},
		[]string{"provider_type", "enabled"},
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

// IncSSOInitiate increments the SSO initiation counter.
func IncSSOInitiate(providerType, providerSlug, tenantID string) {
	if providerType == "" {
		providerType = "unknown"
	}
	if providerSlug == "" {
		providerSlug = "unknown"
	}
	if tenantID == "" {
		tenantID = "unknown"
	}
	ssoInitiateCounter.WithLabelValues(providerType, providerSlug, tenantID).Inc()
}

// IncSSOCallback increments the SSO callback counter.
func IncSSOCallback(providerType, providerSlug, status string) {
	if providerType == "" {
		providerType = "unknown"
	}
	if providerSlug == "" {
		providerSlug = "unknown"
	}
	if status == "" {
		status = "unknown"
	}
	ssoCallbackCounter.WithLabelValues(providerType, providerSlug, status).Inc()
}

// ObserveSSOAuthDuration observes the duration of an SSO authentication flow.
func ObserveSSOAuthDuration(providerType, status string, duration float64) {
	if providerType == "" {
		providerType = "unknown"
	}
	if status == "" {
		status = "unknown"
	}
	ssoAuthDuration.WithLabelValues(providerType, status).Observe(duration)
}

// SetSSOProviderCount sets the number of SSO providers.
func SetSSOProviderCount(providerType, enabled string, count float64) {
	if providerType == "" {
		providerType = "unknown"
	}
	if enabled == "" {
		enabled = "unknown"
	}
	ssoProviderCount.WithLabelValues(providerType, enabled).Set(count)
}
