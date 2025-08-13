package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// authOutcomesTotal counts authentication outcomes by action and result.
	// Labels:
	// - action: password | magic | mfa | sso
	// - result: success | failure
	authOutcomesTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "guard",
			Subsystem: "auth",
			Name:      "outcomes_total",
			Help:      "Authentication outcomes by action and result.",
		},
		[]string{"action", "result"},
	)

	// mfaOutcomesTotal counts MFA verification outcomes by method and result.
	// Labels:
	// - method: totp | backup_code | unknown
	// - result: success | failure | unknown
	mfaOutcomesTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "guard",
			Subsystem: "auth",
			Name:      "mfa_outcomes_total",
			Help:      "MFA verification outcomes by method and result.",
		},
		[]string{"method", "result"},
	)

	// ssoOutcomesTotal counts SSO outcomes by provider and result.
	// Labels:
	// - provider: workos | dev | other
	// - result: success | failure | unknown
	ssoOutcomesTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "guard",
			Subsystem: "auth",
			Name:      "sso_outcomes_total",
			Help:      "SSO outcomes by provider and result.",
		},
		[]string{"provider", "result"},
	)
)

// IncAuthOutcome increments the auth outcome counter.
func IncAuthOutcome(action, result string) {
	if action == "" {
		action = "unknown"
	}
	if result == "" {
		result = "unknown"
	}
	authOutcomesTotal.WithLabelValues(action, result).Inc()
}

// IncMFAOutcome increments the MFA outcome counter.
func IncMFAOutcome(method, result string) {
	if method == "" {
		method = "unknown"
	}
	if result == "" {
		result = "unknown"
	}
	mfaOutcomesTotal.WithLabelValues(method, result).Inc()
}

// IncSSOOutcome increments the SSO outcome counter.
func IncSSOOutcome(provider, result string) {
	if provider == "" {
		provider = "other"
	}
	if result == "" {
		result = "unknown"
	}
	ssoOutcomesTotal.WithLabelValues(provider, result).Inc()
}
