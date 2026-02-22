package metrics

import (
	"testing"

	io_prometheus_client "github.com/prometheus/client_model/go"
)

func readCounterValue(t *testing.T, metric interface {
	Write(*io_prometheus_client.Metric) error
}) float64 {
	t.Helper()
	m := &io_prometheus_client.Metric{}
	if err := metric.Write(m); err != nil {
		t.Fatalf("write metric: %v", err)
	}
	if m.Counter == nil {
		t.Fatal("expected counter metric")
	}
	return m.Counter.GetValue()
}

func readGaugeValue(t *testing.T, metric interface {
	Write(*io_prometheus_client.Metric) error
}) float64 {
	t.Helper()
	m := &io_prometheus_client.Metric{}
	if err := metric.Write(m); err != nil {
		t.Fatalf("write metric: %v", err)
	}
	if m.Gauge == nil {
		t.Fatal("expected gauge metric")
	}
	return m.Gauge.GetValue()
}

func readHistogramCount(t *testing.T, metric interface {
	Write(*io_prometheus_client.Metric) error
}) uint64 {
	t.Helper()
	m := &io_prometheus_client.Metric{}
	if err := metric.Write(m); err != nil {
		t.Fatalf("write metric: %v", err)
	}
	if m.Histogram == nil {
		t.Fatal("expected histogram metric")
	}
	return m.Histogram.GetSampleCount()
}

func TestIncRateLimitExceeded_DefaultLabelsFallback(t *testing.T) {
	before := readCounterValue(t, rateLimitExceeded.WithLabelValues("unknown", "unknown"))
	IncRateLimitExceeded("", "")
	after := readCounterValue(t, rateLimitExceeded.WithLabelValues("unknown", "unknown"))
	if after != before+1 {
		t.Fatalf("expected rate-limit counter increment by 1, before=%v after=%v", before, after)
	}
}

func TestIncSSOInitiate_UsesProvidedLabels(t *testing.T) {
	before := readCounterValue(t, ssoInitiateCounter.WithLabelValues("oidc", "workos", "tenant-1"))
	IncSSOInitiate("oidc", "workos", "tenant-1")
	after := readCounterValue(t, ssoInitiateCounter.WithLabelValues("oidc", "workos", "tenant-1"))
	if after != before+1 {
		t.Fatalf("expected sso initiate increment by 1, before=%v after=%v", before, after)
	}
}

func TestIncSSOCallback_DefaultLabelsFallback(t *testing.T) {
	before := readCounterValue(t, ssoCallbackCounter.WithLabelValues("unknown", "unknown", "unknown"))
	IncSSOCallback("", "", "")
	after := readCounterValue(t, ssoCallbackCounter.WithLabelValues("unknown", "unknown", "unknown"))
	if after != before+1 {
		t.Fatalf("expected sso callback increment by 1, before=%v after=%v", before, after)
	}
}

func TestObserveSSOAuthDuration_AndGaugeSet(t *testing.T) {
	obs, err := ssoAuthDuration.GetMetricWithLabelValues("unknown", "unknown")
	if err != nil {
		t.Fatalf("get histogram metric: %v", err)
	}
	writable, ok := obs.(interface {
		Write(*io_prometheus_client.Metric) error
	})
	if !ok {
		t.Fatal("histogram observer does not expose write method")
	}

	beforeCount := readHistogramCount(t, writable)
	ObserveSSOAuthDuration("", "", 0.42)
	afterCount := readHistogramCount(t, writable)
	if afterCount != beforeCount+1 {
		t.Fatalf("expected histogram sample count increment by 1, before=%v after=%v", beforeCount, afterCount)
	}

	SetSSOProviderCount("", "", 7)
	if got := readGaugeValue(t, ssoProviderCount.WithLabelValues("unknown", "unknown")); got != 7 {
		t.Fatalf("expected sso provider gauge to be 7, got %v", got)
	}
}

func TestIncRateLimitExceeded_UsesProvidedLabels(t *testing.T) {
	before := readCounterValue(t, rateLimitExceeded.WithLabelValues("auth:login", "tenant"))
	IncRateLimitExceeded("auth:login", "tenant")
	after := readCounterValue(t, rateLimitExceeded.WithLabelValues("auth:login", "tenant"))
	if after != before+1 {
		t.Fatalf("expected provided-label counter increment by 1, before=%v after=%v", before, after)
	}
}

func TestIncSSOInitiate_DefaultFallbackLabels(t *testing.T) {
	before := readCounterValue(t, ssoInitiateCounter.WithLabelValues("unknown", "unknown", "unknown"))
	IncSSOInitiate("", "", "")
	after := readCounterValue(t, ssoInitiateCounter.WithLabelValues("unknown", "unknown", "unknown"))
	if after != before+1 {
		t.Fatalf("expected defaulted sso initiate increment by 1, before=%v after=%v", before, after)
	}
}

func TestIncSSOCallback_UsesProvidedLabels(t *testing.T) {
	before := readCounterValue(t, ssoCallbackCounter.WithLabelValues("oidc", "workos", "success"))
	IncSSOCallback("oidc", "workos", "success")
	after := readCounterValue(t, ssoCallbackCounter.WithLabelValues("oidc", "workos", "success"))
	if after != before+1 {
		t.Fatalf("expected provided-label callback increment by 1, before=%v after=%v", before, after)
	}
}

func TestObserveSSOAuthDuration_ProvidedLabelsAndGaugeLabels(t *testing.T) {
	obs, err := ssoAuthDuration.GetMetricWithLabelValues("oidc", "success")
	if err != nil {
		t.Fatalf("get histogram metric: %v", err)
	}
	writable, ok := obs.(interface {
		Write(*io_prometheus_client.Metric) error
	})
	if !ok {
		t.Fatal("histogram observer does not expose write method")
	}

	before := readHistogramCount(t, writable)
	ObserveSSOAuthDuration("oidc", "success", 0.99)
	after := readHistogramCount(t, writable)
	if after != before+1 {
		t.Fatalf("expected provided-label histogram sample increment by 1, before=%v after=%v", before, after)
	}

	SetSSOProviderCount("oidc", "true", 3)
	if got := readGaugeValue(t, ssoProviderCount.WithLabelValues("oidc", "true")); got != 3 {
		t.Fatalf("expected provided-label gauge to be 3, got %v", got)
	}
}
