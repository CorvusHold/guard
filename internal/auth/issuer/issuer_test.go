package issuer

import (
	"testing"

	"github.com/google/uuid"

	"github.com/corvusHold/guard/internal/config"
)

func TestResolveTenantIssuer_PathMode(t *testing.T) {
	tenantID := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	cfg := config.Config{
		PublicBaseURL:   "https://auth.example.com",
		IssuerMode:      ModePath,
		IssuerPathPrefix: "/t",
	}

	got := ResolveTenantIssuer(cfg, tenantID)
	want := "https://auth.example.com/t/11111111-1111-1111-1111-111111111111"
	if got != want {
		t.Fatalf("ResolveTenantIssuer() = %q, want %q", got, want)
	}
}

func TestResolveTenantIssuer_SubdomainMode(t *testing.T) {
	tenantID := uuid.MustParse("22222222-2222-2222-2222-222222222222")
	cfg := config.Config{
		PublicBaseURL:           "https://auth.example.com",
		IssuerMode:              ModeSubdomain,
		IssuerSubdomainTemplate: "{tenant}.auth.example.com",
	}

	got := ResolveTenantIssuer(cfg, tenantID)
	want := "https://22222222-2222-2222-2222-222222222222.auth.example.com"
	if got != want {
		t.Fatalf("ResolveTenantIssuer() = %q, want %q", got, want)
	}
}

func TestResolveJWKSURI_PathMode(t *testing.T) {
	tenantID := uuid.MustParse("33333333-3333-3333-3333-333333333333")
	cfg := config.Config{PublicBaseURL: "https://auth.example.com", IssuerMode: ModePath, IssuerPathPrefix: "/t"}

	got := ResolveJWKSURI(cfg, &tenantID)
	want := "https://auth.example.com/t/33333333-3333-3333-3333-333333333333/.well-known/jwks.json"
	if got != want {
		t.Fatalf("ResolveJWKSURI() = %q, want %q", got, want)
	}
}
