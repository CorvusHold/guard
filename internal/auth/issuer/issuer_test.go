package issuer

import (
	"testing"

	"github.com/google/uuid"

	"github.com/corvusHold/guard/internal/config"
)

func TestResolveTenantIssuer_PathMode(t *testing.T) {
	tenantID := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	cfg := config.Config{
		PublicBaseURL:    "https://auth.example.com",
		IssuerMode:       ModePath,
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

func TestResolveTenantIssuer_SubdomainMode_EmptyTemplate(t *testing.T) {
	tenantID := uuid.MustParse("44444444-4444-4444-4444-444444444444")
	cfg := config.Config{
		PublicBaseURL:           "https://auth.example.com",
		IssuerMode:              ModeSubdomain,
		IssuerSubdomainTemplate: "",
	}

	if got := ResolveTenantIssuer(cfg, tenantID); got != "" {
		t.Fatalf("ResolveTenantIssuer() = %q, want empty string sentinel", got)
	}
}

func TestResolveTenantIssuer_SubdomainMode_MissingPlaceholder(t *testing.T) {
	tenantID := uuid.MustParse("55555555-5555-5555-5555-555555555555")
	cfg := config.Config{
		PublicBaseURL:           "https://auth.example.com",
		IssuerMode:              ModeSubdomain,
		IssuerSubdomainTemplate: "auth.example.com",
	}

	if got := ResolveTenantIssuer(cfg, tenantID); got != "" {
		t.Fatalf("ResolveTenantIssuer() = %q, want empty string sentinel", got)
	}
}

func TestResolveIssuer_NilTenantID(t *testing.T) {
	cfg := config.Config{PublicBaseURL: "https://auth.example.com"}

	if got := ResolveIssuer(cfg, nil); got != "https://auth.example.com" {
		t.Fatalf("ResolveIssuer(nil) = %q, want %q", got, "https://auth.example.com")
	}
	if got := ResolveJWKSURI(cfg, nil); got != "https://auth.example.com/.well-known/jwks.json" {
		t.Fatalf("ResolveJWKSURI(nil) = %q, want %q", got, "https://auth.example.com/.well-known/jwks.json")
	}
}

func TestResolveIssuer_NilUUID(t *testing.T) {
	cfg := config.Config{PublicBaseURL: "https://auth.example.com"}
	nilID := uuid.Nil

	if got := ResolveIssuer(cfg, &nilID); got != "https://auth.example.com" {
		t.Fatalf("ResolveIssuer(uuid.Nil) = %q, want %q", got, "https://auth.example.com")
	}
}

func TestResolveTenantIssuer_EmptyBaseURL(t *testing.T) {
	tenantID := uuid.MustParse("66666666-6666-6666-6666-666666666666")
	cfg := config.Config{PublicBaseURL: "", IssuerMode: ModePath, IssuerPathPrefix: "/t"}

	if got := ResolveTenantIssuer(cfg, tenantID); got != "" {
		t.Fatalf("ResolveTenantIssuer(empty base) = %q, want empty", got)
	}
	if got := ResolveJWKSURI(cfg, &tenantID); got != "" {
		t.Fatalf("ResolveJWKSURI(empty base) = %q, want empty", got)
	}
}
