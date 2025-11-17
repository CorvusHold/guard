package service

import (
	"context"
	"testing"
	"time"

	"github.com/corvusHold/guard/internal/config"
	sdomain "github.com/corvusHold/guard/internal/settings/domain"
	"github.com/google/uuid"
)

type fakeSettings struct {
	strings map[string]string
}

func (f fakeSettings) GetString(_ context.Context, key string, tenantID *uuid.UUID, def string) (string, error) {
	if tenantID != nil {
		if v, ok := f.strings[key+":"+tenantID.String()]; ok {
			return v, nil
		}
	}
	if v, ok := f.strings[key]; ok {
		return v, nil
	}
	return def, nil
}

func (f fakeSettings) GetDuration(_ context.Context, _ string, _ *uuid.UUID, def time.Duration) (time.Duration, error) {
	return def, nil
}

func (f fakeSettings) GetInt(_ context.Context, _ string, _ *uuid.UUID, def int) (int, error) {
	return def, nil
}

func TestService_Introspect_UsesTenantSpecificSigningKey(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	userID := uuid.New()

	globalKey := "global-signing-key-123456"
	tenantKey := "tenant-signing-key-abcdef123456"

	repo := &fakeRepo{}

	cfg := config.Config{
		JWTSigningKey:   globalKey,
		AccessTokenTTL:  time.Minute,
		RefreshTokenTTL: time.Hour,
		PublicBaseURL:   "http://example.test",
	}

	settingsWithTenantKey := fakeSettings{strings: map[string]string{
		sdomain.KeyJWTSigning + ":" + tenantID.String(): tenantKey,
	}}

	// Service that issues and introspects tokens using the tenant-specific signing key
	s := &Service{repo: repo, cfg: cfg, settings: settingsWithTenantKey}

	toks, err := s.issueTokens(ctx, userID, tenantID, "", "", nil)
	if err != nil {
		t.Fatalf("issueTokens error: %v", err)
	}
	if toks.AccessToken == "" {
		t.Fatalf("expected non-empty access token")
	}

	out, err := s.Introspect(ctx, toks.AccessToken)
	if err != nil {
		t.Fatalf("Introspect with tenant key error: %v", err)
	}
	if !out.Active {
		t.Fatalf("expected token to be active with tenant-specific signing key")
	}
	if out.UserID != userID || out.TenantID != tenantID {
		t.Fatalf("unexpected introspection context: got user %s tenant %s", out.UserID, out.TenantID)
	}

	// Service that only knows the global signing key (no tenant override)
	settingsGlobalOnly := fakeSettings{strings: map[string]string{}}
	s2 := &Service{repo: repo, cfg: cfg, settings: settingsGlobalOnly}

	out2, err2 := s2.Introspect(ctx, toks.AccessToken)
	if err2 == nil || out2.Active {
		t.Fatalf("expected introspect to fail with global-only signing key; got active=%v err=%v", out2.Active, err2)
	}
}
