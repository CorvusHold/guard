//go:build integration

package controller

import (
    "bytes"
    "context"
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "os"
    "testing"

    authrepo "github.com/corvusHold/guard/internal/auth/repository"
    svc "github.com/corvusHold/guard/internal/auth/service"
    "github.com/corvusHold/guard/internal/config"
    srepo "github.com/corvusHold/guard/internal/settings/repository"
    ssvc "github.com/corvusHold/guard/internal/settings/service"
    trepo "github.com/corvusHold/guard/internal/tenants/repository"
    "github.com/google/uuid"
    "github.com/jackc/pgx/v5/pgxpool"
    "github.com/labstack/echo/v4"
    "github.com/stretchr/testify/require"
)

// TestBlockedUserBehavior verifies blocked users cannot login, refresh, or access /me/introspect.
func TestBlockedUserBehavior(t *testing.T) {
    if os.Getenv("DATABASE_URL") == "" {
        t.Skip("skipping integration test: DATABASE_URL not set")
    }

    ctx := context.Background()
    pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
    require.NoError(t, err)
    defer pool.Close()

    // Create tenant
    tr := trepo.New(pool)
    tenantID := uuid.New()
    require.NoError(t, tr.Create(ctx, tenantID, "blocked-user-test-"+tenantID.String(), nil))

    // Services
    repo := authrepo.New(pool)
    sr := srepo.New(pool)
    settings := ssvc.New(sr)
    cfg, err := config.Load()
    require.NoError(t, err)
    auth := svc.New(repo, cfg, settings)
    magic := svc.NewMagic(repo, cfg, settings, &fakeEmail{})
    sso := svc.NewSSO(repo, cfg, settings)

    e := echo.New()
    e.Validator = noopValidator{}
    c := New(auth, magic, sso)
    c.Register(e)

    email := "blocked-user@example.com"
    password := "BlockedPass123!"

    // Signup to obtain tokens
    sBody := map[string]string{
        "tenant_id": tenantID.String(),
        "email":     email,
        "password":  password,
    }
    sb, _ := json.Marshal(sBody)
    sreq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/signup", bytes.NewReader(sb))
    sreq.Header.Set("Content-Type", "application/json")
    srec := httptest.NewRecorder()
    e.ServeHTTP(srec, sreq)
    require.Equal(t, http.StatusCreated, srec.Code)

    var toks struct {
        AccessToken  string `json:"access_token"`
        RefreshToken string `json:"refresh_token"`
    }
    require.NoError(t, json.NewDecoder(bytes.NewReader(srec.Body.Bytes())).Decode(&toks))
    require.NotEmpty(t, toks.AccessToken)
    require.NotEmpty(t, toks.RefreshToken)

    // Get user ID from introspection (before blocking)
    intr, err := auth.Introspect(ctx, toks.AccessToken)
    require.NoError(t, err)
    userID := intr.UserID

    // Block the user
    require.NoError(t, repo.SetUserActive(ctx, userID, false))

    // Login should now fail with 401
    lBody := map[string]string{
        "tenant_id": tenantID.String(),
        "email":     email,
        "password":  password,
    }
    lb, _ := json.Marshal(lBody)
    lreq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/login", bytes.NewReader(lb))
    lreq.Header.Set("Content-Type", "application/json")
    lrec := httptest.NewRecorder()
    e.ServeHTTP(lrec, lreq)
    require.Equal(t, http.StatusUnauthorized, lrec.Code, "blocked login should be unauthorized: %s", lrec.Body.String())

    // Refresh should fail with 401
    rBody := map[string]string{"refresh_token": toks.RefreshToken}
    rb, _ := json.Marshal(rBody)
    rreq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewReader(rb))
    rreq.Header.Set("Content-Type", "application/json")
    rrec := httptest.NewRecorder()
    e.ServeHTTP(rrec, rreq)
    require.Equal(t, http.StatusUnauthorized, rrec.Code, "blocked refresh should be unauthorized: %s", rrec.Body.String())

    // /me should fail with 401
    mreq := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
    mreq.Header.Set("Authorization", "Bearer "+toks.AccessToken)
    mrec := httptest.NewRecorder()
    e.ServeHTTP(mrec, mreq)
    require.Equal(t, http.StatusUnauthorized, mrec.Code, "blocked /me should be unauthorized: %s", mrec.Body.String())

    // /introspect should return 401
    ireq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/introspect", nil)
    ireq.Header.Set("Authorization", "Bearer "+toks.AccessToken)
    irec := httptest.NewRecorder()
    e.ServeHTTP(irec, ireq)
    require.Equal(t, http.StatusUnauthorized, irec.Code, "blocked introspect should be unauthorized: %s", irec.Body.String())
}
