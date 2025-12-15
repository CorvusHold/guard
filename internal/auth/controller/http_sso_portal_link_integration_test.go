package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	authrepo "github.com/corvusHold/guard/internal/auth/repository"
	svc "github.com/corvusHold/guard/internal/auth/service"
	ssosvc "github.com/corvusHold/guard/internal/auth/sso/service"
	"github.com/corvusHold/guard/internal/config"
	db "github.com/corvusHold/guard/internal/db/sqlc"
	srepo "github.com/corvusHold/guard/internal/settings/repository"
	ssvc "github.com/corvusHold/guard/internal/settings/service"
	trepo "github.com/corvusHold/guard/internal/tenants/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
)

func toPgUUID(id uuid.UUID) pgtype.UUID {
	return pgtype.UUID{Bytes: id, Valid: true}
}

func toPgText(s string) pgtype.Text {
	return pgtype.Text{String: s, Valid: s != ""}
}

func toPgBool(b bool) pgtype.Bool {
	return pgtype.Bool{Bool: b, Valid: true}
}

func TestHTTP_SSO_PortalLink_NativeProvider_ReturnsInternalPortalURL(t *testing.T) {
	if os.Getenv("DATABASE_URL") == "" {
		t.Skip("skipping integration test: DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		t.Fatalf("db connect: %v", err)
	}
	defer pool.Close()

	tr := trepo.New(pool)
	tenantID := uuid.New()
	name := "http-sso-portal-link-native-" + tenantID.String()
	if err := tr.Create(ctx, tenantID, name); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	time.Sleep(25 * time.Millisecond)

	repo := authrepo.New(pool)
	sr := srepo.New(pool)
	settings := ssvc.New(sr)
	cfg, _ := config.Load()
	auth := svc.New(repo, cfg, settings)
	magic := svc.NewMagic(repo, cfg, settings, &fakeEmail{})
	sso := svc.NewSSO(repo, cfg, settings)

	redisClient := redis.NewClient(&redis.Options{Addr: "127.0.0.1:0"})
	native := ssosvc.New(pool, redisClient, cfg.PublicBaseURL)
	sso.SetSSOProviderService(native)

	e := echo.New()
	e.Validator = noopValidator{}
	c := New(auth, magic, sso)
	c.Register(e)

	adminEmail := "admin.portal.native@example.com"
	password := "Password!123"

	sBody := map[string]string{
		"tenant_id": tenantID.String(),
		"email":     adminEmail,
		"password":  password,
	}
	sb, _ := json.Marshal(sBody)
	sreq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/signup", bytes.NewReader(sb))
	sreq.Header.Set("Content-Type", "application/json")
	sreq.Header.Set("X-Auth-Mode", "bearer")
	srec := httptest.NewRecorder()
	e.ServeHTTP(srec, sreq)
	if srec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", srec.Code, srec.Body.String())
	}
	var adminToks tokensResponse
	if err := json.NewDecoder(srec.Body).Decode(&adminToks); err != nil {
		t.Fatalf("decode tokens: %v", err)
	}
	if adminToks.AccessToken == "" {
		t.Fatalf("expected access token for admin")
	}

	aiAdmin, err := repo.GetAuthIdentityByEmailTenant(ctx, tenantID, adminEmail)
	if err != nil {
		t.Fatalf("lookup admin identity: %v", err)
	}
	if err := auth.UpdateUserRoles(ctx, aiAdmin.UserID, []string{"admin"}); err != nil {
		t.Fatalf("grant admin: %v", err)
	}

	queries := db.New(pool)
	slug := "google"
	_, err = queries.CreateSSOProvider(ctx, db.CreateSSOProviderParams{
		TenantID:     toPgUUID(tenantID),
		Name:         "OIDC Google",
		Slug:         slug,
		ProviderType: "oidc",
		Issuer:       toPgText("https://accounts.google.com"),
		ClientID:     toPgText("client-id"),
		Enabled:      toPgBool(true),
		CreatedBy:    toPgUUID(aiAdmin.UserID),
		UpdatedBy:    toPgUUID(aiAdmin.UserID),
	})
	if err != nil {
		t.Fatalf("create SSO provider: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/sso/"+slug+"/portal-link?tenant_id="+tenantID.String()+"&intent=sso", nil)
	req.Header.Set("Authorization", "Bearer "+adminToks.AccessToken)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Link string `json:"link"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&out); err != nil {
		t.Fatalf("decode portal link: %v", err)
	}
	if out.Link == "" {
		t.Fatal("expected non-empty portal link")
	}

	u, err := url.Parse(out.Link)
	if err != nil {
		t.Fatalf("parse portal link: %v", err)
	}
	if u.Path != "/portal/sso-setup" {
		t.Fatalf("unexpected portal path: %s", u.Path)
	}
	q := u.Query()
	if q.Get("token") == "" {
		t.Fatalf("expected token query param in portal link: %s", out.Link)
	}
	if q.Get("guard-base-url") == "" {
		t.Fatalf("expected guard-base-url query param in portal link: %s", out.Link)
	}
	if got := q.Get("provider"); got != slug {
		t.Fatalf("expected provider=%s, got %s", slug, got)
	}
	if got := q.Get("intent"); got != "sso" {
		t.Fatalf("expected intent=sso, got %s", got)
	}
}
