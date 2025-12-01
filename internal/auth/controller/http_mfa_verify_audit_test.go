package controller

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	authrepo "github.com/corvusHold/guard/internal/auth/repository"
	svc "github.com/corvusHold/guard/internal/auth/service"
	"github.com/corvusHold/guard/internal/config"
	evdomain "github.com/corvusHold/guard/internal/events/domain"
	srepo "github.com/corvusHold/guard/internal/settings/repository"
	ssvc "github.com/corvusHold/guard/internal/settings/service"
	trepo "github.com/corvusHold/guard/internal/tenants/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/pquerna/otp/totp"
)

func TestHTTP_MFA_Verify_PublishesAuditEvent(t *testing.T) {
	if os.Getenv("DATABASE_URL") == "" {
		t.Skip("skipping integration test: DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		t.Fatalf("db connect: %v", err)
	}
	defer pool.Close()

	// tenant
	tr := trepo.New(pool)
	tenantID := uuid.New()
	name := "http-mfa-verify-audit-itest-" + tenantID.String()
	if err := tr.Create(ctx, tenantID, name); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	time.Sleep(25 * time.Millisecond)

	// wire services
	repo := authrepo.New(pool)
	sr := srepo.New(pool)
	settings := ssvc.New(sr)
	cfg, _ := config.Load()
	auth := svc.New(repo, cfg, settings)
	// capture events
	events := make([]evdomain.Event, 0, 2)
	auth.SetPublisher(publisherFunc(func(ctx context.Context, e evdomain.Event) error {
		events = append(events, e)
		return nil
	}))
	magic := svc.NewMagic(repo, cfg, settings, &fakeEmail{})
	sso := svc.NewSSO(repo, cfg, settings)

	e := echo.New()
	e.Validator = noopValidator{}
	c := New(auth, magic, sso)
	c.Register(e)

	email := "user.mfa.audit@example.com"
	password := "Password!123"

	// signup
	sBody := map[string]string{
		"tenant_id": tenantID.String(),
		"email":     email,
		"password":  password,
	}
	sb, _ := json.Marshal(sBody)
	sreq := httptest.NewRequest(http.MethodPost, "/v1/auth/password/signup", bytes.NewReader(sb))
	sreq.Header.Set("Content-Type", "application/json")
	srec := httptest.NewRecorder()
	e.ServeHTTP(srec, sreq)
	if srec.Code != http.StatusCreated {
		t.Fatalf("signup expected 201, got %d: %s", srec.Code, srec.Body.String())
	}
	var stoks tokensResponse
	if err := json.NewDecoder(bytes.NewReader(srec.Body.Bytes())).Decode(&stoks); err != nil {
		t.Fatalf("decode tokens: %v", err)
	}

	// enroll + activate TOTP
	reqStart := httptest.NewRequest(http.MethodPost, "/v1/auth/mfa/totp/start", nil)
	reqStart.Header.Set("Authorization", "Bearer "+stoks.AccessToken)
	recStart := httptest.NewRecorder()
	e.ServeHTTP(recStart, reqStart)
	if recStart.Code != http.StatusOK {
		t.Fatalf("totp start expected 200, got %d: %s", recStart.Code, recStart.Body.String())
	}
	var startResp struct{ Secret string }
	_ = json.NewDecoder(bytes.NewReader(recStart.Body.Bytes())).Decode(&startResp)
	code, _ := totp.GenerateCode(startResp.Secret, time.Now())
	ab, _ := json.Marshal(map[string]string{"code": code})
	reqAct := httptest.NewRequest(http.MethodPost, "/v1/auth/mfa/totp/activate", bytes.NewReader(ab))
	reqAct.Header.Set("Authorization", "Bearer "+stoks.AccessToken)
	reqAct.Header.Set("Content-Type", "application/json")
	recAct := httptest.NewRecorder()
	e.ServeHTTP(recAct, reqAct)
	if recAct.Code != http.StatusNoContent {
		t.Fatalf("totp activate expected 204, got %d: %s", recAct.Code, recAct.Body.String())
	}

	// login -> 202 challenge
	lb, _ := json.Marshal(map[string]string{
		"tenant_id": tenantID.String(),
		"email":     email,
		"password":  password,
	})
	lreq := httptest.NewRequest(http.MethodPost, "/v1/auth/password/login", bytes.NewReader(lb))
	lreq.Header.Set("Content-Type", "application/json")
	lreq.Header.Set("User-Agent", "itest-agent")
	lrec := httptest.NewRecorder()
	e.ServeHTTP(lrec, lreq)
	if lrec.Code != http.StatusAccepted {
		t.Fatalf("login expected 202, got %d: %s", lrec.Code, lrec.Body.String())
	}
	var ch mfaChallengeResp
	_ = json.NewDecoder(bytes.NewReader(lrec.Body.Bytes())).Decode(&ch)

	// verify -> 200 and audit event
	vb, _ := json.Marshal(map[string]string{
		"challenge_token": ch.ChallengeToken,
		"method":          "totp",
		"code":            code,
	})
	vreq := httptest.NewRequest(http.MethodPost, "/v1/auth/mfa/verify", bytes.NewReader(vb))
	vreq.Header.Set("Content-Type", "application/json")
	vreq.Header.Set("User-Agent", "itest-agent")
	vrec := httptest.NewRecorder()
	e.ServeHTTP(vrec, vreq)
	if vrec.Code != http.StatusOK {
		t.Fatalf("verify expected 200, got %d: %s", vrec.Code, vrec.Body.String())
	}
	var vtoks tokensResponse
	_ = json.NewDecoder(bytes.NewReader(vrec.Body.Bytes())).Decode(&vtoks)
	if vtoks.AccessToken == "" || vtoks.RefreshToken == "" {
		t.Fatalf("tokens empty: %+v", vtoks)
	}
	// iss/aud claims
	parts := strings.Split(vtoks.AccessToken, ".")
	if len(parts) < 2 {
		t.Fatalf("invalid jwt format")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode jwt payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	if iss, _ := claims["iss"].(string); iss != cfg.PublicBaseURL {
		t.Fatalf("iss mismatch: expected %s, got %v", cfg.PublicBaseURL, claims["iss"])
	}
	if aud, _ := claims["aud"].(string); aud != cfg.PublicBaseURL {
		t.Fatalf("aud mismatch: expected %s, got %v", cfg.PublicBaseURL, claims["aud"])
	}

	// assert audit event emitted with mfa=true
	found := false
	for _, ev := range events {
		if ev.Type == "auth.password.login.success" {
			if ev.Meta["provider"] != "password" {
				t.Fatalf("provider mismatch: %v", ev.Meta["provider"])
			}
			if ev.Meta["mfa"] != "true" {
				t.Fatalf("mfa meta missing/false: %+v", ev.Meta)
			}
			found = true
		}
	}
	if !found {
		t.Fatalf("expected auth.password.login.success event after MFA verify")
	}
}
