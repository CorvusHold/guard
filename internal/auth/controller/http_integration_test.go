package controller

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	svc "github.com/corvusHold/guard/internal/auth/service"
	authrepo "github.com/corvusHold/guard/internal/auth/repository"
	"github.com/corvusHold/guard/internal/config"
	edomain "github.com/corvusHold/guard/internal/email/domain"
	evdomain "github.com/corvusHold/guard/internal/events/domain"
	srepo "github.com/corvusHold/guard/internal/settings/repository"
	ssvc "github.com/corvusHold/guard/internal/settings/service"
	trepo "github.com/corvusHold/guard/internal/tenants/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

type fakeEmail struct{ lastBody string }

func TestHTTP_Password_Signup_Login_Refresh_AuditAndClaims(t *testing.T) {
    if os.Getenv("DATABASE_URL") == "" {
        t.Skip("skipping integration test: DATABASE_URL not set")
    }
    ctx := context.Background()
    pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
    if err != nil { t.Fatalf("db connect: %v", err) }
    defer pool.Close()

    // tenant
    tr := trepo.New(pool)
    tenantID := uuid.New()
    name := "http-password-itest-" + tenantID.String()
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
    // capture audit events
    events := make([]evdomain.Event, 0, 3)
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

    email := "user.pass.itest@example.com"
    password := "Password!123"

    // POST /v1/auth/password/signup
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
        t.Fatalf("expected 201, got %d: %s", srec.Code, srec.Body.String())
    }
    var stoks tokensResponse
    if err := json.NewDecoder(bytes.NewReader(srec.Body.Bytes())).Decode(&stoks); err != nil {
        t.Fatalf("decode tokens: %v", err)
    }
    if stoks.AccessToken == "" || stoks.RefreshToken == "" {
        t.Fatalf("expected non-empty tokens: %+v", stoks)
    }
    // iss/aud
    sparts := strings.Split(stoks.AccessToken, ".")
    if len(sparts) < 2 { t.Fatalf("invalid jwt format") }
    spayload, err := base64.RawURLEncoding.DecodeString(sparts[1])
    if err != nil { t.Fatalf("decode jwt payload: %v", err) }
    var sclaims map[string]any
    if err := json.Unmarshal(spayload, &sclaims); err != nil { t.Fatalf("unmarshal claims: %v", err) }
    if iss, _ := sclaims["iss"].(string); iss != os.Getenv("PUBLIC_BASE_URL") { t.Fatalf("iss mismatch: %v", sclaims["iss"]) }
    if aud, _ := sclaims["aud"].(string); aud != os.Getenv("PUBLIC_BASE_URL") { t.Fatalf("aud mismatch: %v", sclaims["aud"]) }

    // POST /v1/auth/password/login
    lBody := map[string]string{
        "tenant_id": tenantID.String(),
        "email":     email,
        "password":  password,
    }
    lb, _ := json.Marshal(lBody)
    lreq := httptest.NewRequest(http.MethodPost, "/v1/auth/password/login", bytes.NewReader(lb))
    lreq.Header.Set("Content-Type", "application/json")
    lreq.Header.Set("User-Agent", "itest-agent")
    lrec := httptest.NewRecorder()
    e.ServeHTTP(lrec, lreq)
    if lrec.Code != http.StatusOK {
        t.Fatalf("expected 200, got %d: %s", lrec.Code, lrec.Body.String())
    }
    var ltoks tokensResponse
    if err := json.NewDecoder(bytes.NewReader(lrec.Body.Bytes())).Decode(&ltoks); err != nil {
        t.Fatalf("decode tokens: %v", err)
    }
    if ltoks.AccessToken == "" || ltoks.RefreshToken == "" {
        t.Fatalf("expected non-empty tokens: %+v", ltoks)
    }
    // iss/aud
    lparts := strings.Split(ltoks.AccessToken, ".")
    if len(lparts) < 2 { t.Fatalf("invalid jwt format") }
    lpayload, err := base64.RawURLEncoding.DecodeString(lparts[1])
    if err != nil { t.Fatalf("decode jwt payload: %v", err) }
    var lclaims map[string]any
    if err := json.Unmarshal(lpayload, &lclaims); err != nil { t.Fatalf("unmarshal claims: %v", err) }
    if iss, _ := lclaims["iss"].(string); iss != os.Getenv("PUBLIC_BASE_URL") { t.Fatalf("iss mismatch: %v", lclaims["iss"]) }
    if aud, _ := lclaims["aud"].(string); aud != os.Getenv("PUBLIC_BASE_URL") { t.Fatalf("aud mismatch: %v", lclaims["aud"]) }

    // Assert audit event for password login
    foundLogin := false
    for _, ev := range events {
        if ev.Type == "auth.password.login.success" {
            if ev.Meta["provider"] != "password" { t.Fatalf("provider mismatch: %v", ev.Meta["provider"]) }
            if ev.Meta["email"] != email { t.Fatalf("email mismatch: %v", ev.Meta["email"]) }
            foundLogin = true
        }
    }
    if !foundLogin { t.Fatalf("expected auth.password.login.success event") }

    // POST /v1/auth/refresh
    rBody := map[string]string{
        "refresh_token": ltoks.RefreshToken,
    }
    rb, _ := json.Marshal(rBody)
    rreq := httptest.NewRequest(http.MethodPost, "/v1/auth/refresh", bytes.NewReader(rb))
    rreq.Header.Set("Content-Type", "application/json")
    rrec := httptest.NewRecorder()
    e.ServeHTTP(rrec, rreq)
    if rrec.Code != http.StatusOK {
        t.Fatalf("expected 200, got %d: %s", rrec.Code, rrec.Body.String())
    }
    var rtoks tokensResponse
    if err := json.NewDecoder(bytes.NewReader(rrec.Body.Bytes())).Decode(&rtoks); err != nil {
        t.Fatalf("decode tokens: %v", err)
    }
    if rtoks.AccessToken == "" || rtoks.RefreshToken == "" {
        t.Fatalf("expected non-empty tokens: %+v", rtoks)
    }
    // Assert refresh audit event
    foundRefresh := false
    for _, ev := range events {
        if ev.Type == "auth.token.refresh.success" { foundRefresh = true }
    }
    if !foundRefresh { t.Fatalf("expected auth.token.refresh.success event") }
}

func (f *fakeEmail) Send(ctx context.Context, tenantID uuid.UUID, to, subject, body string) error {
	f.lastBody = body
	return nil
}

var _ edomain.Sender = (*fakeEmail)(nil)

type noopValidator struct{}

func (noopValidator) Validate(i interface{}) error { return nil }

type tokensResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// publisherFunc helps implement evdomain.Publisher in tests via a func.
type publisherFunc func(ctx context.Context, e evdomain.Event) error

func (f publisherFunc) Publish(ctx context.Context, e evdomain.Event) error { return f(ctx, e) }

func TestHTTP_Magic_SendAndVerify(t *testing.T) {
	if os.Getenv("DATABASE_URL") == "" {
		t.Skip("skipping integration test: DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil { t.Fatalf("db connect: %v", err) }
	defer pool.Close()

	// tenant
	tr := trepo.New(pool)
	tenantID := uuid.New()
	name := "http-magic-itest-" + tenantID.String()
	if err := tr.Create(ctx, tenantID, name); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	time.Sleep(25 * time.Millisecond)

	// wire services
	repo := authrepo.New(pool)
	sr := srepo.New(pool)
	settings := ssvc.New(sr)
	cfg, _ := config.Load()
	fe := &fakeEmail{}
	magic := svc.NewMagic(repo, cfg, settings, fe)
	auth := svc.New(repo, cfg, settings)
	sso := svc.NewSSO(repo, cfg, settings)

	e := echo.New()
	e.Validator = noopValidator{}
	c := New(auth, magic, sso)
	c.Register(e)

	// POST /v1/auth/magic/send
	body := map[string]string{
		"tenant_id": tenantID.String(),
		"email":     "user.http.itest@example.com",
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/magic/send", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", rec.Code, rec.Body.String())
	}
	if fe.lastBody == "" { t.Fatalf("expected email sent body captured") }

	// extract token
	re := regexp.MustCompile(`token=([A-Za-z0-9_-]+)`) 
	m := re.FindStringSubmatch(fe.lastBody)
	if len(m) < 2 { t.Fatalf("token not found in body: %q", fe.lastBody) }
	token := m[1]

	// GET /v1/auth/magic/verify
	req2 := httptest.NewRequest(http.MethodGet, "/v1/auth/magic/verify?token="+token, nil)
	rec2 := httptest.NewRecorder()
	e.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec2.Code, rec2.Body.String())
	}
	var trsp tokensResponse
	if err := json.NewDecoder(bytes.NewReader(rec2.Body.Bytes())).Decode(&trsp); err != nil {
		t.Fatalf("decode tokens: %v", err)
	}
	if trsp.AccessToken == "" || trsp.RefreshToken == "" {
		t.Fatalf("expected non-empty tokens: %+v", trsp)
	}
}
