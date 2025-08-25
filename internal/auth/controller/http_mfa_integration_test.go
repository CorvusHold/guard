package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	authrepo "github.com/corvusHold/guard/internal/auth/repository"
	svc "github.com/corvusHold/guard/internal/auth/service"
	"github.com/corvusHold/guard/internal/config"
	srepo "github.com/corvusHold/guard/internal/settings/repository"
	ssvc "github.com/corvusHold/guard/internal/settings/service"
	trepo "github.com/corvusHold/guard/internal/tenants/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/pquerna/otp/totp"
)

// Helper to spin up Echo with wired services and return tenantID and tokens
func setupAuthApp(t *testing.T) (*echo.Echo, uuid.UUID, tokensResponse) {
	t.Helper()
	if os.Getenv("DATABASE_URL") == "" {
		t.Skip("skipping integration test: DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		t.Fatalf("db connect: %v", err)
	}
	// closing handled by t.Cleanup
	t.Cleanup(func() { pool.Close() })

	// tenant
	tr := trepo.New(pool)
	tenantID := uuid.New()
	name := "http-mfa-itest-" + tenantID.String()
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
	magic := svc.NewMagic(repo, cfg, settings, &fakeEmail{})
	sso := svc.NewSSO(repo, cfg, settings)

	e := echo.New()
	e.Validator = noopValidator{}
	c := New(auth, magic, sso)
	c.Register(e)

	// signup to get bearer
	email := "user.mfa.itest@example.com"
	password := "Password!123"
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
	var toks tokensResponse
	if err := json.NewDecoder(bytes.NewReader(srec.Body.Bytes())).Decode(&toks); err != nil {
		t.Fatalf("decode tokens: %v", err)
	}
	return e, tenantID, toks
}

func TestHTTP_MFA_TOTP_Enrollment_Activate_Disable(t *testing.T) {
	e, _, toks := setupAuthApp(t)

	// start
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/mfa/totp/start", nil)
	req.Header.Set("Authorization", "Bearer "+toks.AccessToken)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("totp start expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var startResp mfaTOTPStartResp
	if err := json.NewDecoder(bytes.NewReader(rec.Body.Bytes())).Decode(&startResp); err != nil {
		t.Fatalf("decode start: %v", err)
	}
	if startResp.Secret == "" || startResp.OtpauthURL == "" {
		t.Fatalf("expected secret and url: %+v", startResp)
	}

	// activate using generated code
	code, err := totp.GenerateCode(startResp.Secret, time.Now())
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	ab, _ := json.Marshal(map[string]string{"code": code})
	req2 := httptest.NewRequest(http.MethodPost, "/v1/auth/mfa/totp/activate", bytes.NewReader(ab))
	req2.Header.Set("Authorization", "Bearer "+toks.AccessToken)
	req2.Header.Set("Content-Type", "application/json")
	rec2 := httptest.NewRecorder()
	e.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusNoContent {
		t.Fatalf("totp activate expected 204, got %d: %s", rec2.Code, rec2.Body.String())
	}

	// disable
	req3 := httptest.NewRequest(http.MethodPost, "/v1/auth/mfa/totp/disable", nil)
	req3.Header.Set("Authorization", "Bearer "+toks.AccessToken)
	rec3 := httptest.NewRecorder()
	e.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusNoContent {
		t.Fatalf("totp disable expected 204, got %d: %s", rec3.Code, rec3.Body.String())
	}
}

func TestHTTP_MFA_BackupCodes_Generate_Consume_Count(t *testing.T) {
	e, _, toks := setupAuthApp(t)

	// generate 5
	gb, _ := json.Marshal(map[string]int{"count": 5})
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/mfa/backup/generate", bytes.NewReader(gb))
	req.Header.Set("Authorization", "Bearer "+toks.AccessToken)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("backup generate expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var genResp mfaBackupGenerateResp
	if err := json.NewDecoder(bytes.NewReader(rec.Body.Bytes())).Decode(&genResp); err != nil {
		t.Fatalf("decode generate: %v", err)
	}
	if len(genResp.Codes) != 5 {
		t.Fatalf("expected 5 codes, got %d", len(genResp.Codes))
	}

	// count -> 5
	reqC := httptest.NewRequest(http.MethodGet, "/v1/auth/mfa/backup/count", nil)
	reqC.Header.Set("Authorization", "Bearer "+toks.AccessToken)
	recC := httptest.NewRecorder()
	e.ServeHTTP(recC, reqC)
	if recC.Code != http.StatusOK {
		t.Fatalf("count expected 200, got %d: %s", recC.Code, recC.Body.String())
	}
	var cntResp mfaBackupCountResp
	if err := json.NewDecoder(bytes.NewReader(recC.Body.Bytes())).Decode(&cntResp); err != nil {
		t.Fatalf("decode count: %v", err)
	}
	if cntResp.Count != 5 {
		t.Fatalf("expected count 5, got %d", cntResp.Count)
	}

	// consume one
	cb, _ := json.Marshal(map[string]string{"code": genResp.Codes[0]})
	req2 := httptest.NewRequest(http.MethodPost, "/v1/auth/mfa/backup/consume", bytes.NewReader(cb))
	req2.Header.Set("Authorization", "Bearer "+toks.AccessToken)
	req2.Header.Set("Content-Type", "application/json")
	rec2 := httptest.NewRecorder()
	e.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("consume expected 200, got %d: %s", rec2.Code, rec2.Body.String())
	}
	var consResp mfaBackupConsumeResp
	if err := json.NewDecoder(bytes.NewReader(rec2.Body.Bytes())).Decode(&consResp); err != nil {
		t.Fatalf("decode consume: %v", err)
	}
	if !consResp.Consumed {
		t.Fatalf("expected consumed true")
	}

	// consume again -> false
	req2b := httptest.NewRequest(http.MethodPost, "/v1/auth/mfa/backup/consume", bytes.NewReader(cb))
	req2b.Header.Set("Authorization", "Bearer "+toks.AccessToken)
	req2b.Header.Set("Content-Type", "application/json")
	rec3 := httptest.NewRecorder()
	e.ServeHTTP(rec3, req2b)
	if rec3.Code != http.StatusOK {
		t.Fatalf("re-consume expected 200, got %d: %s", rec3.Code, rec3.Body.String())
	}
	var consResp2 mfaBackupConsumeResp
	if err := json.NewDecoder(bytes.NewReader(rec3.Body.Bytes())).Decode(&consResp2); err != nil {
		t.Fatalf("decode re-consume: %v", err)
	}
	if consResp2.Consumed {
		t.Fatalf("expected consumed false on second attempt")
	}

	// count -> 4
	rec4 := httptest.NewRecorder()
	e.ServeHTTP(rec4, reqC)
	if rec4.Code != http.StatusOK {
		t.Fatalf("count2 expected 200, got %d: %s", rec4.Code, rec4.Body.String())
	}
	var cntResp2 mfaBackupCountResp
	if err := json.NewDecoder(bytes.NewReader(rec4.Body.Bytes())).Decode(&cntResp2); err != nil {
		t.Fatalf("decode count2: %v", err)
	}
	if cntResp2.Count != 4 {
		t.Fatalf("expected count 4, got %d", cntResp2.Count)
	}
}
