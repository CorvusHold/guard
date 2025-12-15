package controller

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func TestHTTP_MFA_LoginChallenge_Then_Verify_TOTP(t *testing.T) {
	e, tenantID, toks := setupAuthApp(t)

	// 1) Enroll TOTP to enable MFA for the user
	reqStart := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/totp/start", nil)
	reqStart.Header.Set("Authorization", "Bearer "+toks.AccessToken)
	recStart := httptest.NewRecorder()
	e.ServeHTTP(recStart, reqStart)
	if recStart.Code != http.StatusOK {
		t.Fatalf("totp start expected 200, got %d: %s", recStart.Code, recStart.Body.String())
	}
	var startResp struct{ Secret, OtpauthURL string }
	if err := json.NewDecoder(bytes.NewReader(recStart.Body.Bytes())).Decode(&startResp); err != nil {
		t.Fatalf("decode start: %v", err)
	}
	if startResp.Secret == "" {
		t.Fatalf("missing secret")
	}

	// Activate
	code, err := totp.GenerateCode(startResp.Secret, time.Now())
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	ab, _ := json.Marshal(map[string]string{"code": code})
	reqAct := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/totp/activate", bytes.NewReader(ab))
	reqAct.Header.Set("Authorization", "Bearer "+toks.AccessToken)
	reqAct.Header.Set("Content-Type", "application/json")
	recAct := httptest.NewRecorder()
	e.ServeHTTP(recAct, reqAct)
	if recAct.Code != http.StatusNoContent {
		t.Fatalf("totp activate expected 204, got %d: %s", recAct.Code, recAct.Body.String())
	}

	// 2) Password login should return MFA challenge (202)
	loginBody := map[string]string{
		"tenant_id": tenantID.String(),
		"email":     "user.mfa.itest@example.com",
		"password":  "Password!123",
	}
	lb, _ := json.Marshal(loginBody)
	reqLogin := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/login", bytes.NewReader(lb))
	reqLogin.Header.Set("Content-Type", "application/json")
	recLogin := httptest.NewRecorder()
	e.ServeHTTP(recLogin, reqLogin)
	if recLogin.Code != http.StatusAccepted {
		t.Fatalf("login expected 202 MFA challenge, got %d: %s", recLogin.Code, recLogin.Body.String())
	}
	var ch mfaChallengeResp
	if err := json.NewDecoder(bytes.NewReader(recLogin.Body.Bytes())).Decode(&ch); err != nil {
		t.Fatalf("decode challenge: %v", err)
	}
	if ch.ChallengeToken == "" {
		t.Fatalf("missing challenge token")
	}

	// 3) Verify MFA using TOTP
	code2, err := totp.GenerateCode(startResp.Secret, time.Now())
	if err != nil {
		t.Fatalf("generate code2: %v", err)
	}
	vb, _ := json.Marshal(map[string]string{
		"challenge_token": ch.ChallengeToken,
		"method":          "totp",
		"code":            code2,
	})
	reqVerify := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/verify", bytes.NewReader(vb))
	reqVerify.Header.Set("Content-Type", "application/json")
	reqVerify.Header.Set("X-Auth-Mode", "bearer")
	recVerify := httptest.NewRecorder()
	e.ServeHTTP(recVerify, reqVerify)
	if recVerify.Code != http.StatusOK {
		t.Fatalf("verify expected 200, got %d: %s", recVerify.Code, recVerify.Body.String())
	}
	var toksOut tokensResp
	if err := json.NewDecoder(bytes.NewReader(recVerify.Body.Bytes())).Decode(&toksOut); err != nil {
		t.Fatalf("decode tokens: %v", err)
	}
	if toksOut.AccessToken == "" || toksOut.RefreshToken == "" {
		t.Fatalf("expected tokens in response")
	}
}

func TestHTTP_MFA_LoginChallenge_Then_Verify_BackupCode(t *testing.T) {
	e, tenantID, toks := setupAuthApp(t)

	// Enroll TOTP first to enable MFA (backup codes require MFA enabled)
	reqStart := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/totp/start", nil)
	reqStart.Header.Set("Authorization", "Bearer "+toks.AccessToken)
	recStart := httptest.NewRecorder()
	e.ServeHTTP(recStart, reqStart)
	if recStart.Code != http.StatusOK {
		t.Fatalf("totp start expected 200, got %d: %s", recStart.Code, recStart.Body.String())
	}
	var startResp struct{ Secret, OtpauthURL string }
	_ = json.NewDecoder(bytes.NewReader(recStart.Body.Bytes())).Decode(&startResp)
	code, _ := totp.GenerateCode(startResp.Secret, time.Now())
	ab, _ := json.Marshal(map[string]string{"code": code})
	reqAct := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/totp/activate", bytes.NewReader(ab))
	reqAct.Header.Set("Authorization", "Bearer "+toks.AccessToken)
	reqAct.Header.Set("Content-Type", "application/json")
	recAct := httptest.NewRecorder()
	e.ServeHTTP(recAct, reqAct)
	if recAct.Code != http.StatusNoContent {
		t.Fatalf("totp activate expected 204, got %d: %s", recAct.Code, recAct.Body.String())
	}

	// Generate one backup code
	gb, _ := json.Marshal(map[string]int{"count": 1})
	reqGen := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/backup/generate", bytes.NewReader(gb))
	reqGen.Header.Set("Authorization", "Bearer "+toks.AccessToken)
	reqGen.Header.Set("Content-Type", "application/json")
	recGen := httptest.NewRecorder()
	e.ServeHTTP(recGen, reqGen)
	if recGen.Code != http.StatusOK {
		t.Fatalf("backup generate expected 200, got %d: %s", recGen.Code, recGen.Body.String())
	}
	var genResp struct{ Codes []string }
	if err := json.NewDecoder(bytes.NewReader(recGen.Body.Bytes())).Decode(&genResp); err != nil {
		t.Fatalf("decode generate: %v", err)
	}
	if len(genResp.Codes) != 1 {
		t.Fatalf("expected 1 code, got %d", len(genResp.Codes))
	}

	// Password login -> 202 challenge
	loginBody := map[string]string{
		"tenant_id": tenantID.String(),
		"email":     "user.mfa.itest@example.com",
		"password":  "Password!123",
	}
	lb, _ := json.Marshal(loginBody)
	reqLogin := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/login", bytes.NewReader(lb))
	reqLogin.Header.Set("Content-Type", "application/json")
	recLogin := httptest.NewRecorder()
	e.ServeHTTP(recLogin, reqLogin)
	if recLogin.Code != http.StatusAccepted {
		t.Fatalf("login expected 202 MFA challenge, got %d: %s", recLogin.Code, recLogin.Body.String())
	}
	var ch mfaChallengeResp
	if err := json.NewDecoder(bytes.NewReader(recLogin.Body.Bytes())).Decode(&ch); err != nil {
		t.Fatalf("decode challenge: %v", err)
	}
	if ch.ChallengeToken == "" {
		t.Fatalf("missing challenge token")
	}

	// Verify using backup code
	vb, _ := json.Marshal(map[string]string{
		"challenge_token": ch.ChallengeToken,
		"method":          "backup_code",
		"code":            genResp.Codes[0],
	})
	reqVerify := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/verify", bytes.NewReader(vb))
	reqVerify.Header.Set("Content-Type", "application/json")
	reqVerify.Header.Set("X-Auth-Mode", "bearer")
	recVerify := httptest.NewRecorder()
	e.ServeHTTP(recVerify, reqVerify)
	if recVerify.Code != http.StatusOK {
		t.Fatalf("verify expected 200, got %d: %s", recVerify.Code, recVerify.Body.String())
	}
	var toksOut tokensResp
	if err := json.NewDecoder(bytes.NewReader(recVerify.Body.Bytes())).Decode(&toksOut); err != nil {
		t.Fatalf("decode tokens: %v", err)
	}
	if toksOut.AccessToken == "" || toksOut.RefreshToken == "" {
		t.Fatalf("expected tokens in response")
	}
}
