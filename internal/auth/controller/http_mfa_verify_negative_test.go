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

func TestHTTP_MFA_Verify_WrongCode_TOTP(t *testing.T) {
	e, tenantID, toks := setupAuthApp(t)

	// Enroll and activate TOTP
	reqStart := httptest.NewRequest(http.MethodPost, "/v1/auth/mfa/totp/start", nil)
	reqStart.Header.Set("Authorization", "Bearer "+toks.AccessToken)
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
	reqAct.Header.Set("Authorization", "Bearer "+toks.AccessToken)
	reqAct.Header.Set("Content-Type", "application/json")
	recAct := httptest.NewRecorder()
	e.ServeHTTP(recAct, reqAct)
	if recAct.Code != http.StatusNoContent {
		t.Fatalf("totp activate expected 204, got %d: %s", recAct.Code, recAct.Body.String())
	}

	// Login -> 202 challenge
	lb, _ := json.Marshal(map[string]string{
		"tenant_id": tenantID.String(),
		"email":     "user.mfa.itest@example.com",
		"password":  "Password!123",
	})
	reqLogin := httptest.NewRequest(http.MethodPost, "/v1/auth/password/login", bytes.NewReader(lb))
	reqLogin.Header.Set("Content-Type", "application/json")
	recLogin := httptest.NewRecorder()
	e.ServeHTTP(recLogin, reqLogin)
	if recLogin.Code != http.StatusAccepted {
		t.Fatalf("login expected 202, got %d: %s", recLogin.Code, recLogin.Body.String())
	}
	var ch mfaChallengeResp
	_ = json.NewDecoder(bytes.NewReader(recLogin.Body.Bytes())).Decode(&ch)

	// Verify with wrong code
	vb, _ := json.Marshal(map[string]string{
		"challenge_token": ch.ChallengeToken,
		"method":          "totp",
		"code":            "000000", // almost certainly wrong
	})
	reqVerify := httptest.NewRequest(http.MethodPost, "/v1/auth/mfa/verify", bytes.NewReader(vb))
	reqVerify.Header.Set("Content-Type", "application/json")
	reqVerify.Header.Set("X-Auth-Mode", "bearer")
	recVerify := httptest.NewRecorder()
	e.ServeHTTP(recVerify, reqVerify)
	if recVerify.Code != http.StatusUnauthorized {
		t.Fatalf("verify wrong totp expected 401, got %d: %s", recVerify.Code, recVerify.Body.String())
	}
}

func TestHTTP_MFA_Verify_BackupCode_SingleUse(t *testing.T) {
	e, tenantID, toks := setupAuthApp(t)

	// Enroll TOTP (to enable MFA) and activate
	reqStart := httptest.NewRequest(http.MethodPost, "/v1/auth/mfa/totp/start", nil)
	reqStart.Header.Set("Authorization", "Bearer "+toks.AccessToken)
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
	reqAct.Header.Set("Authorization", "Bearer "+toks.AccessToken)
	reqAct.Header.Set("Content-Type", "application/json")
	recAct := httptest.NewRecorder()
	e.ServeHTTP(recAct, reqAct)
	if recAct.Code != http.StatusNoContent {
		t.Fatalf("totp activate expected 204, got %d: %s", recAct.Code, recAct.Body.String())
	}

	// Generate one backup code
	gb, _ := json.Marshal(map[string]int{"count": 1})
	reqGen := httptest.NewRequest(http.MethodPost, "/v1/auth/mfa/backup/generate", bytes.NewReader(gb))
	reqGen.Header.Set("Authorization", "Bearer "+toks.AccessToken)
	reqGen.Header.Set("Content-Type", "application/json")
	recGen := httptest.NewRecorder()
	e.ServeHTTP(recGen, reqGen)
	if recGen.Code != http.StatusOK {
		t.Fatalf("backup generate expected 200, got %d: %s", recGen.Code, recGen.Body.String())
	}
	var genResp struct{ Codes []string }
	_ = json.NewDecoder(bytes.NewReader(recGen.Body.Bytes())).Decode(&genResp)
	if len(genResp.Codes) != 1 {
		t.Fatalf("expected 1 code, got %d", len(genResp.Codes))
	}

	// Login -> challenge
	lb, _ := json.Marshal(map[string]string{
		"tenant_id": tenantID.String(),
		"email":     "user.mfa.itest@example.com",
		"password":  "Password!123",
	})
	reqLogin := httptest.NewRequest(http.MethodPost, "/v1/auth/password/login", bytes.NewReader(lb))
	reqLogin.Header.Set("Content-Type", "application/json")
	recLogin := httptest.NewRecorder()
	e.ServeHTTP(recLogin, reqLogin)
	if recLogin.Code != http.StatusAccepted {
		t.Fatalf("login expected 202, got %d: %s", recLogin.Code, recLogin.Body.String())
	}
	var ch1 mfaChallengeResp
	_ = json.NewDecoder(bytes.NewReader(recLogin.Body.Bytes())).Decode(&ch1)

	// Verify first time -> success
	vb1, _ := json.Marshal(map[string]string{
		"challenge_token": ch1.ChallengeToken,
		"method":          "backup_code",
		"code":            genResp.Codes[0],
	})
	reqVerify1 := httptest.NewRequest(http.MethodPost, "/v1/auth/mfa/verify", bytes.NewReader(vb1))
	reqVerify1.Header.Set("Content-Type", "application/json")
	recVerify1 := httptest.NewRecorder()
	e.ServeHTTP(recVerify1, reqVerify1)
	if recVerify1.Code != http.StatusOK {
		t.Fatalf("first verify expected 200, got %d: %s", recVerify1.Code, recVerify1.Body.String())
	}

	// Login again -> new challenge
	reqLogin2 := httptest.NewRequest(http.MethodPost, "/v1/auth/password/login", bytes.NewReader(lb))
	reqLogin2.Header.Set("Content-Type", "application/json")
	recLogin2 := httptest.NewRecorder()
	e.ServeHTTP(recLogin2, reqLogin2)
	if recLogin2.Code != http.StatusAccepted {
		t.Fatalf("login2 expected 202, got %d: %s", recLogin2.Code, recLogin2.Body.String())
	}
	var ch2 mfaChallengeResp
	_ = json.NewDecoder(bytes.NewReader(recLogin2.Body.Bytes())).Decode(&ch2)

	// Verify with same backup code -> should fail (consumed)
	vb2, _ := json.Marshal(map[string]string{
		"challenge_token": ch2.ChallengeToken,
		"method":          "backup_code",
		"code":            genResp.Codes[0],
	})
	reqVerify2 := httptest.NewRequest(http.MethodPost, "/v1/auth/mfa/verify", bytes.NewReader(vb2))
	reqVerify2.Header.Set("Content-Type", "application/json")
	recVerify2 := httptest.NewRecorder()
	e.ServeHTTP(recVerify2, reqVerify2)
	if recVerify2.Code != http.StatusUnauthorized {
		t.Fatalf("second verify with same backup code expected 401, got %d: %s", recVerify2.Code, recVerify2.Body.String())
	}
}
