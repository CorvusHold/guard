package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/corvusHold/guard/internal/config"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	done := make(chan string, 1)
	var once sync.Once
	var captured string
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		_ = r.Close()
		done <- buf.String()
	}()
	finish := func() string {
		once.Do(func() {
			_ = w.Close()
			os.Stdout = orig
			captured = <-done
		})
		return captured
	}
	t.Cleanup(func() {
		_ = finish()
	})

	fn()
	return finish()
}

func TestSanitizePrefix(t *testing.T) {
	if got := sanitizePrefix("  "); got != "bootstrap" {
		t.Fatalf("expected bootstrap fallback, got %q", got)
	}
	if got := sanitizePrefix("  My Prefix  "); got != "my-prefix" {
		t.Fatalf("expected lowercase hyphenated prefix, got %q", got)
	}
}

func TestRandomPassword_LengthAndDifferentValues(t *testing.T) {
	a, err := randomPassword(24)
	if err != nil {
		t.Fatalf("randomPassword returned error: %v", err)
	}
	b, err := randomPassword(24)
	if err != nil {
		t.Fatalf("randomPassword returned error: %v", err)
	}
	if len(a) != 24 || len(b) != 24 {
		t.Fatalf("expected 24-char passwords, got %d and %d", len(a), len(b))
	}
	if a == b {
		t.Fatal("expected random passwords to differ")
	}
}

func TestMintToken_ContainsExpectedClaims(t *testing.T) {
	cfg := config.Config{PublicBaseURL: "https://guard.example.com", JWTSigningKey: "secret-key"}
	userID := uuid.New()
	tenantID := uuid.New()
	expiresAt := time.Now().Add(10 * time.Minute)

	tok, err := mintToken(cfg, userID, tenantID, expiresAt)
	if err != nil {
		t.Fatalf("mintToken returned error: %v", err)
	}

	parsed, err := jwt.Parse(tok, func(token *jwt.Token) (interface{}, error) {
		return []byte(cfg.JWTSigningKey), nil
	})
	if err != nil {
		t.Fatalf("failed to parse token: %v", err)
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatalf("expected map claims, got %T", parsed.Claims)
	}
	if claims["sub"] != userID.String() {
		t.Fatalf("unexpected sub claim: %v", claims["sub"])
	}
	if claims["ten"] != tenantID.String() {
		t.Fatalf("unexpected ten claim: %v", claims["ten"])
	}
	if claims["iss"] != cfg.PublicBaseURL {
		t.Fatalf("unexpected iss claim: %v", claims["iss"])
	}
}

func TestPrintEnv_StableAndSorted(t *testing.T) {
	res := bootstrapResult{
		TenantID:   uuid.MustParse("11111111-1111-1111-1111-111111111111"),
		TenantName: "tenant-a",
		UserID:     uuid.MustParse("22222222-2222-2222-2222-222222222222"),
		Email:      "user@example.com",
		Password:   "pw",
		Token:      "tok",
		ExpiresAt:  time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	out := captureStdout(t, func() { printEnv(res) })
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 7 {
		t.Fatalf("expected 7 env lines, got %d: %q", len(lines), out)
	}
	for i := 1; i < len(lines); i++ {
		if lines[i-1] > lines[i] {
			t.Fatalf("expected sorted env output, got out-of-order lines: %q then %q", lines[i-1], lines[i])
		}
	}
}

func TestEncodeJSON_WritesValidJSON(t *testing.T) {
	res := bootstrapResult{
		TenantID:   uuid.MustParse("11111111-1111-1111-1111-111111111111"),
		TenantName: "tenant-a",
		UserID:     uuid.MustParse("22222222-2222-2222-2222-222222222222"),
		Email:      "user@example.com",
	}

	out := captureStdout(t, func() { encodeJSON(res) })
	var decoded bootstrapResult
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("expected valid json output: %v\noutput: %s", err, out)
	}
	if decoded.Email != "user@example.com" {
		t.Fatalf("unexpected decoded email: %q", decoded.Email)
	}
}
