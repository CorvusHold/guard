package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
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

// writeTestECPrivateKey generates an ES256 EC private key for testing and returns the file path.
// This helper ensures tests use proper asymmetric cryptography matching production behavior.
func writeTestECPrivateKey(t *testing.T) string {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ec key: %v", err)
	}
	der, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal ec key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})

	keyPath := filepath.Join(t.TempDir(), "jwt-es256-private.pem")
	if err := os.WriteFile(keyPath, pemBytes, 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
	return keyPath
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

// TestMintToken_ContainsExpectedClaims verifies that mintToken generates ES256-signed
// JWTs with the correct claims structure for bootstrap access tokens.
func TestMintToken_ContainsExpectedClaims(t *testing.T) {
	// Generate test EC key for ES256 signing
	keyPath := writeTestECPrivateKey(t)

	cfg := config.Config{
		PublicBaseURL:       "https://guard.example.com",
		JWTSigningAlgorithm: "ES256",
		JWTPrivateKeyPath:   keyPath,
	}

	userID := uuid.New()
	tenantID := uuid.New()
	expiresAt := time.Now().Add(10 * time.Minute)

	tok, err := mintToken(cfg, userID, tenantID, expiresAt)
	if err != nil {
		t.Fatalf("mintToken returned error: %v", err)
	}

	// Load the EC public key for verification (ES256 uses asymmetric keys)
	_, publicKey, err := config.LoadECKeys(keyPath)
	if err != nil {
		t.Fatalf("failed to load EC public key: %v", err)
	}

	// Parse and verify the ES256-signed token
	parsed, err := jwt.Parse(tok, func(token *jwt.Token) (interface{}, error) {
		// Verify the algorithm is ES256 as expected
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			t.Fatalf("unexpected signing method: %v", token.Method)
		}
		return publicKey, nil
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
	if claims["aud"] != cfg.PublicBaseURL {
		t.Fatalf("unexpected aud claim: %v", claims["aud"])
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
