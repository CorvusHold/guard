package service

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestSignPayload(t *testing.T) {
	secret := "my-webhook-secret"
	payload := []byte(`{"event":"user.created","user_id":"123"}`)

	sig := SignPayload(secret, payload)
	if sig == "" {
		t.Fatal("expected non-empty signature")
	}

	// Verify manually
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	expected := hex.EncodeToString(mac.Sum(nil))
	if sig != expected {
		t.Errorf("signature mismatch: got %s, want %s", sig, expected)
	}
}

func TestSignPayload_DifferentSecrets(t *testing.T) {
	payload := []byte(`{"event":"user.created"}`)
	sig1 := SignPayload("secret-a", payload)
	sig2 := SignPayload("secret-b", payload)
	if sig1 == sig2 {
		t.Error("different secrets should produce different signatures")
	}
}

func TestSignPayload_DifferentPayloads(t *testing.T) {
	secret := "shared-secret"
	sig1 := SignPayload(secret, []byte(`{"a":1}`))
	sig2 := SignPayload(secret, []byte(`{"a":2}`))
	if sig1 == sig2 {
		t.Error("different payloads should produce different signatures")
	}
}

func TestSignPayload_Deterministic(t *testing.T) {
	secret := "deterministic"
	payload := []byte("hello")
	sig1 := SignPayload(secret, payload)
	sig2 := SignPayload(secret, payload)
	if sig1 != sig2 {
		t.Error("same inputs should produce same signature")
	}
}

func TestHashSecret(t *testing.T) {
	h := hashSecret("my-secret")
	if h == "" {
		t.Fatal("expected non-empty hash")
	}
	if len(h) != 64 { // SHA-256 hex
		t.Errorf("expected 64 char hex, got %d", len(h))
	}
	// Deterministic
	h2 := hashSecret("my-secret")
	if h != h2 {
		t.Error("hashSecret should be deterministic")
	}
	// Different input
	h3 := hashSecret("other-secret")
	if h == h3 {
		t.Error("different secrets should produce different hashes")
	}
}
