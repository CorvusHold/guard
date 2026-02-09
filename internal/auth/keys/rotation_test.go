package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func generateTestPEM(t *testing.T) string {
	t.Helper()
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	derBytes, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: derBytes}))
}

func TestNewManagerFromPEM_Valid(t *testing.T) {
	pemData := generateTestPEM(t)
	m, err := NewManagerFromPEM("ES256", pemData, "test-kid")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m == nil {
		t.Fatal("expected non-nil manager")
	}
	if m.KeyID() != "test-kid" {
		t.Errorf("expected kid 'test-kid', got %q", m.KeyID())
	}
	if !m.IsAsymmetric() {
		t.Error("expected asymmetric manager")
	}
}

func TestNewManagerFromPEM_AutoKID(t *testing.T) {
	pemData := generateTestPEM(t)
	m, err := NewManagerFromPEM("ES256", pemData, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m.KeyID() == "" {
		t.Error("expected auto-generated kid")
	}
}

func TestNewManagerFromPEM_InvalidPEM(t *testing.T) {
	_, err := NewManagerFromPEM("ES256", "not-a-pem", "kid")
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

func TestNewManagerFromPEM_InvalidKey(t *testing.T) {
	// Valid PEM block but not an EC key
	badPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte("not-a-key")}))
	_, err := NewManagerFromPEM("ES256", badPEM, "kid")
	if err == nil {
		t.Fatal("expected error for invalid key bytes")
	}
}

func TestNewManagerFromPEM_DifferentKeysGetDifferentKIDs(t *testing.T) {
	pem1 := generateTestPEM(t)
	pem2 := generateTestPEM(t)

	m1, _ := NewManagerFromPEM("ES256", pem1, "")
	m2, _ := NewManagerFromPEM("ES256", pem2, "")

	if m1.KeyID() == m2.KeyID() {
		t.Error("different keys should produce different auto-generated KIDs")
	}
}

func TestRotatingManager_ActiveManager_Fallback(t *testing.T) {
	pemData := generateTestPEM(t)
	fallback, err := NewManagerFromPEM("ES256", pemData, "fallback")
	if err != nil {
		t.Fatalf("create fallback: %v", err)
	}

	rm := NewRotatingManager(nil, fallback)
	active := rm.ActiveManager()
	if active != fallback {
		t.Error("expected fallback manager when no DB keys loaded")
	}
}

func TestRotatingManager_ManagerByKID_Fallback(t *testing.T) {
	pemData := generateTestPEM(t)
	fallback, _ := NewManagerFromPEM("ES256", pemData, "fallback")
	rm := NewRotatingManager(nil, fallback)

	m := rm.ManagerByKID("nonexistent")
	if m != fallback {
		t.Error("expected fallback for unknown KID")
	}
}

func TestRotatingManager_ManagerByKID_Found(t *testing.T) {
	pemData := generateTestPEM(t)
	mgr, _ := NewManagerFromPEM("ES256", pemData, "my-kid")

	rm := NewRotatingManager(nil, nil)
	rm.managers["my-kid"] = mgr
	rm.activeKID = "my-kid"

	found := rm.ManagerByKID("my-kid")
	if found != mgr {
		t.Error("expected to find the registered manager")
	}
}

func TestRotatingManager_JWKSBytes_Empty(t *testing.T) {
	rm := NewRotatingManager(nil, nil)
	data, err := rm.JWKSBytes()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty JWKS even with no keys")
	}
}

func TestRotatingManager_JWKSBytes_WithFallback(t *testing.T) {
	pemData := generateTestPEM(t)
	fallback, _ := NewManagerFromPEM("ES256", pemData, "fb-kid")
	rm := NewRotatingManager(nil, fallback)

	data, err := rm.JWKSBytes()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should contain at least the fallback key
	if len(data) < 10 {
		t.Errorf("expected meaningful JWKS, got %d bytes", len(data))
	}
}
