package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestNewManager_HS256Defaults(t *testing.T) {
	m, err := NewManager("", "", "secret")
	if err != nil {
		t.Fatalf("NewManager returned error: %v", err)
	}
	if m.Algorithm() != "HS256" {
		t.Fatalf("expected HS256 algorithm, got %q", m.Algorithm())
	}
	if m.IsAsymmetric() {
		t.Fatal("expected HS256 manager to be symmetric")
	}
	if _, ok := m.SigningMethod().(*jwt.SigningMethodHMAC); !ok {
		t.Fatalf("expected HMAC signing method, got %T", m.SigningMethod())
	}
}

func TestNewManager_ES256AndUnsupportedAlgorithm(t *testing.T) {
	m, err := NewManager("ES256", "", "")
	if err != nil {
		t.Fatalf("NewManager ES256 returned error: %v", err)
	}
	if !m.IsAsymmetric() {
		t.Fatal("expected ES256 manager to be asymmetric")
	}
	if m.KeyID() == "" {
		t.Fatal("expected non-empty key id")
	}

	if _, err := NewManager("RS256", "", ""); err == nil {
		t.Fatal("expected unsupported algorithm error")
	}
}

func TestNewManager_FromPrivateKeyFile(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})

	f, err := os.CreateTemp("", "guard-key-*.pem")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(pemBytes); err != nil {
		t.Fatalf("write pem: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close pem file: %v", err)
	}

	m, err := NewManager("ES256", f.Name(), "")
	if err != nil {
		t.Fatalf("NewManager with key file returned error: %v", err)
	}
	if m.publicKey == nil || m.privateKey == nil {
		t.Fatal("expected keys loaded from PEM file")
	}
}

func TestSigningAndVerificationKeyFallbacks(t *testing.T) {
	m := &Manager{algorithm: "HS256", hmacSecret: "secret-a"}
	if got := string(m.SigningKey("").([]byte)); got != "secret-a" {
		t.Fatalf("expected hmac secret signing key, got %q", got)
	}
	if got := string(m.VerificationKey("override").([]byte)); got != "override" {
		t.Fatalf("expected fallback override verification key, got %q", got)
	}
}

func TestJWKSAndJWKSBytes(t *testing.T) {
	m, err := NewManager("ES256", "", "")
	if err != nil {
		t.Fatalf("NewManager returned error: %v", err)
	}
	jwks := m.JWKS()
	if jwks == nil || len(jwks.Keys) != 1 {
		t.Fatalf("expected one JWKS key, got %+v", jwks)
	}

	b, err := m.JWKSBytes()
	if err != nil {
		t.Fatalf("JWKSBytes returned error: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(b, &parsed); err != nil {
		t.Fatalf("invalid JWKS JSON: %v", err)
	}

	hs := &Manager{algorithm: "HS256", hmacSecret: "s"}
	if hs.JWKS() != nil {
		t.Fatal("expected nil JWKS for HS256")
	}
	hsBytes, err := hs.JWKSBytes()
	if err != nil {
		t.Fatalf("JWKSBytes HS256 returned error: %v", err)
	}
	if string(hsBytes) != `{"keys":[]}` {
		t.Fatalf("expected empty JWKS keys, got %s", string(hsBytes))
	}
}

func TestThumbprint_IsDeterministic(t *testing.T) {
	m, err := NewManager("ES256", "", "")
	if err != nil {
		t.Fatalf("NewManager returned error: %v", err)
	}
	id1 := thumbprint(m.publicKey)
	id2 := thumbprint(m.publicKey)
	if id1 != id2 {
		t.Fatalf("expected deterministic thumbprint, got %q and %q", id1, id2)
	}
}
