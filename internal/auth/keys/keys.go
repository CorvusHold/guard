package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

// Manager handles asymmetric key pairs for JWT signing and JWKS serving.
type Manager struct {
	mu         sync.RWMutex
	privateKey *ecdsa.PrivateKey
	publicKey  *ecdsa.PublicKey
	kid        string
	algorithm  string // "ES256" or "HS256"
	hmacSecret string // fallback for HS256
}

// NewManager creates a key manager. If privateKeyPEM path is provided, it loads the key.
// Otherwise, it generates a new EC P-256 key pair in memory.
// If algorithm is "HS256", it falls back to HMAC with the provided secret.
func NewManager(algorithm, privateKeyPath, hmacSecret string) (*Manager, error) {
	m := &Manager{
		algorithm:  algorithm,
		hmacSecret: hmacSecret,
	}

	if algorithm == "HS256" || algorithm == "" {
		m.algorithm = "HS256"
		return m, nil
	}

	if algorithm != "ES256" {
		return nil, fmt.Errorf("unsupported signing algorithm: %s (supported: HS256, ES256)", algorithm)
	}

	if privateKeyPath != "" {
		data, err := os.ReadFile(privateKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read private key file: %w", err)
		}
		key, err := jwt.ParseECPrivateKeyFromPEM(data)
		if err != nil {
			return nil, fmt.Errorf("failed to parse EC private key: %w", err)
		}
		m.privateKey = key
		m.publicKey = &key.PublicKey
	} else {
		// Generate ephemeral key pair
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate EC key: %w", err)
		}
		m.privateKey = key
		m.publicKey = &key.PublicKey
	}

	// Derive kid from public key thumbprint (RFC 7638)
	m.kid = thumbprint(m.publicKey)

	return m, nil
}

// Algorithm returns the configured signing algorithm.
func (m *Manager) Algorithm() string {
	return m.algorithm
}

// IsAsymmetric returns true if the manager uses asymmetric signing.
func (m *Manager) IsAsymmetric() bool {
	return m.algorithm == "ES256"
}

// SigningMethod returns the jwt.SigningMethod for the configured algorithm.
func (m *Manager) SigningMethod() jwt.SigningMethod {
	if m.algorithm == "ES256" {
		return jwt.SigningMethodES256
	}
	return jwt.SigningMethodHS256
}

// SigningKey returns the key to use for signing JWTs.
// For ES256: *ecdsa.PrivateKey
// For HS256: []byte (HMAC secret)
func (m *Manager) SigningKey(hmacFallback string) interface{} {
	if m.algorithm == "ES256" && m.privateKey != nil {
		return m.privateKey
	}
	// HS256 fallback
	if hmacFallback != "" {
		return []byte(hmacFallback)
	}
	return []byte(m.hmacSecret)
}

// VerificationKey returns the key to use for verifying JWTs.
// For ES256: *ecdsa.PublicKey
// For HS256: []byte (HMAC secret)
func (m *Manager) VerificationKey(hmacFallback string) interface{} {
	if m.algorithm == "ES256" && m.publicKey != nil {
		return m.publicKey
	}
	if hmacFallback != "" {
		return []byte(hmacFallback)
	}
	return []byte(m.hmacSecret)
}

// KeyID returns the key ID for the current signing key.
func (m *Manager) KeyID() string {
	return m.kid
}

// JWKS returns the JSON Web Key Set containing the public key(s).
// Returns nil if using HS256 (no public keys to expose).
func (m *Manager) JWKS() *jose.JSONWebKeySet {
	if !m.IsAsymmetric() || m.publicKey == nil {
		return nil
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	return &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Key:       m.publicKey,
				KeyID:     m.kid,
				Algorithm: "ES256",
				Use:       "sig",
			},
		},
	}
}

// JWKSBytes returns the JWKS as JSON bytes.
func (m *Manager) JWKSBytes() ([]byte, error) {
	jwks := m.JWKS()
	if jwks == nil {
		return json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{}})
	}
	return json.Marshal(jwks)
}

// thumbprint computes a key ID from the public key using SHA-256 thumbprint.
func thumbprint(pub *ecdsa.PublicKey) string {
	// Simple thumbprint: hash the uncompressed public key bytes
	xBytes := pub.X.Bytes()
	yBytes := pub.Y.Bytes()
	data := append(xBytes, yBytes...)
	h := sha256.Sum256(data)
	return base64.RawURLEncoding.EncodeToString(h[:8])
}
