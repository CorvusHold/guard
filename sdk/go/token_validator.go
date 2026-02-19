package guard

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Typed errors for token validation.
var (
	ErrTokenExpired   = errors.New("guard: token expired")
	ErrTokenInvalid   = errors.New("guard: token invalid")
	ErrTokenMalform   = errors.New("guard: token malformed")
	ErrJWKSFetch      = errors.New("guard: failed to fetch JWKS")
	ErrKeyNotFound    = errors.New("guard: signing key not found in JWKS")
	ErrUnsupportedAlg = errors.New("guard: unsupported signing algorithm")
)

// TokenClaims represents the validated claims from a Guard JWT.
type TokenClaims struct {
	Subject  string   `json:"sub"`
	TenantID string   `json:"ten"`
	Email    string   `json:"email"`
	Name     string   `json:"name"`
	Roles    []string `json:"roles"`
	Issuer   string   `json:"iss"`
	Audience string   `json:"aud"`
	IssuedAt int64    `json:"iat"`
	Expiry   int64    `json:"exp"`
}

// TokenValidator validates Guard-issued JWTs using ES256 public keys from JWKS.
type TokenValidator struct {
	guardURL   string
	tenantID   string
	httpClient *http.Client
	cacheTTL   time.Duration

	mu        sync.RWMutex
	keys      map[string]*ecdsa.PublicKey
	fetchedAt time.Time
}

// TokenValidatorOption customizes TokenValidator construction.
type TokenValidatorOption func(*TokenValidator)

// WithValidatorHTTPClient overrides the HTTP client used for JWKS fetching.
func WithValidatorHTTPClient(c *http.Client) TokenValidatorOption {
	return func(v *TokenValidator) { v.httpClient = c }
}

// WithJWKSCacheTTL sets the JWKS cache duration (default: 1 hour).
func WithJWKSCacheTTL(d time.Duration) TokenValidatorOption {
	return func(v *TokenValidator) { v.cacheTTL = d }
}

// WithValidatorTenantID configures tenant-scoped JWKS resolution (path-based issuer mode).
// When set, JWKS are fetched from: {guardURL}/t/{tenantID}/.well-known/jwks.json
func WithValidatorTenantID(tenantID string) TokenValidatorOption {
	return func(v *TokenValidator) { v.tenantID = strings.TrimSpace(tenantID) }
}

// NewTokenValidator creates a validator that fetches and caches JWKS from the Guard server.
func NewTokenValidator(guardURL string, opts ...TokenValidatorOption) *TokenValidator {
	v := &TokenValidator{
		guardURL:   guardURL,
		httpClient: &http.Client{Timeout: 10 * time.Second},
		cacheTTL:   time.Hour,
		keys:       make(map[string]*ecdsa.PublicKey),
	}
	for _, o := range opts {
		o(v)
	}
	return v
}

// Validate parses and validates a Guard JWT, returning the claims.
func (v *TokenValidator) Validate(ctx context.Context, tokenString string) (*TokenClaims, error) {
	// Parse header to determine algorithm and kid
	header, err := parseJWTHeader(tokenString)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTokenMalform, err)
	}

	alg, _ := header["alg"].(string)
	kid, _ := header["kid"].(string)

	if alg != "ES256" {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedAlg, alg)
	}
	return v.validateES256(ctx, tokenString, kid)
}

// validateES256 validates an ES256-signed JWT using JWKS.
func (v *TokenValidator) validateES256(ctx context.Context, tokenString, kid string) (*TokenClaims, error) {
	key, err := v.getKey(ctx, kid)
	if err != nil {
		return nil, err
	}

	parts, err := splitJWT(tokenString)
	if err != nil {
		return nil, err
	}

	// Verify signature
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("%w: invalid signature encoding", ErrTokenMalform)
	}

	message := parts[0] + "." + parts[1]
	if !ecdsaVerify(key, []byte(message), sigBytes) {
		return nil, ErrTokenInvalid
	}

	// Decode payload
	claims, err := decodePayload(parts[1])
	if err != nil {
		return nil, err
	}

	// Check expiry
	if claims.Expiry > 0 && time.Now().Unix() > claims.Expiry {
		return nil, ErrTokenExpired
	}

	return claims, nil
}

// getKey retrieves the public key for the given kid, fetching JWKS if needed.
func (v *TokenValidator) getKey(ctx context.Context, kid string) (*ecdsa.PublicKey, error) {
	v.mu.RLock()
	key, ok := v.keys[kid]
	stale := time.Since(v.fetchedAt) > v.cacheTTL
	v.mu.RUnlock()

	if ok && !stale {
		return key, nil
	}

	// Fetch JWKS
	if err := v.fetchJWKS(ctx); err != nil {
		// If we have a cached key, use it even if stale
		if ok {
			return key, nil
		}
		return nil, err
	}

	v.mu.RLock()
	key, ok = v.keys[kid]
	v.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("%w: kid=%s", ErrKeyNotFound, kid)
	}
	return key, nil
}

// fetchJWKS fetches the JWKS from the Guard server.
func (v *TokenValidator) fetchJWKS(ctx context.Context) error {
	url := strings.TrimRight(v.guardURL, "/") + "/.well-known/jwks.json"
	if v.tenantID != "" {
		url = strings.TrimRight(v.guardURL, "/") + "/t/" + v.tenantID + "/.well-known/jwks.json"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrJWKSFetch, err)
	}

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrJWKSFetch, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: status %d", ErrJWKSFetch, resp.StatusCode)
	}

	var jwks jwksResponse
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return fmt.Errorf("%w: %v", ErrJWKSFetch, err)
	}

	newKeys := make(map[string]*ecdsa.PublicKey)
	for _, k := range jwks.Keys {
		if k.Kty != "EC" || k.Crv != "P-256" {
			continue
		}
		pub, err := parseECPublicKey(k)
		if err != nil {
			continue
		}
		newKeys[k.Kid] = pub
	}

	v.mu.Lock()
	v.keys = newKeys
	v.fetchedAt = time.Now()
	v.mu.Unlock()

	return nil
}

// --- JWKS types ---

type jwksResponse struct {
	Keys []jwkKey `json:"keys"`
}

type jwkKey struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
}

func parseECPublicKey(k jwkKey) (*ecdsa.PublicKey, error) {
	xBytes, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, err
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(k.Y)
	if err != nil {
		return nil, err
	}
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}, nil
}

// --- JWT helpers (minimal, no external deps) ---

func parseJWTHeader(token string) (map[string]interface{}, error) {
	parts, err := splitJWT(token)
	if err != nil {
		return nil, err
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, err
	}
	return header, nil
}

func splitJWT(token string) ([]string, error) {
	// Split into header.payload.signature
	var parts []string
	start := 0
	count := 0
	for i := 0; i < len(token); i++ {
		if token[i] == '.' {
			parts = append(parts, token[start:i])
			start = i + 1
			count++
		}
	}
	parts = append(parts, token[start:])
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: expected 3 parts, got %d", ErrTokenMalform, len(parts))
	}
	return parts, nil
}

func decodePayload(payload string) (*TokenClaims, error) {
	payloadBytes, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTokenMalform, err)
	}

	// First decode into raw map to handle roles array
	var raw map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &raw); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTokenMalform, err)
	}

	claims := &TokenClaims{}
	if v, ok := raw["sub"].(string); ok {
		claims.Subject = v
	}
	if v, ok := raw["ten"].(string); ok {
		claims.TenantID = v
	}
	if v, ok := raw["email"].(string); ok {
		claims.Email = v
	}
	if v, ok := raw["name"].(string); ok {
		claims.Name = v
	}
	if v, ok := raw["iss"].(string); ok {
		claims.Issuer = v
	}
	if v, ok := raw["aud"].(string); ok {
		claims.Audience = v
	}
	if v, ok := raw["iat"].(float64); ok {
		claims.IssuedAt = int64(v)
	}
	if v, ok := raw["exp"].(float64); ok {
		claims.Expiry = int64(v)
	}
	if arr, ok := raw["roles"].([]interface{}); ok {
		for _, r := range arr {
			if s, ok := r.(string); ok {
				claims.Roles = append(claims.Roles, s)
			}
		}
	}

	return claims, nil
}
