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
	"net/url"
	"strings"
	"sync"
	"time"
)

// Typed errors for token validation.
var (
	ErrTokenExpired    = errors.New("guard: token expired")
	ErrTokenInvalid    = errors.New("guard: token invalid")
	ErrTokenMalform    = errors.New("guard: token malformed")
	ErrJWKSFetch       = errors.New("guard: failed to fetch JWKS")
	ErrKeyNotFound     = errors.New("guard: signing key not found in JWKS")
	ErrUnsupportedAlg  = errors.New("guard: unsupported signing algorithm")
	ErrInvalidIssuer   = errors.New("guard: invalid issuer")
	ErrInvalidAudience = errors.New("guard: invalid audience")
)

// TokenClaims represents the validated claims from a Guard JWT.
type TokenClaims struct {
	Subject  string   `json:"sub"`
	TenantID string   `json:"ten"`
	Email    string   `json:"email"`
	Name     string   `json:"name"`
	Roles    []string `json:"roles"`
	Issuer   string   `json:"iss"`
	Audience []string `json:"aud"`
	IssuedAt int64    `json:"iat"`
	Expiry   int64    `json:"exp"`
}

// AudienceContains reports whether the token audience list contains aud.
func (c *TokenClaims) AudienceContains(aud string) bool {
	aud = strings.TrimSpace(aud)
	if aud == "" {
		return false
	}
	for _, candidate := range c.Audience {
		if candidate == aud {
			return true
		}
	}
	return false
}

// PrimaryAudience returns the first audience value, or an empty string when unset.
func (c *TokenClaims) PrimaryAudience() string {
	if len(c.Audience) == 0 {
		return ""
	}
	return c.Audience[0]
}

// AudienceString returns the first audience value for backwards-compatibility usage.
func (c *TokenClaims) AudienceString() string {
	return c.PrimaryAudience()
}

// Logger is a minimal logging interface for optional diagnostics.
type Logger interface {
	Printf(format string, v ...interface{})
}

type noopLogger struct{}

func (noopLogger) Printf(string, ...interface{}) {}

// TokenValidator validates Guard-issued JWTs using ES256 public keys from JWKS.
type TokenValidator struct {
	guardURL         string
	tenantID         string
	expectedAudience string
	httpClient       *http.Client
	cacheTTL         time.Duration
	logger           Logger

	mu            sync.RWMutex
	keys          map[string]*ecdsa.PublicKey
	fetchedAt     time.Time
	fetchInFlight bool
	fetchDone     chan struct{}
	lastFetchErr  error
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

// WithExpectedAudience enforces a required audience match during token validation.
// When empty, audience validation is skipped.
func WithExpectedAudience(audience string) TokenValidatorOption {
	return func(v *TokenValidator) { v.expectedAudience = strings.TrimSpace(audience) }
}

// WithValidatorLogger sets a logger for non-fatal JWKS parsing diagnostics.
func WithValidatorLogger(l Logger) TokenValidatorOption {
	return func(v *TokenValidator) {
		if l == nil {
			v.logger = noopLogger{}
			return
		}
		v.logger = l
	}
}

// NewTokenValidator creates a validator that fetches and caches JWKS from the Guard server.
func NewTokenValidator(guardURL string, opts ...TokenValidatorOption) *TokenValidator {
	v := &TokenValidator{
		guardURL:   guardURL,
		httpClient: &http.Client{Timeout: 10 * time.Second},
		cacheTTL:   time.Hour,
		keys:       make(map[string]*ecdsa.PublicKey),
		logger:     noopLogger{},
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

	if strings.TrimRight(claims.Issuer, "/") != v.expectedIssuer() {
		return nil, ErrInvalidIssuer
	}
	if v.expectedAudience != "" && !claims.AudienceContains(v.expectedAudience) {
		return nil, ErrInvalidAudience
	}

	return claims, nil
}

func (v *TokenValidator) expectedIssuer() string {
	base := strings.TrimRight(v.guardURL, "/")
	if v.tenantID == "" {
		return base
	}
	return base + "/t/" + url.PathEscape(v.tenantID)
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

	// Fetch JWKS (deduplicated across concurrent callers)
	if err := v.fetchJWKSOnce(ctx); err != nil {
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

func (v *TokenValidator) fetchJWKSOnce(ctx context.Context) error {
	v.mu.Lock()
	if v.fetchInFlight {
		done := v.fetchDone
		v.mu.Unlock()
		select {
		case <-done:
			v.mu.RLock()
			err := v.lastFetchErr
			v.mu.RUnlock()
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	v.fetchInFlight = true
	v.fetchDone = make(chan struct{})
	v.mu.Unlock()

	err := v.fetchJWKS(ctx)

	v.mu.Lock()
	v.lastFetchErr = err
	close(v.fetchDone)
	v.fetchInFlight = false
	v.mu.Unlock()

	return err
}

// fetchJWKS fetches the JWKS from the Guard server.
func (v *TokenValidator) fetchJWKS(ctx context.Context) error {
	jwksURL := strings.TrimRight(v.guardURL, "/") + "/.well-known/jwks.json"
	if v.tenantID != "" {
		jwksURL = strings.TrimRight(v.guardURL, "/") + "/t/" + url.PathEscape(v.tenantID) + "/.well-known/jwks.json"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
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
			v.logger.Printf("guard token validator: skipping jwks key kid=%q reason=unsupported key type/curve kty=%q crv=%q", k.Kid, k.Kty, k.Crv)
			continue
		}
		pub, err := parseECPublicKey(k)
		if err != nil {
			v.logger.Printf("guard token validator: skipping jwks key kid=%q reason=parse error: %v", k.Kid, err)
			continue
		}
		newKeys[k.Kid] = pub
	}
	if len(newKeys) == 0 {
		v.logger.Printf("guard token validator: jwks fetch produced zero valid EC keys; keeping previous cache")
		return fmt.Errorf("%w: no valid keys in jwks response", ErrJWKSFetch)
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
	parts := strings.SplitN(token, ".", 3)
	partCount := strings.Count(token, ".") + 1
	if len(parts) != 3 || partCount != 3 {
		return nil, fmt.Errorf("%w: expected 3 parts, got %d", ErrTokenMalform, partCount)
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
		claims.Audience = []string{v}
	} else if arr, ok := raw["aud"].([]interface{}); ok {
		for _, a := range arr {
			if s, ok := a.(string); ok {
				claims.Audience = append(claims.Audience, s)
			}
		}
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
