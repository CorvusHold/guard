package guard

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func b64(v any) string {
	b, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(b)
}

func TestSplitJWT(t *testing.T) {
	parts, err := splitJWT("a.b.c")
	if err != nil {
		t.Fatalf("splitJWT returned error: %v", err)
	}
	if len(parts) != 3 || parts[0] != "a" || parts[1] != "b" || parts[2] != "c" {
		t.Fatalf("unexpected parts: %#v", parts)
	}
}

func TestSplitJWT_Invalid(t *testing.T) {
	if _, err := splitJWT("a.b"); err == nil {
		t.Fatal("expected malformed token error")
	}
}

func TestParseJWTHeader_AndDecodePayload(t *testing.T) {
	token := strings.Join([]string{
		b64(map[string]any{"alg": "ES256", "kid": "k1"}),
		b64(map[string]any{
			"sub": "u1", "ten": "t1", "email": "u@example.com", "name": "User",
			"iss": "issuer", "aud": "audience", "iat": float64(1), "exp": float64(2),
			"roles": []any{"admin", 42, "viewer"},
		}),
		"sig",
	}, ".")

	h, err := parseJWTHeader(token)
	if err != nil {
		t.Fatalf("parseJWTHeader returned error: %v", err)
	}
	if h["alg"] != "ES256" || h["kid"] != "k1" {
		t.Fatalf("unexpected header: %#v", h)
	}

	parts, _ := splitJWT(token)
	claims, err := decodePayload(parts[1])
	if err != nil {
		t.Fatalf("decodePayload returned error: %v", err)
	}
	if claims.Subject != "u1" || claims.TenantID != "t1" || claims.Email != "u@example.com" {
		t.Fatalf("unexpected claims: %#v", claims)
	}
	if len(claims.Roles) != 2 || claims.Roles[0] != "admin" || claims.Roles[1] != "viewer" {
		t.Fatalf("unexpected roles: %#v", claims.Roles)
	}
}

func TestParseJWTHeaderAndDecodePayload_InvalidInputs(t *testing.T) {
	if _, err := parseJWTHeader("@@.b.c"); err == nil {
		t.Fatal("expected invalid base64 header error")
	}
	if _, err := decodePayload("@@"); err == nil {
		t.Fatal("expected invalid payload error")
	}
}

func TestParseECPublicKey_InvalidBase64(t *testing.T) {
	_, err := parseECPublicKey(jwkKey{X: "@@", Y: "@@"})
	if err == nil {
		t.Fatal("expected parseECPublicKey error")
	}
}

func TestGetKey_UsesCacheAndStaleFallback(t *testing.T) {
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: big.NewInt(1), Y: big.NewInt(2)}
	v := NewTokenValidator("https://guard.example.com", WithValidatorHTTPClient(&http.Client{
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("network down")
		}),
	}))
	v.keys["kid-1"] = pub

	// fresh cache: should return immediately
	v.fetchedAt = time.Now()
	key, err := v.getKey(context.Background(), "kid-1")
	if err != nil || key != pub {
		t.Fatalf("expected cached key without fetch, key=%v err=%v", key, err)
	}

	// stale cache + fetch failure: should fail-open to stale cached key
	v.fetchedAt = time.Now().Add(-2 * v.cacheTTL)
	key, err = v.getKey(context.Background(), "kid-1")
	if err != nil || key != pub {
		t.Fatalf("expected stale fallback key on fetch error, key=%v err=%v", key, err)
	}
}

func TestCryptoHelpers_HMACAndECDSAAndDERParser(t *testing.T) {
	msg := []byte("hello")
	secret := []byte("secret")
	mac := hmac.New(sha256.New, secret)
	mac.Write(msg)
	sig := mac.Sum(nil)

	if !hmacVerify(secret, msg, sig) {
		t.Fatal("expected valid HMAC signature")
	}
	if hmacVerify(secret, msg, []byte("bad")) {
		t.Fatal("expected invalid HMAC signature")
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	h := sha256.Sum256(msg)
	r, s, err := ecdsa.Sign(rand.Reader, priv, h[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	rb := r.FillBytes(make([]byte, 32))
	sb := s.FillBytes(make([]byte, 32))
	rawSig := append(rb, sb...)
	if !ecdsaVerify(&priv.PublicKey, msg, rawSig) {
		t.Fatal("expected valid raw ECDSA signature")
	}

	derSig, err := asn1.Marshal(struct{ R, S *big.Int }{R: r, S: s})
	if err != nil {
		t.Fatalf("marshal DER: %v", err)
	}
	if !ecdsaVerify(&priv.PublicKey, msg, derSig) {
		t.Fatal("expected valid DER ECDSA signature")
	}

	if _, _, err := parseDERSignature([]byte("bad")); err == nil {
		t.Fatal("expected parseDERSignature error")
	}
}

func makeES256Token(t *testing.T, priv *ecdsa.PrivateKey, kid string, payload map[string]any) string {
	t.Helper()
	head, _ := json.Marshal(map[string]any{"alg": "ES256", "kid": kid})
	body, _ := json.Marshal(payload)
	h := base64.RawURLEncoding.EncodeToString(head)
	p := base64.RawURLEncoding.EncodeToString(body)
	msg := h + "." + p
	digest := sha256.Sum256([]byte(msg))
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	rb := r.FillBytes(make([]byte, 32))
	sb := s.FillBytes(make([]byte, 32))
	sig := append(rb, sb...)
	return msg + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func TestTokenValidatorOptionsAndFetchJWKS(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	x := base64.RawURLEncoding.EncodeToString(priv.PublicKey.X.FillBytes(make([]byte, 32)))
	y := base64.RawURLEncoding.EncodeToString(priv.PublicKey.Y.FillBytes(make([]byte, 32)))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/t/tenant-x/.well-known/jwks.json":
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{
				{"kty": "EC", "crv": "P-256", "x": x, "y": y, "kid": "kid-1"},
				{"kty": "RSA", "kid": "ignore-me"},
			}})
		case "/bad-json":
			_, _ = io.WriteString(w, "{")
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	v := NewTokenValidator(server.URL,
		WithValidatorTenantID(" tenant-x "),
		WithJWKSCacheTTL(2*time.Minute),
	)
	if v.tenantID != "tenant-x" || v.cacheTTL != 2*time.Minute {
		t.Fatalf("options not applied: tenantID=%q cacheTTL=%s", v.tenantID, v.cacheTTL)
	}
	if err := v.fetchJWKS(context.Background()); err != nil {
		t.Fatalf("fetchJWKS failed: %v", err)
	}
	if _, ok := v.keys["kid-1"]; !ok {
		t.Fatalf("expected EC key loaded from JWKS, got keys=%v", v.keys)
	}

	v2 := NewTokenValidator(server.URL + "/bad-status")
	if err := v2.fetchJWKS(context.Background()); err == nil {
		t.Fatal("expected fetchJWKS error for non-200 status")
	}
	v3 := NewTokenValidator(server.URL + "/bad-json")
	if err := v3.fetchJWKS(context.Background()); err == nil {
		t.Fatal("expected fetchJWKS error for invalid JSON")
	}
}

func TestTokenValidatorValidateBranches(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	v := NewTokenValidator("https://guard.example.com")
	v.keys["kid-ok"] = &priv.PublicKey
	v.fetchedAt = time.Now()

	badAlg := strings.Join([]string{b64(map[string]any{"alg": "HS256", "kid": "kid-ok"}), b64(map[string]any{"sub": "u1"}), "sig"}, ".")
	if _, err := v.Validate(context.Background(), badAlg); err == nil || !errors.Is(err, ErrUnsupportedAlg) {
		t.Fatalf("expected ErrUnsupportedAlg, got %v", err)
	}

	invalidSig := strings.Join([]string{b64(map[string]any{"alg": "ES256", "kid": "kid-ok"}), b64(map[string]any{"sub": "u1", "exp": float64(time.Now().Add(time.Hour).Unix())}), base64.RawURLEncoding.EncodeToString([]byte("bad"))}, ".")
	if _, err := v.Validate(context.Background(), invalidSig); err == nil || !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("expected ErrTokenInvalid, got %v", err)
	}

	expired := makeES256Token(t, priv, "kid-ok", map[string]any{"sub": "u1", "ten": "t1", "exp": float64(time.Now().Add(-time.Minute).Unix())})
	if _, err := v.Validate(context.Background(), expired); err == nil || !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expected ErrTokenExpired, got %v", err)
	}

	ok := makeES256Token(t, priv, "kid-ok", map[string]any{
		"sub": "u1", "ten": "t1", "email": "u@example.com", "name": "User",
		"iss": "https://guard.example.com/", "aud": "aud", "iat": float64(time.Now().Unix()), "exp": float64(time.Now().Add(time.Hour).Unix()),
		"roles": []string{"admin", "viewer"},
	})
	claims, err := v.Validate(context.Background(), ok)
	if err != nil {
		t.Fatalf("expected valid token, got error: %v", err)
	}
	if claims.Subject != "u1" || claims.TenantID != "t1" || len(claims.Roles) != 2 {
		t.Fatalf("unexpected claims: %+v", claims)
	}

	vf := NewTokenValidator("https://guard.example.com", WithValidatorHTTPClient(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("down")
	})}))
	tok := strings.Join([]string{b64(map[string]any{"alg": "ES256", "kid": "missing"}), b64(map[string]any{"sub": "u1"}), "sig"}, ".")
	if _, err := vf.Validate(context.Background(), tok); err == nil {
		t.Fatal("expected validate error when key fetch fails")
	}
}
