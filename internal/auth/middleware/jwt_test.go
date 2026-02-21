package middleware

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/corvusHold/guard/internal/auth/domain"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

func writePEM(t *testing.T, blockType string, der []byte) string {
	t.Helper()
	f, err := os.CreateTemp("", "guard-jwt-key-*.pem")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: blockType, Bytes: der}); err != nil {
		t.Fatalf("encode pem: %v", err)
	}
	return f.Name()
}

func TestLoadECPublicKey_FromECPrivatePKCS1AndPublicKey(t *testing.T) {
	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}

	ecDER, err := x509.MarshalECPrivateKey(ecPriv)
	if err != nil {
		t.Fatalf("marshal ec key: %v", err)
	}
	ecPath := writePEM(t, "EC PRIVATE KEY", ecDER)
	defer os.Remove(ecPath)

	pub1, err := loadECPublicKey(ecPath)
	if err != nil {
		t.Fatalf("load EC PRIVATE KEY: %v", err)
	}
	if pub1 == nil {
		t.Fatal("expected non-nil public key from EC private key")
	}

	pkcs8, err := x509.MarshalPKCS8PrivateKey(ecPriv)
	if err != nil {
		t.Fatalf("marshal pkcs8 key: %v", err)
	}
	pkcs8Path := writePEM(t, "PRIVATE KEY", pkcs8)
	defer os.Remove(pkcs8Path)

	pub2, err := loadECPublicKey(pkcs8Path)
	if err != nil {
		t.Fatalf("load PRIVATE KEY: %v", err)
	}
	if pub2 == nil {
		t.Fatal("expected non-nil public key from PKCS#8 key")
	}

	pkix, err := x509.MarshalPKIXPublicKey(&ecPriv.PublicKey)
	if err != nil {
		t.Fatalf("marshal pkix public key: %v", err)
	}
	pubPath := writePEM(t, "PUBLIC KEY", pkix)
	defer os.Remove(pubPath)

	pub3, err := loadECPublicKey(pubPath)
	if err != nil {
		t.Fatalf("load PUBLIC KEY: %v", err)
	}
	if pub3 == nil {
		t.Fatal("expected non-nil public key from public key pem")
	}
}

func TestLoadECPublicKey_ErrorPaths(t *testing.T) {
	if _, err := loadECPublicKey("/does/not/exist.pem"); err == nil {
		t.Fatal("expected error for missing key file")
	}

	f, err := os.CreateTemp("", "guard-jwt-empty-*.pem")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	emptyPath := f.Name()
	f.Close()
	defer os.Remove(emptyPath)
	if _, err := loadECPublicKey(emptyPath); err == nil {
		t.Fatal("expected no pem block error")
	}

	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	rsaPKCS8, err := x509.MarshalPKCS8PrivateKey(rsaPriv)
	if err != nil {
		t.Fatalf("marshal rsa pkcs8: %v", err)
	}
	rsaPath := writePEM(t, "PRIVATE KEY", rsaPKCS8)
	defer os.Remove(rsaPath)
	if _, err := loadECPublicKey(rsaPath); err == nil {
		t.Fatal("expected EC key type error for RSA private key")
	}

	unsupportedPath := writePEM(t, "CERTIFICATE", []byte("not-cert"))
	defer os.Remove(unsupportedPath)
	if _, err := loadECPublicKey(unsupportedPath); err == nil {
		t.Fatal("expected unsupported pem type error")
	}
}

func TestUserIDAndTenantID_ContextHelpers(t *testing.T) {
	e := echo.New()
	c := e.NewContext(nil, nil)

	if _, ok := UserID(c); ok {
		t.Fatal("expected missing user id to return ok=false")
	}
	if _, ok := TenantID(c); ok {
		t.Fatal("expected missing tenant id to return ok=false")
	}

	uid := uuid.New()
	tid := uuid.New()
	c.Set(ctxUserIDKey, uid)
	c.Set(ctxTenantIDKey, tid)

	gotUID, ok := UserID(c)
	if !ok || gotUID != uid {
		t.Fatalf("expected user id %s, got %s (ok=%v)", uid, gotUID, ok)
	}
	gotTID, ok := TenantID(c)
	if !ok || gotTID != tid {
		t.Fatalf("expected tenant id %s, got %s (ok=%v)", tid, gotTID, ok)
	}
}

func signES256Token(t *testing.T, key *ecdsa.PrivateKey, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	signed, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signed
}

func newEchoCtxWithAuthHeader(token string) echo.Context {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	return e.NewContext(req, rec)
}

func TestNewJWTWithPublicKey_SuccessAndCookieFallback(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	uid := uuid.New()
	tid := uuid.New()
	tok := signES256Token(t, key, jwt.MapClaims{
		"sub": uid.String(),
		"ten": tid.String(),
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(5 * time.Minute).Unix(),
	})

	mw := newJWTWithPublicKey(&key.PublicKey)

	// Authorization header path
	c := newEchoCtxWithAuthHeader(tok)
	called := false
	h := mw(func(c echo.Context) error {
		called = true
		return c.NoContent(http.StatusNoContent)
	})
	if err := h(c); err != nil {
		t.Fatalf("middleware returned error: %v", err)
	}
	if !called {
		t.Fatal("expected downstream handler to be called")
	}
	if got, ok := UserID(c); !ok || got != uid {
		t.Fatalf("expected user id set, got %s (ok=%v)", got, ok)
	}
	if got, ok := TenantID(c); !ok || got != tid {
		t.Fatalf("expected tenant id set, got %s (ok=%v)", got, ok)
	}

	// Cookie fallback path
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: domain.CookieAccessToken, Value: tok})
	rec := httptest.NewRecorder()
	c2 := e.NewContext(req, rec)
	if err := h(c2); err != nil {
		t.Fatalf("middleware cookie path returned error: %v", err)
	}
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected success via cookie fallback, got status %d", rec.Code)
	}
}

func TestNewJWTWithPublicKey_ErrorPaths(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	validUID := uuid.New().String()
	validTID := uuid.New().String()

	badAlg := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": validUID, "ten": validTID, "iat": time.Now().Unix()})
	badAlgToken, err := badAlg.SignedString([]byte("secret"))
	if err != nil {
		t.Fatalf("sign hs token: %v", err)
	}

	cases := []struct {
		name   string
		key    *ecdsa.PublicKey
		token  string
		status int
	}{
		{name: "missing token", key: &key.PublicKey, token: "", status: http.StatusUnauthorized},
		{name: "invalid signing alg", key: &key.PublicKey, token: badAlgToken, status: http.StatusUnauthorized},
		{name: "nil public key", key: nil, token: signES256Token(t, key, jwt.MapClaims{"sub": validUID, "ten": validTID, "iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix()}), status: http.StatusUnauthorized},
		{name: "invalid uuid claims", key: &key.PublicKey, token: signES256Token(t, key, jwt.MapClaims{"sub": "not-uuid", "ten": "not-uuid", "iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix()}), status: http.StatusUnauthorized},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mw := newJWTWithPublicKey(tc.key)
			e := echo.New()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.token != "" {
				req.Header.Set("Authorization", "Bearer "+tc.token)
			}
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			h := mw(func(c echo.Context) error {
				t.Fatalf("downstream should not be called for case %s", tc.name)
				return nil
			})
			_ = h(c)
			if rec.Code != tc.status {
				t.Fatalf("expected status %d, got %d", tc.status, rec.Code)
			}
		})
	}
}
