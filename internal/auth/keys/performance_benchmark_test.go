package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// BenchmarkJWTSigning_HS256_vs_ES256 compares the performance characteristics
// of HS256 (HMAC-based, symmetric) vs ES256 (ECDSA-based, asymmetric) JWT signing.
//
// Context for ES256 migration:
// Guard migrated from optional HS256 to mandatory ES256 for several security reasons:
//   1. Asymmetric cryptography enables proper key rotation via JWKS
//   2. No shared secrets to distribute/rotate across services
//   3. Better alignment with OAuth 2.0 / OIDC best practices
//   4. Private key can be kept server-side while public key is distributed via JWKS
//
// Performance characteristics:
//   - HS256: Faster signing (~5-20x), faster verification, but requires shared secret
//   - ES256: Slower signing/verification but provides better security model
//
// The performance trade-off is acceptable because:
//   - JWT operations are infrequent compared to overall request processing
//   - Security benefits outweigh the minor latency increase
//   - Modern CPUs handle ECDSA efficiently
//
// Run benchmarks with:
//   go test -bench=BenchmarkJWTSigning -benchmem -benchtime=5s

// Benchmark HS256 (HMAC-SHA256) JWT signing
func BenchmarkJWTSigning_HS256(b *testing.B) {
	// Setup: Generate a shared secret (HS256 uses symmetric key)
	secret := []byte("test-secret-key-32-bytes-long-minimum")

	claims := jwt.MapClaims{
		"sub": "user-123",
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(15 * time.Minute).Unix(),
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		_, err := token.SignedString(secret)
		if err != nil {
			b.Fatalf("HS256 signing failed: %v", err)
		}
	}
}

// Benchmark ES256 (ECDSA-SHA256) JWT signing
func BenchmarkJWTSigning_ES256(b *testing.B) {
	// Setup: Generate an EC P-256 private key (ES256 uses asymmetric key)
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatalf("failed to generate EC key: %v", err)
	}

	claims := jwt.MapClaims{
		"sub": "user-123",
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(15 * time.Minute).Unix(),
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
		_, err := token.SignedString(privateKey)
		if err != nil {
			b.Fatalf("ES256 signing failed: %v", err)
		}
	}
}

// Benchmark HS256 JWT verification
func BenchmarkJWTVerification_HS256(b *testing.B) {
	secret := []byte("test-secret-key-32-bytes-long-minimum")

	// Pre-generate a token to verify
	claims := jwt.MapClaims{
		"sub": "user-123",
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(15 * time.Minute).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(secret)
	if err != nil {
		b.Fatalf("failed to create test token: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return secret, nil
		})
		if err != nil {
			b.Fatalf("HS256 verification failed: %v", err)
		}
	}
}

// Benchmark ES256 JWT verification
func BenchmarkJWTVerification_ES256(b *testing.B) {
	// Generate EC key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatalf("failed to generate EC key: %v", err)
	}
	publicKey := &privateKey.PublicKey

	// Pre-generate a token to verify
	claims := jwt.MapClaims{
		"sub": "user-123",
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(15 * time.Minute).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		b.Fatalf("failed to create test token: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return publicKey, nil
		})
		if err != nil {
			b.Fatalf("ES256 verification failed: %v", err)
		}
	}
}

// Benchmark HMAC-SHA256 raw operation (for baseline comparison)
func BenchmarkRawHMAC_SHA256(b *testing.B) {
	secret := []byte("test-secret-key-32-bytes-long-minimum")
	message := []byte("sample.jwt.payload")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		h := hmac.New(sha256.New, secret)
		h.Write(message)
		_ = h.Sum(nil)
	}
}

// Benchmark ECDSA-SHA256 raw signing operation (for baseline comparison)
func BenchmarkRawECDSA_Sign(b *testing.B) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatalf("failed to generate EC key: %v", err)
	}

	message := []byte("sample.jwt.payload")
	hash := sha256.Sum256(message)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
		if err != nil {
			b.Fatalf("ECDSA sign failed: %v", err)
		}
	}
}

// Benchmark ECDSA-SHA256 raw verification operation (for baseline comparison)
func BenchmarkRawECDSA_Verify(b *testing.B) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatalf("failed to generate EC key: %v", err)
	}
	publicKey := &privateKey.PublicKey

	message := []byte("sample.jwt.payload")
	hash := sha256.Sum256(message)

	// Pre-sign the message
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		b.Fatalf("failed to pre-sign: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		valid := ecdsa.Verify(publicKey, hash[:], r, s)
		if !valid {
			b.Fatalf("ECDSA verify failed")
		}
	}
}

// Benchmark full JWT roundtrip (sign + verify) for HS256
func BenchmarkJWTRoundtrip_HS256(b *testing.B) {
	secret := []byte("test-secret-key-32-bytes-long-minimum")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Sign
		claims := jwt.MapClaims{
			"sub": "user-123",
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(15 * time.Minute).Unix(),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString(secret)
		if err != nil {
			b.Fatalf("HS256 signing failed: %v", err)
		}

		// Verify
		_, err = jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return secret, nil
		})
		if err != nil {
			b.Fatalf("HS256 verification failed: %v", err)
		}
	}
}

// Benchmark full JWT roundtrip (sign + verify) for ES256
func BenchmarkJWTRoundtrip_ES256(b *testing.B) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatalf("failed to generate EC key: %v", err)
	}
	publicKey := &privateKey.PublicKey

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Sign
		claims := jwt.MapClaims{
			"sub": "user-123",
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(15 * time.Minute).Unix(),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
		tokenString, err := token.SignedString(privateKey)
		if err != nil {
			b.Fatalf("ES256 signing failed: %v", err)
		}

		// Verify
		_, err = jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return publicKey, nil
		})
		if err != nil {
			b.Fatalf("ES256 verification failed: %v", err)
		}
	}
}

// Benchmark key generation cost (one-time operation, but useful to understand)
func BenchmarkKeyGeneration_EC_P256(b *testing.B) {
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			b.Fatalf("key generation failed: %v", err)
		}
	}
}

// Benchmark JWT parsing overhead (no verification)
func BenchmarkJWTParsing_NoVerify(b *testing.B) {
	// Create a sample token (we don't care about validity)
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	claims := jwt.MapClaims{"sub": "user-123"}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tokenString, _ := token.SignedString(privateKey)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Parse without verifying signature
		parser := jwt.NewParser(jwt.WithoutClaimsValidation())
		_, _, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})
		if err != nil {
			b.Fatalf("parse failed: %v", err)
		}
	}
}

// Benchmark base64 encoding overhead (JWT uses base64url encoding)
func BenchmarkBase64URLEncoding(b *testing.B) {
	data := []byte("sample.jwt.payload.with.some.reasonable.length.for.typical.claims")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = base64.RawURLEncoding.EncodeToString(data)
	}
}

// Benchmark base64 decoding overhead
func BenchmarkBase64URLDecoding(b *testing.B) {
	data := []byte("sample.jwt.payload.with.some.reasonable.length.for.typical.claims")
	encoded := base64.RawURLEncoding.EncodeToString(data)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil {
			b.Fatalf("decode failed: %v", err)
		}
	}
}
