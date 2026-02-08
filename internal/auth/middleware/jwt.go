package middleware

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog/log"

	"github.com/corvusHold/guard/internal/config"
)

const (
	ctxUserIDKey   = "auth_user_id"
	ctxTenantIDKey = "auth_tenant_id"
)

// NewJWT returns an Echo middleware that validates access JWTs and
// stores user and tenant IDs in the context.
func NewJWT(cfg config.Config) echo.MiddlewareFunc {
	// Pre-load EC public key if ES256 is configured. We allow either a private or public key PEM.
	var ecPubKey *ecdsa.PublicKey
	if cfg.JWTSigningAlgorithm == "ES256" {
		if cfg.JWTPrivateKeyPath == "" {
			log.Fatal().Msg("JWT_PRIVATE_KEY_PATH is required when JWT_SIGNING_ALGORITHM=ES256")
		}
		key, err := loadECPublicKey(cfg.JWTPrivateKeyPath)
		if err != nil {
			log.Fatal().Err(err).Str("path", cfg.JWTPrivateKeyPath).Msg("failed to load EC public/public key for ES256 JWT verification")
		}
		ecPubKey = key
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			auth := c.Request().Header.Get("Authorization")

			// If no Authorization header, fall back to cookie-based session token
			if auth == "" {
				if cookie, err := c.Cookie("guard_access_token"); err == nil && cookie != nil && cookie.Value != "" {
					auth = "Bearer " + cookie.Value
				}
			}

			if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
				return c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
			}
			tokStr := strings.TrimPrefix(auth, "Bearer ")

			tok, err := jwt.Parse(tokStr, func(token *jwt.Token) (any, error) {
				switch token.Method.(type) {
				case *jwt.SigningMethodECDSA:
					if ecPubKey != nil {
						return ecPubKey, nil
					}
					return nil, fmt.Errorf("no EC public key configured for ES256 verification")
				case *jwt.SigningMethodHMAC:
					return []byte(cfg.JWTSigningKey), nil
				default:
					return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
				}
			}, jwt.WithLeeway(30*time.Second), jwt.WithIssuedAt(), jwt.WithValidMethods([]string{"HS256", "ES256"}))
			if err != nil || !tok.Valid {
				return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid token"})
			}

			claims, ok := tok.Claims.(jwt.MapClaims)
			if !ok {
				return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid claims"})
			}
			sub, _ := claims["sub"].(string)
			ten, _ := claims["ten"].(string)
			uid, err1 := uuid.Parse(sub)
			tid, err2 := uuid.Parse(ten)
			if err1 != nil || err2 != nil {
				return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid subject or tenant"})
			}

			c.Set(ctxUserIDKey, uid)
			c.Set(ctxTenantIDKey, tid)
			return next(c)
		}
	}
}

// loadECPublicKey reads an EC private key PEM file and extracts the public key.
func loadECPublicKey(path string) (*ecdsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}
	switch block.Type {
	case "EC PRIVATE KEY":
		privKey, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return &privKey.PublicKey, nil
	case "PUBLIC KEY", "EC PUBLIC KEY":
		pubAny, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		pubKey, ok := pubAny.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("expected EC PUBLIC KEY, got %T in %s", pubAny, path)
		}
		return pubKey, nil
	default:
		return nil, fmt.Errorf("expected EC PRIVATE KEY or EC PUBLIC KEY PEM block, got %q in %s", block.Type, path)
	}
}

// UserID returns the authenticated user's ID from context.
func UserID(c echo.Context) (uuid.UUID, bool) {
	v := c.Get(ctxUserIDKey)
	if v == nil {
		return uuid.UUID{}, false
	}
	id, ok := v.(uuid.UUID)
	return id, ok
}

// TenantID returns the authenticated tenant's ID from context.
func TenantID(c echo.Context) (uuid.UUID, bool) {
	v := c.Get(ctxTenantIDKey)
	if v == nil {
		return uuid.UUID{}, false
	}
	id, ok := v.(uuid.UUID)
	return id, ok
}
