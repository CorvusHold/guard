package config

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	AppEnv             string
	AppAddr            string
	CORSAllowedOrigins []string
	PublicBaseURL      string
	ForceHTTPS         bool

	DatabaseURL         string
	DBMaxConns          int32
	DBMinConns          int32
	DBMaxConnLifetime   time.Duration
	DBHealthCheckPeriod time.Duration
	DBReadReplicaURL    string

	RedisAddr string
	RedisDB   int

	JWTSigningKey       string
	JWTSigningAlgorithm string // HS256 | ES256
	JWTPrivateKeyPath   string // Path to EC private key PEM (for ES256)
	JWTKeyID            string // Key ID for JWKS (auto-generated if empty)
	IssuerMode          string `enums:"path,subdomain"` // path | subdomain
	IssuerPathPrefix    string // default: /t
	// IssuerSubdomainTemplate supports future domain-based issuers, e.g. "{tenant}.auth.example.com"
	IssuerSubdomainTemplate string
	AccessTokenTTL          time.Duration
	RefreshTokenTTL         time.Duration
	MagicLinkTTL            time.Duration

	SMTPHost      string
	SMTPPort      int
	SMTPUsername  string
	SMTPPassword  string
	SMTPFrom      string
	EmailProvider string // smtp | brevo
	BrevoAPIKey   string
	BrevoSender   string

	DefaultAuthMode string // bearer | cookie

	CookieSameSite http.SameSite
}

func Load() (Config, error) {
	c := Config{}

	c.AppEnv = getEnv("APP_ENV", "development")
	c.AppAddr = getEnv("APP_ADDR", ":8080")
	c.CORSAllowedOrigins = splitCSV(getEnv("CORS_ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:5173"))
	c.PublicBaseURL = getEnv("PUBLIC_BASE_URL", "http://localhost:8080")
	c.ForceHTTPS = getBool("FORCE_HTTPS", false)

	c.DatabaseURL = getEnv("DATABASE_URL", "postgres://guard:guard@localhost:5433/guard?sslmode=disable")
	c.DBMaxConns = int32(getInt("DB_MAX_CONNS", 25))
	c.DBMinConns = int32(getInt("DB_MIN_CONNS", 5))
	c.DBMaxConnLifetime = getDuration("DB_MAX_CONN_LIFETIME", 30*time.Minute)
	c.DBHealthCheckPeriod = getDuration("DB_HEALTH_CHECK_PERIOD", 15*time.Second)
	c.DBReadReplicaURL = getEnv("DB_READ_REPLICA_URL", "")

	c.RedisAddr = getEnv("REDIS_ADDR", "localhost:6379")
	c.RedisDB = getInt("REDIS_DB", 0)

	c.JWTSigningKey = getEnv("JWT_SIGNING_KEY", "dev-insecure-change-this")
	c.JWTSigningAlgorithm = getEnv("JWT_SIGNING_ALGORITHM", "HS256")
	c.JWTPrivateKeyPath = getEnv("JWT_PRIVATE_KEY_PATH", "")
	c.JWTKeyID = getEnv("JWT_KEY_ID", "")
	issuerMode := strings.ToLower(getEnv("ISSUER_MODE", "path"))
	if issuerMode != "path" && issuerMode != "subdomain" {
		issuerMode = "path"
	}
	c.IssuerMode = issuerMode
	c.IssuerPathPrefix = getEnv("ISSUER_PATH_PREFIX", "/t")
	c.IssuerSubdomainTemplate = getEnv("ISSUER_SUBDOMAIN_TEMPLATE", "")
	c.AccessTokenTTL = getDuration("ACCESS_TOKEN_TTL", time.Minute*15)
	c.RefreshTokenTTL = getDuration("REFRESH_TOKEN_TTL", time.Hour*24*30)
	c.MagicLinkTTL = getDuration("MAGIC_LINK_TTL", 15*time.Minute)

	c.SMTPHost = getEnv("SMTP_HOST", "localhost")
	c.SMTPPort = getInt("SMTP_PORT", 1025)
	c.SMTPUsername = getEnv("SMTP_USERNAME", "")
	c.SMTPPassword = getEnv("SMTP_PASSWORD", "")
	c.SMTPFrom = getEnv("SMTP_FROM", "no-reply@local.dev")
	c.EmailProvider = strings.ToLower(getEnv("EMAIL_PROVIDER", "smtp"))
	c.BrevoAPIKey = getEnv("BREVO_API_KEY", "")
	c.BrevoSender = getEnv("BREVO_SENDER", c.SMTPFrom)

	// Default auth mode: bearer | cookie
	authMode := strings.ToLower(getEnv("DEFAULT_AUTH_MODE", "bearer"))
	if authMode != "bearer" && authMode != "cookie" {
		authMode = "bearer" // fallback to bearer if invalid value
	}
	c.DefaultAuthMode = authMode
	sameSite := getSameSite("COOKIE_SAME_SITE", http.SameSiteLaxMode)
	if sameSite == http.SameSiteDefaultMode {
		sameSite = http.SameSiteLaxMode
	}
	c.CookieSameSite = sameSite

	// Refuse to start in production with the insecure default JWT signing key
	env := strings.ToLower(c.AppEnv)
	if (env == "production" || env == "prod") && c.JWTSigningKey == "dev-insecure-change-this" {
		return Config{}, fmt.Errorf("JWT_SIGNING_KEY must be set to a secure value in production (current value is the insecure default)")
	}

	return c, nil
}

func getEnv(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

func getInt(key string, def int) int {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return def
}

func getDuration(key string, def time.Duration) time.Duration {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		d, err := time.ParseDuration(v)
		if err == nil {
			return d
		}
	}
	return def
}

func getBool(key string, def bool) bool {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return def
}

func getSameSite(key string, def http.SameSite) http.SameSite {
	v, ok := os.LookupEnv(key)
	if !ok {
		return def
	}
	v = strings.TrimSpace(v)
	if v == "" {
		return def
	}
	switch strings.ToLower(v) {
	case "lax":
		return http.SameSiteLaxMode
	case "strict":
		return http.SameSiteStrictMode
	case "none":
		return http.SameSiteNoneMode
	case "default":
		return http.SameSiteDefaultMode
	default:
		return def
	}
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	res := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			res = append(res, p)
		}
	}
	if len(res) == 0 {
		return []string{"*"}
	}
	return res
}

func (c Config) String() string {
	return fmt.Sprintf("env=%s addr=%s db=%s redis=%s/%d", c.AppEnv, c.AppAddr, c.DatabaseURL, c.RedisAddr, c.RedisDB)
}

// ValidateJWTConfig validates that JWT configuration is properly set for ES256 signing.
// This centralized validation ensures consistent error handling across the application.
//
// Guard now exclusively uses ES256 (asymmetric cryptography) for JWT signing to enhance
// security and enable proper key rotation via JWKS. This function enforces the requirement
// that ES256 algorithm is configured with a valid private key path.
//
// Returns an error if:
//   - JWT_SIGNING_ALGORITHM is not "ES256"
//   - JWT_PRIVATE_KEY_PATH is empty when ES256 is configured
//
// Example usage:
//
//	if err := cfg.ValidateJWTConfig(); err != nil {
//	    log.Fatal().Err(err).Msg("invalid JWT configuration")
//	}
func (c Config) ValidateJWTConfig() error {
	alg := strings.TrimSpace(c.JWTSigningAlgorithm)

	// ES256 is now the only supported algorithm for production security
	if !strings.EqualFold(alg, "ES256") {
		return fmt.Errorf(
			"JWT_SIGNING_ALGORITHM must be ES256 (got: %q). "+
				"Guard no longer supports HS256/HMAC shared secrets. "+
				"See docs/IAM_VNEXT_MIGRATION.md for migration guide",
			c.JWTSigningAlgorithm,
		)
	}

	// ES256 requires an EC private key file
	if strings.TrimSpace(c.JWTPrivateKeyPath) == "" {
		return fmt.Errorf(
			"JWT_PRIVATE_KEY_PATH is required when JWT_SIGNING_ALGORITHM=ES256. "+
				"Generate a key with: openssl ecparam -genkey -name prime256v1 -noout -out jwt-es256-private.pem",
		)
	}

	return nil
}

// LoadECKeys loads an ES256 EC private/public key pair from a PEM file.
// This is used for JWT signing (private key) and verification (public key).
//
// The PEM file should contain an EC PRIVATE KEY block with the P-256 curve.
// Both the private and public keys are returned for signing and verification operations.
//
// Returns:
//   - privateKey: *ecdsa.PrivateKey for signing JWTs
//   - publicKey: *ecdsa.PublicKey for verifying JWTs
//   - error: if the file cannot be read or parsed
//
// Example usage:
//
//	privateKey, publicKey, err := config.LoadECKeys(cfg.JWTPrivateKeyPath)
//	if err != nil {
//	    return fmt.Errorf("failed to load EC keys: %w", err)
//	}
func LoadECKeys(pemPath string) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	keyData, err := os.ReadFile(pemPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read EC private key file %q: %w", pemPath, err)
	}

	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, nil, fmt.Errorf("no PEM block found in EC private key file %q", pemPath)
	}

	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse EC private key from %q: %w", pemPath, err)
	}

	publicKey := &privateKey.PublicKey
	return privateKey, publicKey, nil
}
