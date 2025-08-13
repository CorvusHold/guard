package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	AppEnv            string
	AppAddr           string
	CORSAllowedOrigins []string
	PublicBaseURL     string

	DatabaseURL string

	RedisAddr string
	RedisDB   int

	JWTSigningKey    string
	AccessTokenTTL   time.Duration
	RefreshTokenTTL  time.Duration
	MagicLinkTTL     time.Duration

	SMTPHost     string
	SMTPPort     int
	SMTPUsername string
	SMTPPassword string
	SMTPFrom     string
	EmailProvider string // smtp | brevo
	BrevoAPIKey   string
	BrevoSender   string

	WorkOSAPIKey      string
	WorkOSClientID    string
	WorkOSClientSecret string
}

func Load() (Config, error) {
	c := Config{}

	c.AppEnv = getEnv("APP_ENV", "development")
	c.AppAddr = getEnv("APP_ADDR", ":8080")
	c.CORSAllowedOrigins = splitCSV(getEnv("CORS_ALLOWED_ORIGINS", "http://localhost:3000"))
	c.PublicBaseURL = getEnv("PUBLIC_BASE_URL", "http://localhost:8080")

	c.DatabaseURL = getEnv("DATABASE_URL", "postgres://guard:guard@localhost:5433/guard?sslmode=disable")

	c.RedisAddr = getEnv("REDIS_ADDR", "localhost:6380")
	c.RedisDB = getInt("REDIS_DB", 0)

	c.JWTSigningKey = getEnv("JWT_SIGNING_KEY", "dev-insecure-change-this")
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

	c.WorkOSAPIKey = getEnv("WORKOS_API_KEY", "")
	c.WorkOSClientID = getEnv("WORKOS_CLIENT_ID", "")
	c.WorkOSClientSecret = getEnv("WORKOS_CLIENT_SECRET", "")

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
