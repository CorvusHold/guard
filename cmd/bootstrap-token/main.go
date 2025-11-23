package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"

	authrepo "github.com/corvusHold/guard/internal/auth/repository"
	"github.com/corvusHold/guard/internal/config"
	tenrepo "github.com/corvusHold/guard/internal/tenants/repository"
	tensvc "github.com/corvusHold/guard/internal/tenants/service"
)

type bootstrapResult struct {
	TenantID   uuid.UUID `json:"tenant_id"`
	TenantName string    `json:"tenant_name"`
	UserID     uuid.UUID `json:"user_id"`
	Email      string    `json:"email"`
	Password   string    `json:"password"`
	Token      string    `json:"token"`
	ExpiresAt  time.Time `json:"expires_at"`
}

func main() {
	var (
		tokenTTL = flag.Duration("ttl", 15*time.Minute, "lifetime for the issued bootstrap token")
		prefix   = flag.String("prefix", "bootstrap", "tenant name prefix")
		email    = flag.String("email", "", "explicit email for the bootstrap admin user")
		first    = flag.String("first-name", "Bootstrap", "first name for the admin user")
		last     = flag.String("last-name", "Admin", "last name for the admin user")
		output   = flag.String("output", "env", "output format: env or json")
	)
	flag.Parse()

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pgCfg, err := pgxpool.ParseConfig(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("invalid DATABASE_URL: %v", err)
	}
	pool, err := pgxpool.NewWithConfig(ctx, pgCfg)
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}
	defer pool.Close()

	result, err := provisionPrincipal(ctx, pool, *prefix, *email, *first, *last)
	if err != nil {
		log.Fatalf("failed to create bootstrap principal: %v", err)
	}

	expiresAt := time.Now().Add(*tokenTTL)
	token, err := mintToken(cfg, result.UserID, result.TenantID, expiresAt)
	if err != nil {
		log.Fatalf("failed to mint token: %v", err)
	}
	result.Token = token
	result.ExpiresAt = expiresAt.UTC()

	switch strings.ToLower(*output) {
	case "json":
		encodeJSON(result)
	case "env":
		printEnv(result)
	default:
		log.Fatalf("unsupported output format: %s", *output)
	}
}

func provisionPrincipal(ctx context.Context, pool *pgxpool.Pool, prefix, email, first, last string) (bootstrapResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	tenants := tensvc.New(tenrepo.New(pool))
	name := fmt.Sprintf("%s-%d", sanitizePrefix(prefix), time.Now().Unix())
	tenant, err := tenants.Create(ctx, name)
	if err != nil {
		return bootstrapResult{}, err
	}
	tenantID := uuid.UUID(tenant.ID.Bytes)

	credsEmail := email
	if credsEmail == "" {
		credsEmail = fmt.Sprintf("%s@bootstrap.local", strings.ReplaceAll(name, " ", "-"))
	}
	password, err := randomPassword(24)
	if err != nil {
		return bootstrapResult{}, err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return bootstrapResult{}, err
	}

	auth := authrepo.New(pool)
	userID := uuid.New()
	if err := auth.CreateUser(ctx, userID, first, last, []string{"admin"}); err != nil {
		return bootstrapResult{}, err
	}
	if err := auth.AddUserToTenant(ctx, userID, tenantID); err != nil {
		return bootstrapResult{}, err
	}
	if err := auth.CreateAuthIdentity(ctx, uuid.New(), userID, tenantID, credsEmail, string(hash)); err != nil {
		return bootstrapResult{}, err
	}

	return bootstrapResult{
		TenantID:   tenantID,
		TenantName: name,
		UserID:     userID,
		Email:      credsEmail,
		Password:   password,
	}, nil
}

func mintToken(cfg config.Config, userID, tenantID uuid.UUID, expiresAt time.Time) (string, error) {
	claims := jwt.MapClaims{
		"sub": userID.String(),
		"ten": tenantID.String(),
		"exp": expiresAt.Unix(),
		"iat": time.Now().Unix(),
		"iss": cfg.PublicBaseURL,
		"aud": cfg.PublicBaseURL,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return tok.SignedString([]byte(cfg.JWTSigningKey))
}

func randomPassword(length int) (string, error) {
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf)[:length], nil
}

func sanitizePrefix(prefix string) string {
	trimmed := strings.TrimSpace(prefix)
	if trimmed == "" {
		return "bootstrap"
	}
	return strings.ToLower(strings.ReplaceAll(trimmed, " ", "-"))
}

func encodeJSON(res bootstrapResult) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(res); err != nil {
		log.Fatalf("failed to encode JSON: %v", err)
	}
}

func printEnv(res bootstrapResult) {
	vars := map[string]string{
		"GUARD_API_TOKEN":         res.Token,
		"BOOTSTRAP_EXPIRES_AT":    res.ExpiresAt.Format(time.RFC3339),
		"BOOTSTRAP_TENANT_ID":     res.TenantID.String(),
		"BOOTSTRAP_TENANT_NAME":   res.TenantName,
		"BOOTSTRAP_USER_ID":       res.UserID.String(),
		"BOOTSTRAP_USER_EMAIL":    res.Email,
		"BOOTSTRAP_USER_PASSWORD": res.Password,
	}
	keys := make([]string, 0, len(vars))
	for k := range vars {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Printf("%s=%s\n", k, vars[k])
	}
}
