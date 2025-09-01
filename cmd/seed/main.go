package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/pquerna/otp/totp"

	"github.com/corvusHold/guard/internal/config"
	adb "github.com/corvusHold/guard/internal/auth/domain"
	arepo "github.com/corvusHold/guard/internal/auth/repository"
	asvc "github.com/corvusHold/guard/internal/auth/service"
	sdomain "github.com/corvusHold/guard/internal/settings/domain"
	srepo "github.com/corvusHold/guard/internal/settings/repository"
	ssvc "github.com/corvusHold/guard/internal/settings/service"
	trepo "github.com/corvusHold/guard/internal/tenants/repository"
	tdomain "github.com/corvusHold/guard/internal/tenants/domain"
	tsvc "github.com/corvusHold/guard/internal/tenants/service"
)

func main() {
	ctx := context.Background()
	cfg, err := config.Load()
	if err != nil {
		fatalf("load config: %v", err)
	}
	pgCfg, err := pgxpool.ParseConfig(cfg.DatabaseURL)
	if err != nil {
		fatalf("invalid DATABASE_URL: %v", err)
	}
	pgPool, err := pgxpool.NewWithConfig(ctx, pgCfg)
	if err != nil {
		fatalf("pg pool: %v", err)
	}
	defer pgPool.Close()

	// Wire repositories/services we need
	tenantsRepo := trepo.New(pgPool)
	tenantsSvc := tsvc.New(tenantsRepo)
	settingsRepo := srepo.New(pgPool)
	settingsSvc := ssvc.New(settingsRepo)
	authRepo := arepo.New(pgPool)
	authSvc := asvc.New(authRepo, cfg, settingsSvc)

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	sub := os.Args[1]
	switch sub {
	case "tenant":
		fs := flag.NewFlagSet("tenant", flag.ExitOnError)
		name := fs.String("name", envOr("TENANT_NAME", "test"), "tenant name")
		_ = fs.Parse(os.Args[2:])
		if strings.TrimSpace(*name) == "" {
			def := envOr("TENANT_NAME", "test")
			name = &def
		}
		id, err := ensureTenant(ctx, tenantsSvc, *name)
		if err != nil {
			fatalf("tenant create: %v", err)
		}
		printEnv(map[string]string{"TENANT_ID": id.String()})
	case "user":
		fs := flag.NewFlagSet("user", flag.ExitOnError)
		tenantIDStr := fs.String("tenant-id", os.Getenv("TENANT_ID"), "tenant UUID")
		email := fs.String("email", os.Getenv("EMAIL"), "user email")
		password := fs.String("password", os.Getenv("PASSWORD"), "user password")
		first := fs.String("first", envOr("FIRST_NAME", "Test"), "first name")
		last := fs.String("last", envOr("LAST_NAME", "User"), "last name")
		rolesCSV := fs.String("roles", os.Getenv("ROLES"), "comma-separated roles (e.g. admin,member)")
		enableMFA := fs.Bool("enable-mfa", envOrBool("ENABLE_MFA", false), "enable MFA (TOTP) for user")
		_ = fs.Parse(os.Args[2:])

		// Coalesce empty flags back to env/defaults
		if strings.TrimSpace(*tenantIDStr) == "" {
			v := os.Getenv("TENANT_ID")
			tenantIDStr = &v
		}
		if strings.TrimSpace(*email) == "" {
			v := os.Getenv("EMAIL")
			email = &v
		}
		if strings.TrimSpace(*password) == "" {
			v := os.Getenv("PASSWORD")
			password = &v
		}
		if strings.TrimSpace(*first) == "" {
			v := envOr("FIRST_NAME", "Test")
			first = &v
		}
		if strings.TrimSpace(*last) == "" {
			v := envOr("LAST_NAME", "User")
			last = &v
		}
		if strings.TrimSpace(*rolesCSV) == "" {
			v := os.Getenv("ROLES")
			rolesCSV = &v
		}

		if *tenantIDStr == "" || *email == "" || *password == "" {
			fatalf("tenant-id, email, and password are required")
		}
		tenantID, err := uuid.Parse(*tenantIDStr)
		if err != nil {
			fatalf("invalid tenant-id: %v", err)
		}
		userID, created, err := ensureUser(ctx, authSvc, authRepo, tenantID, *email, *password, *first, *last)
		if err != nil {
			fatalf("user create: %v", err)
		}
		// Apply roles if provided
		if strings.TrimSpace(*rolesCSV) != "" {
			parts := strings.Split(*rolesCSV, ",")
			var roles []string
			for _, p := range parts {
				r := strings.TrimSpace(p)
				if r == "" {
					continue
				}
				roles = append(roles, r)
			}
			if len(roles) > 0 {
				if err := authSvc.UpdateUserRoles(ctx, userID, roles); err != nil {
					fatalf("update roles: %v", err)
				}
				stderr("updated roles for user %s: %s", userID, strings.Join(roles, ","))
			}
		}
		out := map[string]string{
			"TENANT_ID": tenantID.String(),
			"EMAIL":     *email,
			"PASSWORD":  *password,
			"USER_ID":   userID.String(),
			// k6-friendly aliases
			"K6_TENANT_ID": tenantID.String(),
			"K6_EMAIL":     *email,
			"K6_PASSWORD":  *password,
		}
		if *enableMFA {
			secret, codes, err := enableUserMFA(ctx, authSvc, userID, tenantID)
			if err != nil {
				fatalf("enable mfa: %v", err)
			}
			out["TOTP_SECRET"] = secret
			out["K6_TOTP"] = secret
			if len(codes) > 0 {
				out["BACKUP_CODES"] = strings.Join(codes, ",")
			}
		}
		printEnv(out)
		if created {
			stderr("created user %s in tenant %s", userID, tenantID)
		} else {
			stderr("existing user %s in tenant %s", userID, tenantID)
		}
	case "sso-workos":
		fs := flag.NewFlagSet("sso-workos", flag.ExitOnError)
		tenantIDStr := fs.String("tenant-id", os.Getenv("TENANT_ID"), "tenant UUID")
		clientID := fs.String("client-id", os.Getenv("WORKOS_CLIENT_ID"), "WorkOS client_id")
		clientSecret := fs.String("client-secret", os.Getenv("WORKOS_CLIENT_SECRET"), "WorkOS client_secret (secret)")
		apiKey := fs.String("api-key", os.Getenv("WORKOS_API_KEY"), "WorkOS API key (secret; used if client_secret not set)")
		stateTTL := fs.String("state-ttl", os.Getenv("SSO_STATE_TTL"), "SSO state TTL (e.g., 10m)")
		allowlist := fs.String("redirect-allowlist", os.Getenv("SSO_REDIRECT_ALLOWLIST"), "Comma-separated redirect URL prefixes")
		defConn := fs.String("default-connection-id", os.Getenv("WORKOS_DEFAULT_CONNECTION_ID"), "Default WorkOS connection ID for SSO start")
		defOrg := fs.String("default-organization-id", os.Getenv("WORKOS_DEFAULT_ORGANIZATION_ID"), "Default WorkOS organization ID for SSO start")
		_ = fs.Parse(os.Args[2:])

		// Coalesce empties to env again (already defaulted above via env, keep for safety)
		if strings.TrimSpace(*tenantIDStr) == "" {
			v := os.Getenv("TENANT_ID")
			tenantIDStr = &v
		}
		if strings.TrimSpace(*clientID) == "" {
			v := os.Getenv("WORKOS_CLIENT_ID")
			clientID = &v
		}
		if strings.TrimSpace(*clientSecret) == "" {
			v := os.Getenv("WORKOS_CLIENT_SECRET")
			clientSecret = &v
		}
		if strings.TrimSpace(*apiKey) == "" {
			v := os.Getenv("WORKOS_API_KEY")
			apiKey = &v
		}
		if strings.TrimSpace(*stateTTL) == "" {
			v := os.Getenv("SSO_STATE_TTL")
			stateTTL = &v
		}
		if strings.TrimSpace(*allowlist) == "" {
			v := os.Getenv("SSO_REDIRECT_ALLOWLIST")
			allowlist = &v
		}
		if strings.TrimSpace(*defConn) == "" {
			v := os.Getenv("WORKOS_DEFAULT_CONNECTION_ID")
			defConn = &v
		}
		if strings.TrimSpace(*defOrg) == "" {
			v := os.Getenv("WORKOS_DEFAULT_ORGANIZATION_ID")
			defOrg = &v
		}

		if *tenantIDStr == "" {
			fatalf("tenant-id is required")
		}
		tenantID, err := uuid.Parse(*tenantIDStr)
		if err != nil {
			fatalf("invalid tenant-id: %v", err)
		}

		// Required: provider=workos and client_id
		if strings.TrimSpace(*clientID) == "" {
			fatalf("client-id is required for WorkOS SSO")
		}
		if strings.TrimSpace(*clientSecret) == "" && strings.TrimSpace(*apiKey) == "" {
			fatalf("either client-secret or api-key is required for WorkOS SSO")
		}

		// Upsert settings
		if err := settingsRepo.Upsert(ctx, sdomain.KeySSOProvider, &tenantID, "workos", false); err != nil {
			fatalf("upsert sso.provider: %v", err)
		}
		if err := settingsRepo.Upsert(ctx, sdomain.KeyWorkOSClientID, &tenantID, strings.TrimSpace(*clientID), false); err != nil {
			fatalf("upsert workos client_id: %v", err)
		}
		if strings.TrimSpace(*clientSecret) != "" {
			if err := settingsRepo.Upsert(ctx, sdomain.KeyWorkOSClientSecret, &tenantID, strings.TrimSpace(*clientSecret), true); err != nil {
				fatalf("upsert workos client_secret: %v", err)
			}
		}
		if strings.TrimSpace(*apiKey) != "" {
			if err := settingsRepo.Upsert(ctx, sdomain.KeyWorkOSAPIKey, &tenantID, strings.TrimSpace(*apiKey), true); err != nil {
				fatalf("upsert workos api_key: %v", err)
			}
		}
		if strings.TrimSpace(*stateTTL) != "" {
			if err := settingsRepo.Upsert(ctx, sdomain.KeySSOStateTTL, &tenantID, strings.TrimSpace(*stateTTL), false); err != nil {
				fatalf("upsert sso.state_ttl: %v", err)
			}
		}
		if strings.TrimSpace(*allowlist) != "" {
			if err := settingsRepo.Upsert(ctx, sdomain.KeySSORedirectAllowlist, &tenantID, strings.TrimSpace(*allowlist), false); err != nil {
				fatalf("upsert sso.redirect_allowlist: %v", err)
			}
		}
		if strings.TrimSpace(*defConn) != "" {
			if err := settingsRepo.Upsert(ctx, sdomain.KeyWorkOSDefaultConnectionID, &tenantID, strings.TrimSpace(*defConn), false); err != nil {
				fatalf("upsert sso.workos.default_connection_id: %v", err)
			}
		}
		if strings.TrimSpace(*defOrg) != "" {
			if err := settingsRepo.Upsert(ctx, sdomain.KeyWorkOSDefaultOrganizationID, &tenantID, strings.TrimSpace(*defOrg), false); err != nil {
				fatalf("upsert sso.workos.default_organization_id: %v", err)
			}
		}

		// Only print non-secret confirmations
		printEnv(map[string]string{
			"TENANT_ID": tenantID.String(),
			"SSO_PROVIDER": "workos",
			"WORKOS_CLIENT_ID_SET": "true",
		})
		stderr("WorkOS SSO settings configured for tenant %s", tenantID)
	case "default":
		fs := flag.NewFlagSet("default", flag.ExitOnError)
		tenantName := fs.String("tenant-name", envOr("TENANT_NAME", "test"), "tenant name to create or reuse")
		email := fs.String("email", envOr("EMAIL", "test@example.com"), "user email")
		password := fs.String("password", envOr("PASSWORD", "Password123!"), "user password")
		first := fs.String("first", envOr("FIRST_NAME", "Test"), "first name")
		last := fs.String("last", envOr("LAST_NAME", "User"), "last name")
		enableMFA := fs.Bool("enable-mfa", envOrBool("ENABLE_MFA", false), "enable MFA (TOTP) for user")
		_ = fs.Parse(os.Args[2:])

		// Coalesce empties to env/defaults if flags were provided empty
		if strings.TrimSpace(*tenantName) == "" {
			v := envOr("TENANT_NAME", "test")
			tenantName = &v
		}
		if strings.TrimSpace(*email) == "" {
			v := envOr("EMAIL", "test@example.com")
			email = &v
		}
		if strings.TrimSpace(*password) == "" {
			v := envOr("PASSWORD", "Password123!")
			password = &v
		}
		if strings.TrimSpace(*first) == "" {
			v := envOr("FIRST_NAME", "Test")
			first = &v
		}
		if strings.TrimSpace(*last) == "" {
			v := envOr("LAST_NAME", "User")
			last = &v
		}

		tenantID, err := ensureTenant(ctx, tenantsSvc, *tenantName)
		if err != nil {
			fatalf("ensure tenant: %v", err)
		}
		userID, _, err := ensureUser(ctx, authSvc, authRepo, tenantID, *email, *password, *first, *last)
		if err != nil {
			fatalf("ensure user: %v", err)
		}
		out := map[string]string{"TENANT_ID": tenantID.String(), "EMAIL": *email, "PASSWORD": *password, "USER_ID": userID.String()}
		if *enableMFA {
			secret, codes, err := enableUserMFA(ctx, authSvc, userID, tenantID)
			if err != nil {
				fatalf("enable mfa: %v", err)
			}
			out["TOTP_SECRET"] = secret
			if len(codes) > 0 {
				out["BACKUP_CODES"] = strings.Join(codes, ",")
			}
		}
		printEnv(out)
	default:
		usage()
		os.Exit(2)
	}
}

func ensureTenant(ctx context.Context, svc tdomain.Service, name string) (uuid.UUID, error) {
	if name == "" {
		return uuid.Nil, errors.New("tenant name required")
	}
	if t, err := svc.GetByName(ctx, name); err == nil {
		id, e := fromPgUUID(t.ID)
		if e != nil {
			return uuid.Nil, e
		}
		return id, nil
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, err
	}
	t, err := svc.Create(ctx, name)
	if err != nil {
		return uuid.Nil, err
	}
	id, e := fromPgUUID(t.ID)
	if e != nil {
		return uuid.Nil, e
	}
	return id, nil
}

func fromPgUUID(id pgtype.UUID) (uuid.UUID, error) {
	if !id.Valid {
		return uuid.Nil, errors.New("uuid invalid")
	}
	return uuid.UUID(id.Bytes), nil
}

func ensureUser(ctx context.Context, svc adb.Service, repo adb.Repository, tenantID uuid.UUID, email, password, first, last string) (uuid.UUID, bool, error) {
	// Try to find existing auth identity
	if ai, err := repo.GetAuthIdentityByEmailTenant(ctx, tenantID, strings.ToLower(email)); err == nil {
		return ai.UserID, false, nil
	}
	// Create via service.Signup (handles hashing and associations)
	_, err := svc.Signup(ctx, adb.SignupInput{
		TenantID:  tenantID,
		Email:     strings.ToLower(email),
		Password:  password,
		FirstName: first,
		LastName:  last,
	})
	if err != nil {
		return uuid.Nil, false, err
	}
	ai, err := repo.GetAuthIdentityByEmailTenant(ctx, tenantID, strings.ToLower(email))
	if err != nil {
		return uuid.Nil, false, err
	}
	return ai.UserID, true, nil
}

func enableUserMFA(ctx context.Context, svc adb.Service, userID, tenantID uuid.UUID) (secret string, codes []string, err error) {
	sec, _, err := svc.StartTOTPEnrollment(ctx, userID, tenantID)
	if err != nil {
		return "", nil, err
	}
	// Generate a current code to activate
	code, err := totp.GenerateCode(sec, time.Now())
	if err != nil {
		return "", nil, err
	}
	if err := svc.ActivateTOTP(ctx, userID, code); err != nil {
		return "", nil, err
	}
	codes, err = svc.GenerateBackupCodes(ctx, userID, 5)
	if err != nil {
		return "", nil, err
	}
	return sec, codes, nil
}

func usage() {
	fmt.Fprintf(os.Stderr, `Usage:
  seed tenant --name <name>
  seed user --tenant-id <uuid> --email <email> --password <password> [--first First] [--last Last] [--roles admin,member] [--enable-mfa]
  seed sso-workos --tenant-id <uuid> --client-id <id> [--client-secret <secret> | --api-key <key>] [--state-ttl 10m] [--redirect-allowlist https://app.example/] [--default-connection-id <id>] [--default-organization-id <id>]
  seed default [--tenant-name test] [--email test@example.com] [--password Password123!] [--enable-mfa]

Environment fallbacks:
  TENANT_NAME, TENANT_ID, EMAIL, PASSWORD, FIRST_NAME, LAST_NAME, ENABLE_MFA, ROLES
  WORKOS_CLIENT_ID, WORKOS_CLIENT_SECRET, WORKOS_API_KEY, SSO_STATE_TTL, SSO_REDIRECT_ALLOWLIST,
  WORKOS_DEFAULT_CONNECTION_ID, WORKOS_DEFAULT_ORGANIZATION_ID
`)
}

func envOr(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func envOrBool(k string, def bool) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(k)))
	if v == "true" || v == "1" || v == "yes" { return true }
	if v == "false" || v == "0" || v == "no" { return false }
	return def
}

func printEnv(kv map[string]string) {
	// Print as KEY=VALUE lines so callers can tee into a .env file and `source` it.
	for k, v := range kv {
		fmt.Printf("%s=%s\n", k, v)
	}
}

func fatalf(f string, a ...any) {
	fmt.Fprintf(os.Stderr, f+"\n", a...)
	os.Exit(1)
}

func stderr(f string, a ...any) {
	fmt.Fprintf(os.Stderr, f+"\n", a...)
}
