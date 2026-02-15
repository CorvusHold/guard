package auth

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"

	ctrl "github.com/corvusHold/guard/internal/auth/controller"
	"github.com/corvusHold/guard/internal/auth/keys"
	repo "github.com/corvusHold/guard/internal/auth/repository"
	svc "github.com/corvusHold/guard/internal/auth/service"
	ssoctrl "github.com/corvusHold/guard/internal/auth/sso/controller"
	ssosvc "github.com/corvusHold/guard/internal/auth/sso/service"
	"github.com/corvusHold/guard/internal/config"
	emailsvc "github.com/corvusHold/guard/internal/email/service"
	evsvc "github.com/corvusHold/guard/internal/events/service"
	"github.com/corvusHold/guard/internal/logger"
	oauth "github.com/corvusHold/guard/internal/oauth"
	rl "github.com/corvusHold/guard/internal/platform/ratelimit"
	srepo "github.com/corvusHold/guard/internal/settings/repository"
	ssvc "github.com/corvusHold/guard/internal/settings/service"
)

type Registrar struct {
	ctrl     *ctrl.Controller
	sso      *ssoctrl.SSOController
	ssoRedis *redis.Client
	authSvc  *svc.Service
	oauth    *oauth.Registrar
	cfg      config.Config
}

func NewRegistrar(pg *pgxpool.Pool, cfg config.Config) (*Registrar, error) {
	r := repo.New(pg)
	// settings service (DB-backed, with tenant overrides)
	sr := srepo.New(pg)
	settings := ssvc.New(sr)
	authSvc := svc.New(r, cfg, settings)
	authSvc.SetLogger(logger.New(cfg.AppEnv))

	// Key manager for JWT signing (ES256 or HS256 fallback)
	keyMgr, err := keys.NewManager(cfg.JWTSigningAlgorithm, cfg.JWTPrivateKeyPath, cfg.JWTSigningKey)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize key manager: %w", err)
	}
	authSvc.SetKeyManager(keyMgr)

	emailSender := emailsvc.NewRouter(settings, cfg)
	authSvc.SetEmailSender(emailSender)
	magic := svc.NewMagic(r, cfg, settings, emailSender)
	authSSO := svc.NewSSO(r, cfg, settings)
	authSSO.SetLogger(logger.New(cfg.AppEnv))
	authSSO.SetKeyManager(keyMgr)

	pub := evsvc.NewMulti(evsvc.NewLogger(), evsvc.NewDB(pg))
	rlStore := rl.NewCircuitBreakerStore(rl.NewRedisStore(cfg), 5, 10*time.Second)
	webauthnSvc := svc.NewWebAuthnService(pg)
	authCtrl := ctrl.New(authSvc, magic, authSSO).WithRateLimit(settings, rlStore).WithPublisher(pub).WithWebAuthn(webauthnSvc)

	// SSO provider management + browser flows
	ssoRedis := redis.NewClient(&redis.Options{
		Addr: cfg.RedisAddr,
		DB:   cfg.RedisDB,
	})
	ssoService := ssosvc.New(pg, ssoRedis, cfg.PublicBaseURL)
	ssoService.SetLogger(logger.New(cfg.AppEnv))
	ssoService.SetPublisher(pub)
	// Wire the native SSO provider service into the auth SSO service for portal link generation.
	authSSO.SetSSOProviderService(ssoService)

	ssoController := ssoctrl.New(ssoService, authSvc).WithRateLimitStore(rlStore)
	ssoController.SetLogger(logger.New(cfg.AppEnv))

	// OAuth 2.0 provider module
	oauthReg := oauth.NewRegistrar(pg, authSvc, settings, cfg, keyMgr, rlStore)

	return &Registrar{ctrl: authCtrl, sso: ssoController, ssoRedis: ssoRedis, authSvc: authSvc, oauth: oauthReg, cfg: cfg}, nil
}

// SeedDefaultRoles creates the standard set of roles for a tenant. Idempotent.
func (r *Registrar) SeedDefaultRoles(ctx context.Context, tenantID uuid.UUID) error {
	return r.authSvc.SeedDefaultRoles(ctx, tenantID)
}

// AuthService returns the underlying auth service (for API key middleware wiring).
func (r *Registrar) AuthService() *svc.Service { return r.authSvc }

func (r *Registrar) Close() error {
	if r.ssoRedis != nil {
		return r.ssoRedis.Close()
	}
	return nil
}

func (r *Registrar) RegisterWellKnown(e *echo.Echo) {
	e.GET("/.well-known/oauth-authorization-server", r.ctrl.OAuth2Metadata)
	e.GET("/login", func(c echo.Context) error {
		publicBase := strings.TrimRight(r.cfg.PublicBaseURL, "/")
		if publicBase == "" {
			return c.JSON(http.StatusNotFound, map[string]string{"message": "Not Found"})
		}

		target, err := url.Parse(publicBase)
		if err != nil || target.Scheme == "" || target.Host == "" {
			return c.JSON(http.StatusNotFound, map[string]string{"message": "Not Found"})
		}

		reqScheme := "https"
		if c.Request().TLS == nil {
			reqScheme = "http"
		}
		reqOrigin := reqScheme + "://" + c.Request().Host
		if strings.EqualFold(reqOrigin, target.Scheme+"://"+target.Host) {
			return c.JSON(http.StatusNotFound, map[string]string{"message": "Not Found"})
		}

		loginURL := strings.TrimRight(publicBase, "/") + "/login"
		q := c.QueryParams()
		if q.Get("guard-base-url") == "" {
			q.Set("guard-base-url", reqOrigin)
		}
		if q.Get("auth-mode") == "" {
			q.Set("auth-mode", r.cfg.DefaultAuthMode)
		}
		if raw := q.Encode(); raw != "" {
			loginURL += "?" + raw
		}
		return c.Redirect(http.StatusFound, loginURL)
	})

	// OIDC Discovery (OpenID Connect Discovery 1.0)
	e.GET("/.well-known/openid-configuration", func(c echo.Context) error {
		baseURL := r.cfg.PublicBaseURL
		if baseURL == "" {
			scheme := "https"
			if c.Request().TLS == nil {
				scheme = "http"
			}
			baseURL = scheme + "://" + c.Request().Host
		}

		algSupported := []string{"HS256"}
		if km := r.authSvc.KeyManager(); km != nil && km.IsAsymmetric() {
			algSupported = []string{"ES256", "HS256"}
		}

		return c.JSON(200, map[string]interface{}{
			"issuer":                                baseURL,
			"authorization_endpoint":                baseURL + "/oauth/authorize",
			"token_endpoint":                        baseURL + "/oauth/token",
			"userinfo_endpoint":                     baseURL + "/api/v1/auth/me",
			"jwks_uri":                              baseURL + "/.well-known/jwks.json",
			"introspection_endpoint":                baseURL + "/api/v1/auth/introspect",
			"revocation_endpoint":                   baseURL + "/oauth/revoke",
			"scopes_supported":                      []string{"openid", "profile", "email", "offline_access"},
			"response_types_supported":              []string{"code"},
			"grant_types_supported":                 []string{"authorization_code", "refresh_token", "client_credentials"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": algSupported,
			"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
			"code_challenge_methods_supported":      []string{"S256"},
		})
	})

	// JWKS endpoint for public key discovery
	if km := r.authSvc.KeyManager(); km != nil && km.IsAsymmetric() {
		e.GET("/.well-known/jwks.json", func(c echo.Context) error {
			data, err := km.JWKSBytes()
			if err != nil {
				return c.JSON(500, map[string]string{"error": "failed to serialize JWKS"})
			}
			c.Response().Header().Set("Cache-Control", "public, max-age=3600")
			return c.JSONBlob(200, data)
		})
	} else {
		// Return empty JWKS when using HS256
		e.GET("/.well-known/jwks.json", func(c echo.Context) error {
			return c.JSON(200, map[string]interface{}{"keys": []interface{}{}})
		})
	}
}

func (r *Registrar) RegisterSSOBrowser(e *echo.Echo) {
	r.sso.Register(e)
}

func (r *Registrar) RegisterV1(g *echo.Group) {
	r.ctrl.RegisterV1(g)
	r.sso.RegisterV1(g)
}

// RegisterOAuth registers the public /oauth/* endpoints and admin OAuth client routes.
func (r *Registrar) RegisterOAuth(e *echo.Echo, adminGroup *echo.Group) {
	r.oauth.RegisterOAuthRoutes(e)
	r.oauth.RegisterAdminRoutes(adminGroup)
}

// RegisterWellKnown registers root-level endpoints that must not be under /api.
// This is intended to be used alongside RegisterV1 in cmd/api/main.go.
func RegisterWellKnown(e *echo.Echo, pg *pgxpool.Pool, cfg config.Config) error {
	r, err := NewRegistrar(pg, cfg)
	if err != nil {
		return err
	}
	defer func() { _ = r.Close() }()
	r.RegisterWellKnown(e)
	return nil
}

// RegisterSSOBrowser wires the SSO module and registers browser-based SSO flows under /auth/sso/*.
// This is intended to be used alongside RegisterV1 in cmd/api/main.go.
func RegisterSSOBrowser(e *echo.Echo, pg *pgxpool.Pool, cfg config.Config) error {
	r, err := NewRegistrar(pg, cfg)
	if err != nil {
		return err
	}
	r.RegisterSSOBrowser(e)
	return nil
}

// Register wires the auth module and registers HTTP routes (deprecated, use RegisterV1).
func Register(e *echo.Echo, pg *pgxpool.Pool, cfg config.Config) error {
	reg, err := NewRegistrar(pg, cfg)
	if err != nil {
		return err
	}
	reg.ctrl.Register(e)
	reg.sso.Register(e)
	api := e.Group("/api")
	apiV1 := api.Group("/v1")
	reg.sso.RegisterV1(apiV1)
	return nil
}

// RegisterV1 wires the auth module and registers HTTP routes under /api/v1.
func RegisterV1(g *echo.Group, pg *pgxpool.Pool, cfg config.Config) error {
	r, err := NewRegistrar(pg, cfg)
	if err != nil {
		return err
	}
	r.RegisterV1(g)
	return nil
}
