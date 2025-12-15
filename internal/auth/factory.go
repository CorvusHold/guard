package auth

import (
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"

	ctrl "github.com/corvusHold/guard/internal/auth/controller"
	repo "github.com/corvusHold/guard/internal/auth/repository"
	svc "github.com/corvusHold/guard/internal/auth/service"
	ssoctrl "github.com/corvusHold/guard/internal/auth/sso/controller"
	ssosvc "github.com/corvusHold/guard/internal/auth/sso/service"
	"github.com/corvusHold/guard/internal/config"
	emailsvc "github.com/corvusHold/guard/internal/email/service"
	evsvc "github.com/corvusHold/guard/internal/events/service"
	"github.com/corvusHold/guard/internal/logger"
	rl "github.com/corvusHold/guard/internal/platform/ratelimit"
	srepo "github.com/corvusHold/guard/internal/settings/repository"
	ssvc "github.com/corvusHold/guard/internal/settings/service"
)

type Registrar struct {
	ctrl     *ctrl.Controller
	sso      *ssoctrl.SSOController
	ssoRedis *redis.Client
}

func NewRegistrar(pg *pgxpool.Pool, cfg config.Config) *Registrar {
	r := repo.New(pg)
	// settings service (DB-backed, with tenant overrides)
	sr := srepo.New(pg)
	settings := ssvc.New(sr)
	authSvc := svc.New(r, cfg, settings)
	authSvc.SetLogger(logger.New(cfg.AppEnv))

	emailSender := emailsvc.NewRouter(settings, cfg)
	magic := svc.NewMagic(r, cfg, settings, emailSender)
	authSSO := svc.NewSSO(r, cfg, settings)
	authSSO.SetLogger(logger.New(cfg.AppEnv))

	pub := evsvc.NewLogger()
	rlStore := rl.NewRedisStore(cfg)
	authCtrl := ctrl.New(authSvc, magic, authSSO).WithRateLimit(settings, rlStore).WithPublisher(pub)

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

	return &Registrar{ctrl: authCtrl, sso: ssoController, ssoRedis: ssoRedis}
}

func (r *Registrar) Close() error {
	if r.ssoRedis != nil {
		return r.ssoRedis.Close()
	}
	return nil
}

func (r *Registrar) RegisterWellKnown(e *echo.Echo) {
	e.GET("/.well-known/oauth-authorization-server", r.ctrl.OAuth2Metadata)
}

func (r *Registrar) RegisterSSOBrowser(e *echo.Echo) {
	r.sso.Register(e)
}

func (r *Registrar) RegisterV1(g *echo.Group) {
	r.ctrl.RegisterV1(g)
	r.sso.RegisterV1(g)
}

// RegisterWellKnown registers root-level endpoints that must not be under /api.
// This is intended to be used alongside RegisterV1 in cmd/api/main.go.
func RegisterWellKnown(e *echo.Echo, pg *pgxpool.Pool, cfg config.Config) {
	r := NewRegistrar(pg, cfg)
	defer func() { _ = r.Close() }()
	r.RegisterWellKnown(e)
}

// RegisterSSOBrowser wires the SSO module and registers browser-based SSO flows under /auth/sso/*.
// This is intended to be used alongside RegisterV1 in cmd/api/main.go.
func RegisterSSOBrowser(e *echo.Echo, pg *pgxpool.Pool, cfg config.Config) {
	r := NewRegistrar(pg, cfg)
	defer func() { _ = r.Close() }()
	r.RegisterSSOBrowser(e)
}

// Register wires the auth module and registers HTTP routes (deprecated, use RegisterV1).
func Register(e *echo.Echo, pg *pgxpool.Pool, cfg config.Config) {
	r := repo.New(pg)
	// settings service (DB-backed, with tenant overrides)
	sr := srepo.New(pg)
	settings := ssvc.New(sr)
	s := svc.New(r, cfg, settings)
	// Inject module logger (debug in development)
	s.SetLogger(logger.New(cfg.AppEnv))
	emailSender := emailsvc.NewRouter(settings, cfg)
	magic := svc.NewMagic(r, cfg, settings, emailSender)
	sso := svc.NewSSO(r, cfg, settings)
	sso.SetLogger(logger.New(cfg.AppEnv))
	pub := evsvc.NewLogger()
	rlStore := rl.NewRedisStore(cfg)
	c := ctrl.New(s, magic, sso).WithRateLimit(settings, rlStore).WithPublisher(pub)
	c.Register(e)

	// SSO provider management (admin/public SSO provider APIs)
	ssoRedis := redis.NewClient(&redis.Options{
		Addr: cfg.RedisAddr,
		DB:   cfg.RedisDB,
	})
	defer func() { _ = ssoRedis.Close() }()
	ssoService := ssosvc.New(pg, ssoRedis, cfg.PublicBaseURL)
	ssoService.SetLogger(logger.New(cfg.AppEnv))
	ssoService.SetPublisher(pub)
	// Wire the native SSO provider service into the auth SSO service for portal link generation.
	sso.SetSSOProviderService(ssoService)
	ssoController := ssoctrl.New(ssoService, s).WithRateLimitStore(rlStore)
	ssoController.SetLogger(logger.New(cfg.AppEnv))
	// Browser SSO flows (/auth/sso/*)
	ssoController.Register(e)
	// JSON SSO APIs (/api/v1/sso/*)
	api := e.Group("/api")
	apiV1 := api.Group("/v1")
	ssoController.RegisterV1(apiV1)
}

// RegisterV1 wires the auth module and registers HTTP routes under /api/v1.
func RegisterV1(g *echo.Group, pg *pgxpool.Pool, cfg config.Config) {
	NewRegistrar(pg, cfg).RegisterV1(g)
}
