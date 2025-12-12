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
	ssoService := ssosvc.New(pg, ssoRedis, cfg.PublicBaseURL)
	ssoService.SetLogger(logger.New(cfg.AppEnv))
	ssoService.SetPublisher(pub)
	// Wire the native SSO provider service into the auth SSO service for portal link generation.
	sso.SetSSOProviderService(ssoService)
	ssoController := ssoctrl.New(ssoService, s).WithRateLimitStore(rlStore)
	ssoController.SetLogger(logger.New(cfg.AppEnv))
	ssoController.Register(e)
}

// RegisterV1 wires the auth module and registers HTTP routes under /api/v1.
func RegisterV1(g *echo.Group, pg *pgxpool.Pool, cfg config.Config) {
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
	c.RegisterV1(g)

	// SSO provider management (admin/public SSO provider APIs)
	ssoRedis := redis.NewClient(&redis.Options{
		Addr: cfg.RedisAddr,
		DB:   cfg.RedisDB,
	})
	ssoService := ssosvc.New(pg, ssoRedis, cfg.PublicBaseURL)
	ssoService.SetLogger(logger.New(cfg.AppEnv))
	ssoService.SetPublisher(pub)
	// Wire the native SSO provider service into the auth SSO service for portal link generation.
	sso.SetSSOProviderService(ssoService)
	ssoController := ssoctrl.New(ssoService, s).WithRateLimitStore(rlStore)
	ssoController.SetLogger(logger.New(cfg.AppEnv))
	// SSO JSON APIs (admin/portal) registered under /api/v1/sso
	// SSO browser flows stay at root /auth/sso (registered in main.go Register method)
	ssoController.RegisterV1(g)
}
