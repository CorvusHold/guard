package auth

import (
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"

	"github.com/corvusHold/guard/internal/config"
	ctrl "github.com/corvusHold/guard/internal/auth/controller"
	repo "github.com/corvusHold/guard/internal/auth/repository"
	svc "github.com/corvusHold/guard/internal/auth/service"
	emailsvc "github.com/corvusHold/guard/internal/email/service"
	rl "github.com/corvusHold/guard/internal/platform/ratelimit"
	srepo "github.com/corvusHold/guard/internal/settings/repository"
	ssvc "github.com/corvusHold/guard/internal/settings/service"
	"github.com/corvusHold/guard/internal/logger"
)

// Register wires the auth module and registers HTTP routes.
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
	c := ctrl.New(s, magic, sso).WithRateLimit(settings, rl.NewRedisStore(cfg))
	c.Register(e)
}
