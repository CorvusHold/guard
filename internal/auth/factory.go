package auth

import (
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"

	ctrl "github.com/corvusHold/guard/internal/auth/controller"
	repo "github.com/corvusHold/guard/internal/auth/repository"
	svc "github.com/corvusHold/guard/internal/auth/service"
	"github.com/corvusHold/guard/internal/config"
	emailsvc "github.com/corvusHold/guard/internal/email/service"
	evsvc "github.com/corvusHold/guard/internal/events/service"
	"github.com/corvusHold/guard/internal/logger"
	rl "github.com/corvusHold/guard/internal/platform/ratelimit"
	srepo "github.com/corvusHold/guard/internal/settings/repository"
	ssvc "github.com/corvusHold/guard/internal/settings/service"
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
	pub := evsvc.NewLogger()
	c := ctrl.New(s, magic, sso).WithRateLimit(settings, rl.NewRedisStore(cfg)).WithPublisher(pub)
	c.Register(e)
}
