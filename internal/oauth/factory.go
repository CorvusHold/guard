package oauth

import (
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"

	authdomain "github.com/corvusHold/guard/internal/auth/domain"
	"github.com/corvusHold/guard/internal/auth/keys"
	"github.com/corvusHold/guard/internal/config"
	ctrl "github.com/corvusHold/guard/internal/oauth/controller"
	repo "github.com/corvusHold/guard/internal/oauth/repository"
	svc "github.com/corvusHold/guard/internal/oauth/service"
	rl "github.com/corvusHold/guard/internal/platform/ratelimit"
	sdomain "github.com/corvusHold/guard/internal/settings/domain"
)

// Registrar wires up the OAuth module.
type Registrar struct {
	ctrl *ctrl.Controller
}

// NewRegistrar creates the OAuth registrar with all dependencies.
func NewRegistrar(pg *pgxpool.Pool, authSvc authdomain.Service, settings sdomain.Service, cfg config.Config, keyMgr *keys.Manager, rlStore rl.Store) *Registrar {
	r := repo.New(pg)
	s := svc.New(r)
	c := ctrl.New(s, authSvc, settings, cfg, keyMgr)

	// Wire rate limiting if store is available
	if rlStore != nil {
		rlToken := rl.MiddlewareWithStore(rl.Policy{
			Name:   "oauth:token",
			Window: time.Minute,
			Limit:  30,
			Key:    rl.KeyTenantOrIP("oauth:token"),
		}, rlStore)
		rlAuth := rl.MiddlewareWithStore(rl.Policy{
			Name:   "oauth:authorize",
			Window: time.Minute,
			Limit:  20,
			Key:    rl.KeyTenantOrIP("oauth:authorize"),
		}, rlStore)
		c.WithRateLimits(rlToken, rlAuth)
	}

	return &Registrar{ctrl: c}
}

// RegisterAdminRoutes registers OAuth client admin CRUD under /api/v1/auth/admin.
func (r *Registrar) RegisterAdminRoutes(adminGroup *echo.Group) {
	r.ctrl.RegisterAdminRoutes(adminGroup)
}

// RegisterOAuthRoutes registers the public /oauth/* endpoints.
func (r *Registrar) RegisterOAuthRoutes(e *echo.Echo) {
	r.ctrl.RegisterOAuthRoutes(e)
}
