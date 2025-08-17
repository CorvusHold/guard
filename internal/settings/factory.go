package settings

import (
    "context"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"

    "github.com/corvusHold/guard/internal/config"
    amw "github.com/corvusHold/guard/internal/auth/middleware"
    arepo "github.com/corvusHold/guard/internal/auth/repository"
    evsvc "github.com/corvusHold/guard/internal/events/service"
    rl "github.com/corvusHold/guard/internal/platform/ratelimit"
	ctrl "github.com/corvusHold/guard/internal/settings/controller"
	repo "github.com/corvusHold/guard/internal/settings/repository"
	svc "github.com/corvusHold/guard/internal/settings/service"
    "github.com/google/uuid"
)

// Register wires the settings module and registers HTTP routes.
func Register(e *echo.Echo, pg *pgxpool.Pool, cfg config.Config) {
    r := repo.New(pg)
    s := svc.New(r)
    c := ctrl.New(r, s)

    // Dependencies
    jwt := amw.NewJWT(cfg)
    store := rl.NewRedisStore(cfg)
    pub := evsvc.NewLogger()
    // role fetcher from auth repository (global roles)
    ar := arepo.New(pg)
    roleFetcher := func(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID) ([]string, error) {
        u, err := ar.GetUserByID(ctx, userID)
        if err != nil { return nil, err }
        return u.Roles, nil
    }

    c.WithJWT(jwt).WithRateLimit(store).WithPublisher(pub).WithRoleFetcher(roleFetcher)
    c.Register(e)
}
