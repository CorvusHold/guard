package tenants

import (
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"

	ctrl "github.com/corvusHold/guard/internal/tenants/controller"
	repo "github.com/corvusHold/guard/internal/tenants/repository"
	svc "github.com/corvusHold/guard/internal/tenants/service"
)

// Register wires the tenants module and registers HTTP routes.
func Register(e *echo.Echo, pg *pgxpool.Pool) {
	r := repo.New(pg)
	s := svc.New(r)
	c := ctrl.New(s)
	c.Register(e)
}
