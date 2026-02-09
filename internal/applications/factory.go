package applications

import (
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"

	ctrl "github.com/corvusHold/guard/internal/applications/controller"
	repo "github.com/corvusHold/guard/internal/applications/repository"
	svc "github.com/corvusHold/guard/internal/applications/service"
)

// RegisterV1 wires the applications module and registers HTTP routes under /api/v1.
func RegisterV1(g *echo.Group, pg *pgxpool.Pool) {
	r := repo.New(pg)
	s := svc.New(r)
	c := ctrl.New(s)
	c.RegisterV1(g)
}
