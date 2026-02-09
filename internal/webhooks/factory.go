package webhooks

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"

	ctrl "github.com/corvusHold/guard/internal/webhooks/controller"
	repo "github.com/corvusHold/guard/internal/webhooks/repository"
	svc "github.com/corvusHold/guard/internal/webhooks/service"
)

// RegisterV1 wires the webhooks module and registers HTTP routes under /api/v1.
func RegisterV1(g *echo.Group, pg *pgxpool.Pool) {
	r := repo.New(pg)
	s := svc.New(r)
	c := ctrl.New(s)
	c.RegisterV1(g)
}

// StartWorker starts the webhook delivery worker in the background.
func StartWorker(ctx context.Context, pg *pgxpool.Pool) {
	r := repo.New(pg)
	w := svc.NewWorker(r)
	go w.Run(ctx)
}
