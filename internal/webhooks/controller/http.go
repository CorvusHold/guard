package controller

import (
	"net/http"

	"github.com/corvusHold/guard/internal/webhooks/domain"
	whsvc "github.com/corvusHold/guard/internal/webhooks/service"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

// Controller handles HTTP requests for webhook management.
type Controller struct {
	svc *whsvc.Service
}

// New creates a new webhook controller.
func New(svc *whsvc.Service) *Controller {
	return &Controller{svc: svc}
}

type createWebhookRequest struct {
	URL    string   `json:"url" validate:"required"`
	Secret string   `json:"secret" validate:"required"`
	Events []string `json:"events" validate:"required"`
}

type updateWebhookRequest struct {
	URL      *string  `json:"url"`
	Events   []string `json:"events"`
	IsActive *bool    `json:"is_active"`
}

// RegisterV1 registers webhook routes under the given group.
func (ctrl *Controller) RegisterV1(g *echo.Group) {
	wh := g.Group("/webhooks")
	wh.POST("", ctrl.create)
	wh.GET("", ctrl.list)
	wh.GET("/:id", ctrl.get)
	wh.PUT("/:id", ctrl.update)
	wh.DELETE("/:id", ctrl.delete)
}

func (ctrl *Controller) create(c echo.Context) error {
	var req createWebhookRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid json"})
	}
	tenantID, err := uuid.Parse(c.Request().Header.Get("X-Tenant-ID"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "X-Tenant-ID header required"})
	}
	wh, err := ctrl.svc.Create(c.Request().Context(), domain.CreateWebhookInput{
		TenantID: tenantID,
		URL:      req.URL,
		Secret:   req.Secret,
		Events:   req.Events,
	})
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	return c.JSON(http.StatusCreated, wh)
}

func (ctrl *Controller) list(c echo.Context) error {
	tenantID, err := uuid.Parse(c.Request().Header.Get("X-Tenant-ID"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "X-Tenant-ID header required"})
	}
	webhooks, err := ctrl.svc.List(c.Request().Context(), tenantID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	return c.JSON(http.StatusOK, map[string]interface{}{"webhooks": webhooks})
}

func (ctrl *Controller) get(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid id"})
	}
	wh, err := ctrl.svc.Get(c.Request().Context(), id)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "webhook not found"})
	}
	return c.JSON(http.StatusOK, wh)
}

func (ctrl *Controller) update(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid id"})
	}
	var req updateWebhookRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid json"})
	}
	wh, err := ctrl.svc.Update(c.Request().Context(), id, req.URL, req.Events, req.IsActive)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	return c.JSON(http.StatusOK, wh)
}

func (ctrl *Controller) delete(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid id"})
	}
	if err := ctrl.svc.Delete(c.Request().Context(), id); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	return c.NoContent(http.StatusNoContent)
}
