package controller

import (
	"net/http"

	"github.com/corvusHold/guard/internal/auth/middleware"
	"github.com/corvusHold/guard/internal/webhooks/domain"
	whsvc "github.com/corvusHold/guard/internal/webhooks/service"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog/log"
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

// @Summary      Create webhook
// @Description  Creates a new webhook subscription for the tenant
// @Tags         Webhooks
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body  body  createWebhookRequest  true  "Webhook configuration"
// @Success      201  {object}  domain.Webhook
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Router       /api/v1/webhooks [post]
func (ctrl *Controller) create(c echo.Context) error {
	var req createWebhookRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid json"})
	}
	tenantID, ok := middleware.TenantID(c)
	if !ok {
		headerVal := c.Request().Header.Get("X-Tenant-ID")
		parsed, err := uuid.Parse(headerVal)
		if err != nil {
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "authenticated tenant context required"})
		}
		tenantID = parsed
	}
	wh, err := ctrl.svc.Create(c.Request().Context(), domain.CreateWebhookInput{
		TenantID: tenantID,
		URL:      req.URL,
		Secret:   req.Secret,
		Events:   req.Events,
	})
	if err != nil {
		log.Error().Err(err).Msg("webhook: create failed")
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "failed to create webhook"})
	}
	return c.JSON(http.StatusCreated, wh)
}

// @Summary      List webhooks
// @Description  Lists all webhook subscriptions for the tenant
// @Tags         Webhooks
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  map[string]interface{}
// @Failure      401  {object}  map[string]string
// @Failure      500  {object}  map[string]string
// @Router       /api/v1/webhooks [get]
func (ctrl *Controller) list(c echo.Context) error {
	tenantID, ok := middleware.TenantID(c)
	if !ok {
		headerVal := c.Request().Header.Get("X-Tenant-ID")
		parsed, err := uuid.Parse(headerVal)
		if err != nil {
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "authenticated tenant context required"})
		}
		tenantID = parsed
	}
	webhooks, err := ctrl.svc.List(c.Request().Context(), tenantID)
	if err != nil {
		log.Error().Err(err).Msg("webhook: list failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to list webhooks"})
	}
	return c.JSON(http.StatusOK, map[string]interface{}{"webhooks": webhooks})
}

// @Summary      Get webhook
// @Description  Returns a single webhook subscription by ID
// @Tags         Webhooks
// @Produce      json
// @Security     BearerAuth
// @Param        id  path  string  true  "Webhook ID (UUID)"
// @Success      200  {object}  domain.Webhook
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Router       /api/v1/webhooks/{id} [get]
func (ctrl *Controller) get(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid id"})
	}
	tenantID, ok := middleware.TenantID(c)
	if !ok {
		headerVal := c.Request().Header.Get("X-Tenant-ID")
		parsed, err := uuid.Parse(headerVal)
		if err != nil {
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "authenticated tenant context required"})
		}
		tenantID = parsed
	}
	wh, err := ctrl.svc.Get(c.Request().Context(), id, tenantID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "webhook not found"})
	}
	return c.JSON(http.StatusOK, wh)
}

// @Summary      Update webhook
// @Description  Updates an existing webhook subscription
// @Tags         Webhooks
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id    path  string                true  "Webhook ID (UUID)"
// @Param        body  body  updateWebhookRequest  true  "Updated webhook configuration"
// @Success      200  {object}  domain.Webhook
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Router       /api/v1/webhooks/{id} [put]
func (ctrl *Controller) update(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid id"})
	}
	tenantID, ok := middleware.TenantID(c)
	if !ok {
		headerVal := c.Request().Header.Get("X-Tenant-ID")
		parsed, err := uuid.Parse(headerVal)
		if err != nil {
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "authenticated tenant context required"})
		}
		tenantID = parsed
	}
	var req updateWebhookRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid json"})
	}
	wh, err := ctrl.svc.Update(c.Request().Context(), id, tenantID, req.URL, req.Events, req.IsActive)
	if err != nil {
		log.Error().Err(err).Str("webhook_id", id.String()).Msg("webhook: update failed")
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "failed to update webhook"})
	}
	return c.JSON(http.StatusOK, wh)
}

// @Summary      Delete webhook
// @Description  Deletes a webhook subscription
// @Tags         Webhooks
// @Security     BearerAuth
// @Param        id  path  string  true  "Webhook ID (UUID)"
// @Success      204
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Router       /api/v1/webhooks/{id} [delete]
func (ctrl *Controller) delete(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid id"})
	}
	tenantID, ok := middleware.TenantID(c)
	if !ok {
		headerVal := c.Request().Header.Get("X-Tenant-ID")
		parsed, err := uuid.Parse(headerVal)
		if err != nil {
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "authenticated tenant context required"})
		}
		tenantID = parsed
	}
	if err := ctrl.svc.Delete(c.Request().Context(), id, tenantID); err != nil {
		log.Error().Err(err).Str("webhook_id", id.String()).Msg("webhook: delete failed")
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "failed to delete webhook"})
	}
	return c.NoContent(http.StatusNoContent)
}
