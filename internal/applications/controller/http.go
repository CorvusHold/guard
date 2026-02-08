package controller

import (
	"net/http"
	"strconv"

	"github.com/corvusHold/guard/internal/applications/domain"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

// Controller handles HTTP requests for application management.
type Controller struct {
	svc domain.Service
}

// New creates a new application controller.
func New(svc domain.Service) *Controller {
	return &Controller{svc: svc}
}

type createAppRequest struct {
	Name        string `json:"name" validate:"required"`
	Description string `json:"description"`
	LogoURI     string `json:"logo_uri"`
	HomepageURL string `json:"homepage_url"`
}

type updateAppRequest struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`
	LogoURI     *string `json:"logo_uri"`
	HomepageURL *string `json:"homepage_url"`
	IsActive    *bool   `json:"is_active"`
}

// RegisterV1 registers application routes under the given group.
func (ctrl *Controller) RegisterV1(g *echo.Group) {
	apps := g.Group("/applications")
	apps.POST("", ctrl.create)
	apps.GET("", ctrl.list)
	apps.GET("/:id", ctrl.get)
	apps.PUT("/:id", ctrl.update)
	apps.DELETE("/:id", ctrl.delete)
}

// @Summary      Create application
// @Description  Creates a new application within a tenant
// @Tags         Applications
// @Accept       json
// @Produce      json
// @Param        body  body  createAppRequest  true  "Application details"
// @Success      201   {object}  domain.Application
// @Failure      400   {object}  map[string]string
// @Router       /api/v1/applications [post]
func (ctrl *Controller) create(c echo.Context) error {
	var req createAppRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid json"})
	}

	tenantID, err := uuid.Parse(c.Request().Header.Get("X-Tenant-ID"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "X-Tenant-ID header required"})
	}

	// Extract user ID from JWT claims (sub)
	userID := uuid.Nil
	if sub := c.Get("user_id"); sub != nil {
		if id, ok := sub.(uuid.UUID); ok {
			userID = id
		}
	}

	app, err := ctrl.svc.Create(c.Request().Context(), domain.CreateInput{
		TenantID:    tenantID,
		Name:        req.Name,
		Description: req.Description,
		LogoURI:     req.LogoURI,
		HomepageURL: req.HomepageURL,
		CreatedBy:   userID,
	})
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	return c.JSON(http.StatusCreated, app)
}

// @Summary      List applications
// @Description  Lists all applications for a tenant
// @Tags         Applications
// @Produce      json
// @Param        limit   query  int  false  "Limit"
// @Param        offset  query  int  false  "Offset"
// @Success      200  {object}  map[string]interface{}
// @Router       /api/v1/applications [get]
func (ctrl *Controller) list(c echo.Context) error {
	tenantID, err := uuid.Parse(c.Request().Header.Get("X-Tenant-ID"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "X-Tenant-ID header required"})
	}

	limit, _ := strconv.Atoi(c.QueryParam("limit"))
	offset, _ := strconv.Atoi(c.QueryParam("offset"))

	apps, total, err := ctrl.svc.List(c.Request().Context(), tenantID, domain.ListOptions{Limit: limit, Offset: offset})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	return c.JSON(http.StatusOK, map[string]interface{}{
		"applications": apps,
		"total":        total,
	})
}

// @Summary      Get application
// @Description  Gets an application by ID
// @Tags         Applications
// @Produce      json
// @Param        id  path  string  true  "Application ID"
// @Success      200  {object}  domain.Application
// @Failure      404  {object}  map[string]string
// @Router       /api/v1/applications/{id} [get]
func (ctrl *Controller) get(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid id"})
	}
	app, err := ctrl.svc.GetByID(c.Request().Context(), id)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "application not found"})
	}
	return c.JSON(http.StatusOK, app)
}

// @Summary      Update application
// @Description  Updates an application
// @Tags         Applications
// @Accept       json
// @Produce      json
// @Param        id    path  string            true  "Application ID"
// @Param        body  body  updateAppRequest  true  "Updated fields"
// @Success      200   {object}  domain.Application
// @Failure      400   {object}  map[string]string
// @Router       /api/v1/applications/{id} [put]
func (ctrl *Controller) update(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid id"})
	}
	var req updateAppRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid json"})
	}
	app, err := ctrl.svc.Update(c.Request().Context(), id, domain.UpdateInput{
		Name:        req.Name,
		Description: req.Description,
		LogoURI:     req.LogoURI,
		HomepageURL: req.HomepageURL,
		IsActive:    req.IsActive,
	})
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	return c.JSON(http.StatusOK, app)
}

// @Summary      Delete application
// @Description  Deletes an application
// @Tags         Applications
// @Param        id  path  string  true  "Application ID"
// @Success      204
// @Failure      400  {object}  map[string]string
// @Router       /api/v1/applications/{id} [delete]
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
