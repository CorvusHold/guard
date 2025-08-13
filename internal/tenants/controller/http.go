package controller

import (
	"net/http"
	"time"
	"strconv"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/labstack/echo/v4"

	domain "github.com/corvusHold/guard/internal/tenants/domain"
	"github.com/corvusHold/guard/internal/platform/validation"
)

type Controller struct {
	svc domain.Service
}

func New(svc domain.Service) *Controller {
	return &Controller{svc: svc}
}

func (h *Controller) Register(e *echo.Echo) {
	e.POST("/tenants", h.createTenant)
	e.GET("/tenants/:id", h.getTenantByID)
	e.GET("/tenants/by-name/:name", h.getTenantByName)
	e.PATCH("/tenants/:id/deactivate", h.deactivateTenant)
	e.GET("/tenants", h.listTenants)
}

type createTenantReq struct {
	Name string `json:"name" validate:"required"`
}

type tenantResp struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	IsActive  bool   `json:"is_active"`
	CreatedAt string `json:"created_at,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

func toUUIDString(u pgtype.UUID) string {
	if !u.Valid {
		return ""
	}
	return uuid.UUID(u.Bytes).String()
}

func toTimeString(t pgtype.Timestamptz) string {
	if !t.Valid {
		return ""
	}
	return t.Time.UTC().Format(time.RFC3339)
}

func (h *Controller) createTenant(c echo.Context) error {
	var req createTenantReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid json"})
	}
	if err := c.Validate(&req); err != nil {
		return c.JSON(http.StatusBadRequest, validation.ErrorResponse(err))
	}
	ten, err := h.svc.Create(c.Request().Context(), req.Name)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	return c.JSON(http.StatusCreated, tenantResp{
		ID:        toUUIDString(ten.ID),
		Name:      ten.Name,
		IsActive:  ten.IsActive,
		CreatedAt: toTimeString(ten.CreatedAt),
		UpdatedAt: toTimeString(ten.UpdatedAt),
	})
}

func (h *Controller) getTenantByID(c echo.Context) error {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid id"})
	}
	ten, err := h.svc.GetByID(c.Request().Context(), id)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "not found"})
	}
	return c.JSON(http.StatusOK, tenantResp{
		ID:        toUUIDString(ten.ID),
		Name:      ten.Name,
		IsActive:  ten.IsActive,
		CreatedAt: toTimeString(ten.CreatedAt),
		UpdatedAt: toTimeString(ten.UpdatedAt),
	})
}

func (h *Controller) getTenantByName(c echo.Context) error {
	name := c.Param("name")
	if name == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "name required"})
	}
	ten, err := h.svc.GetByName(c.Request().Context(), name)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "not found"})
	}
	return c.JSON(http.StatusOK, tenantResp{
		ID:        toUUIDString(ten.ID),
		Name:      ten.Name,
		IsActive:  ten.IsActive,
		CreatedAt: toTimeString(ten.CreatedAt),
		UpdatedAt: toTimeString(ten.UpdatedAt),
	})
}

func (h *Controller) deactivateTenant(c echo.Context) error {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid id"})
	}
	if err := h.svc.Deactivate(c.Request().Context(), id); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	return c.NoContent(http.StatusNoContent)
}

type listQuery struct {
	Q        string `query:"q"`
	Active   int    `query:"active"`   // -1 any, 1 active, 0 inactive
	Page     int    `query:"page"`
	PageSize int    `query:"page_size"`
}

type listResponse struct {
	Items      []tenantResp `json:"items"`
	Total      int64        `json:"total"`
	Page       int          `json:"page"`
	PageSize   int          `json:"page_size"`
	TotalPages int          `json:"total_pages"`
}

func (h *Controller) listTenants(c echo.Context) error {
	// Allow both query binding and manual fallback to avoid validation dependence
	q := listQuery{Active: -1}
	if err := c.Bind(&q); err != nil {
		// fallback manual parse
		q.Q = c.QueryParam("q")
		if a := c.QueryParam("active"); a != "" {
			if v, err := strconv.Atoi(a); err == nil {
				q.Active = v
			}
		}
		if p := c.QueryParam("page"); p != "" {
			if v, err := strconv.Atoi(p); err == nil {
				q.Page = v
			}
		}
		if ps := c.QueryParam("page_size"); ps != "" {
			if v, err := strconv.Atoi(ps); err == nil {
				q.PageSize = v
			}
		}
	}

	res, err := h.svc.List(c.Request().Context(), domain.ListOptions{
		Query:    q.Q,
		Active:   q.Active,
		Page:     q.Page,
		PageSize: q.PageSize,
	})
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	items := make([]tenantResp, 0, len(res.Items))
	for _, ten := range res.Items {
		items = append(items, tenantResp{
			ID:        toUUIDString(ten.ID),
			Name:      ten.Name,
			IsActive:  ten.IsActive,
			CreatedAt: toTimeString(ten.CreatedAt),
			UpdatedAt: toTimeString(ten.UpdatedAt),
		})
	}
	return c.JSON(http.StatusOK, listResponse{
		Items:      items,
		Total:      res.Total,
		Page:       res.Page,
		PageSize:   res.PageSize,
		TotalPages: res.TotalPages,
	})
}
