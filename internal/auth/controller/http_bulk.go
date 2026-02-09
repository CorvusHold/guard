package controller

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/corvusHold/guard/internal/auth/domain"
	"github.com/labstack/echo/v4"
)

// registerBulkRoutes registers bulk import/export endpoints.
func (h *Controller) registerBulkRoutes(g *echo.Group) {
	bulk := g.Group("/bulk")
	bulk.POST("/users/import", h.bulkImportUsers)
	bulk.GET("/users/export", h.bulkExportUsers)
}

type bulkImportResult struct {
	Created int      `json:"created"`
	Skipped int      `json:"skipped"`
	Errors  []string `json:"errors,omitempty"`
}

// @Summary      Bulk import users
// @Description  Import users from CSV or JSON. CSV columns: email,first_name,last_name,role. JSON: array of objects.
// @Tags         Admin Bulk
// @Accept       multipart/form-data
// @Produce      json
// @Param        file  formData  file  true  "CSV or JSON file"
// @Success      200   {object}  bulkImportResult
// @Failure      400   {object}  map[string]string
// @Router       /api/v1/auth/admin/bulk/users/import [post]
func (h *Controller) bulkImportUsers(c echo.Context) error {
	in, err := h.requireAuth(c)
	if err != nil {
		return nil
	}
	ok, err := h.svc.HasPermission(c.Request().Context(), in.UserID, in.TenantID, "users:manage", "*", nil)
	if err != nil || !ok {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "admin required"})
	}

	const maxImportSize = 10 << 20 // 10 MB
	const maxImportRows = 10_000

	file, err := c.FormFile("file")
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "file required"})
	}
	if file.Size > maxImportSize {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("file too large (max %d MB)", maxImportSize>>20)})
	}
	src, err := file.Open()
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "cannot open file"})
	}
	defer func() {
		_ = src.Close()
	}()

	// Wrap in a LimitReader as a safety net even if Content-Length was spoofed
	limitedSrc := io.LimitReader(src, maxImportSize+1)

	var users []domain.AdminCreateUserInput
	contentType := file.Header.Get("Content-Type")

	if strings.Contains(contentType, "json") || strings.HasSuffix(file.Filename, ".json") {
		data, err := io.ReadAll(limitedSrc)
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "cannot read file"})
		}
		var records []struct {
			Email     string `json:"email"`
			FirstName string `json:"first_name"`
			LastName  string `json:"last_name"`
			Password  string `json:"password"`
			Role      string `json:"role"`
		}
		if err := json.Unmarshal(data, &records); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		}
		if len(records) > maxImportRows {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("too many rows (max %d)", maxImportRows)})
		}
		for _, r := range records {
			roles := []string{"member"}
			if r.Role != "" {
				roles = []string{r.Role}
			}
			users = append(users, domain.AdminCreateUserInput{
				TenantID:  in.TenantID,
				Email:     r.Email,
				FirstName: r.FirstName,
				LastName:  r.LastName,
				Password:  r.Password,
				Roles:     roles,
			})
		}
	} else {
		// CSV
		reader := csv.NewReader(limitedSrc)
		header, err := reader.Read()
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "cannot read CSV header"})
		}
		colMap := make(map[string]int)
		for i, col := range header {
			colMap[strings.TrimSpace(strings.ToLower(col))] = i
		}

		for {
			record, err := reader.Read()
			if err == io.EOF {
				break
			}
			if err != nil {
				break
			}
			getCol := func(name string) string {
				if idx, ok := colMap[name]; ok && idx < len(record) {
					return strings.TrimSpace(record[idx])
				}
				return ""
			}
			roles := []string{"member"}
			if r := getCol("role"); r != "" {
				roles = []string{r}
			}
			users = append(users, domain.AdminCreateUserInput{
				TenantID:  in.TenantID,
				Email:     getCol("email"),
				FirstName: getCol("first_name"),
				LastName:  getCol("last_name"),
				Password:  getCol("password"),
				Roles:     roles,
			})
			if len(users) >= maxImportRows {
				break
			}
		}
	}

	result := bulkImportResult{}
	for _, u := range users {
		if u.Email == "" {
			result.Skipped++
			continue
		}
		_, err := h.svc.AdminCreateUser(c.Request().Context(), u)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %s", u.Email, err.Error()))
			result.Skipped++
		} else {
			result.Created++
		}
	}
	return c.JSON(http.StatusOK, result)
}

// @Summary      Bulk export users
// @Description  Export all users in a tenant as JSON
// @Tags         Admin Bulk
// @Produce      json
// @Param        format  query  string  false  "Export format (json or csv)"
// @Success      200
// @Router       /api/v1/auth/admin/bulk/users/export [get]
func (h *Controller) bulkExportUsers(c echo.Context) error {
	in, err := h.requireAuth(c)
	if err != nil {
		return nil
	}
	ok, err := h.svc.HasPermission(c.Request().Context(), in.UserID, in.TenantID, "users:manage", "*", nil)
	if err != nil || !ok {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "admin required"})
	}

	const maxExportLimit = 10_000
	limit, _ := strconv.Atoi(c.QueryParam("limit"))
	offset, _ := strconv.Atoi(c.QueryParam("offset"))
	if limit <= 0 || limit > maxExportLimit {
		limit = maxExportLimit
	}
	if offset < 0 {
		offset = 0
	}

	// Fetch limit+1 to detect if there are more rows beyond this page
	users, err := h.svc.ListUsersByTenant(c.Request().Context(), in.TenantID, limit+1, offset)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	hasMore := len(users) > limit
	if hasMore {
		users = users[:limit]
	}

	format := c.QueryParam("format")
	if format == "csv" {
		c.Response().Header().Set("Content-Type", "text/csv")
		c.Response().Header().Set("Content-Disposition", "attachment; filename=users.csv")
		w := csv.NewWriter(c.Response().Writer)
		_ = w.Write([]string{"id", "email", "first_name", "last_name", "blocked", "created_at"})
		for _, u := range users {
			_ = w.Write([]string{u.ID.String(), u.Email, u.FirstName, u.LastName, fmt.Sprintf("%t", u.Blocked), u.CreatedAt.Format("2006-01-02T15:04:05Z")})
		}
		w.Flush()
		return nil
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"users":     users,
		"tenant_id": in.TenantID,
		"count":     len(users),
		"has_more":  hasMore,
		"offset":    offset,
	})
}
