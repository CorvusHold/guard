package controller

import (
	"crypto/subtle"
	"net/http"
	"strconv"
	"strings"

	"github.com/corvusHold/guard/internal/scim/domain"
	sdomain "github.com/corvusHold/guard/internal/settings/domain"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

// Controller handles SCIM 2.0 HTTP requests.
type Controller struct {
	svc      domain.Service
	settings sdomain.Service
}

// New creates a new SCIM controller.
func New(svc domain.Service, settings sdomain.Service) *Controller {
	return &Controller{svc: svc, settings: settings}
}

// scimBearerAuth is middleware that validates the SCIM bearer token per-tenant.
// The tenant is identified by the X-Tenant-ID header.
func (ctrl *Controller) scimBearerAuth(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		tid, err := uuid.Parse(c.Request().Header.Get("X-Tenant-ID"))
		if err != nil {
			return c.JSON(http.StatusBadRequest, domain.SCIMError{
				Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
				Detail:  "X-Tenant-ID required",
				Status:  400,
			})
		}

		// Load the expected bearer token for this tenant
		expected, _ := ctrl.settings.GetString(c.Request().Context(), sdomain.KeySCIMBearerToken, &tid, "")
		if expected == "" {
			return c.JSON(http.StatusForbidden, domain.SCIMError{
				Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
				Detail:  "SCIM provisioning is not configured for this tenant",
				Status:  403,
			})
		}

		auth := c.Request().Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			return c.JSON(http.StatusUnauthorized, domain.SCIMError{
				Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
				Detail:  "Bearer token required",
				Status:  401,
			})
		}
		token := strings.TrimPrefix(auth, "Bearer ")

		if subtle.ConstantTimeCompare([]byte(token), []byte(expected)) != 1 {
			return c.JSON(http.StatusUnauthorized, domain.SCIMError{
				Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
				Detail:  "Invalid bearer token",
				Status:  401,
			})
		}

		return next(c)
	}
}

// Register registers SCIM 2.0 routes under /scim/v2.
func (ctrl *Controller) Register(e *echo.Echo) {
	scim := e.Group("/scim/v2", ctrl.scimBearerAuth)
	scim.GET("/Users", ctrl.listUsers)
	scim.GET("/Users/:id", ctrl.getUser)
	scim.POST("/Users", ctrl.createUser)
	scim.PUT("/Users/:id", ctrl.updateUser)
	scim.PATCH("/Users/:id", ctrl.patchUser)
	scim.DELETE("/Users/:id", ctrl.deleteUser)
	scim.GET("/Groups", ctrl.listGroups)
	scim.GET("/Groups/:id", ctrl.getGroup)
	scim.POST("/Groups", ctrl.createGroup)
	scim.PUT("/Groups/:id", ctrl.updateGroup)
	scim.PATCH("/Groups/:id", ctrl.patchGroup)
	scim.DELETE("/Groups/:id", ctrl.deleteGroup)
	scim.GET("/ServiceProviderConfig", ctrl.serviceProviderConfig)
	scim.GET("/Schemas", ctrl.schemas)
	scim.GET("/ResourceTypes", ctrl.resourceTypes)
}

func (ctrl *Controller) tenantID(c echo.Context) (uuid.UUID, error) {
	return uuid.Parse(c.Request().Header.Get("X-Tenant-ID"))
}

// List SCIM Users godoc
// @Summary      List SCIM users
// @Description  Returns a paginated list of users for the tenant per SCIM 2.0
// @Tags         SCIM
// @Produce      json
// @Param        X-Tenant-ID  header  string  true   "Tenant ID"
// @Param        filter       query   string  false  "SCIM filter expression"
// @Param        startIndex   query   int     false  "1-based start index"
// @Param        count        query   int     false  "Page size"
// @Success      200  {object}  domain.SCIMListResponse
// @Failure      400  {object}  domain.SCIMError
// @Failure      401  {object}  domain.SCIMError
// @Failure      500  {object}  domain.SCIMError
// @Router       /scim/v2/Users [get]
func (ctrl *Controller) listUsers(c echo.Context) error {
	tid, err := ctrl.tenantID(c)
	if err != nil {
		return c.JSON(http.StatusBadRequest, domain.SCIMError{Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:Error"}, Detail: "X-Tenant-ID required", Status: 400})
	}
	filter := c.QueryParam("filter")
	startIndex, _ := strconv.Atoi(c.QueryParam("startIndex"))
	count, _ := strconv.Atoi(c.QueryParam("count"))
	if startIndex <= 0 {
		startIndex = 1
	}
	if count <= 0 {
		count = 100
	}
	resp, err := ctrl.svc.ListUsers(c.Request().Context(), tid, filter, startIndex, count)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, domain.SCIMError{Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:Error"}, Detail: err.Error(), Status: 500})
	}
	return c.JSON(http.StatusOK, resp)
}

// Get SCIM User godoc
// @Summary      Get a SCIM user by ID
// @Description  Returns a single user resource
// @Tags         SCIM
// @Produce      json
// @Param        X-Tenant-ID  header  string  true  "Tenant ID"
// @Param        id           path    string  true  "User ID"
// @Success      200  {object}  domain.SCIMUser
// @Failure      400  {object}  domain.SCIMError
// @Failure      404  {object}  domain.SCIMError
// @Router       /scim/v2/Users/{id} [get]
func (ctrl *Controller) getUser(c echo.Context) error {
	tid, err := ctrl.tenantID(c)
	if err != nil {
		return c.JSON(http.StatusBadRequest, domain.SCIMError{Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:Error"}, Detail: "X-Tenant-ID required", Status: 400})
	}
	user, err := ctrl.svc.GetUser(c.Request().Context(), tid, c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusNotFound, domain.SCIMError{Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:Error"}, Detail: "User not found", Status: 404})
	}
	return c.JSON(http.StatusOK, user)
}

// Create SCIM User godoc
// @Summary      Create a SCIM user
// @Description  Provisions a new user in the tenant
// @Tags         SCIM
// @Accept       json
// @Produce      json
// @Param        X-Tenant-ID  header  string          true  "Tenant ID"
// @Param        body         body    domain.SCIMUser true  "User resource"
// @Success      201  {object}  domain.SCIMUser
// @Failure      400  {object}  domain.SCIMError
// @Failure      409  {object}  domain.SCIMError
// @Router       /scim/v2/Users [post]
func (ctrl *Controller) createUser(c echo.Context) error {
	tid, err := ctrl.tenantID(c)
	if err != nil {
		return c.JSON(http.StatusBadRequest, domain.SCIMError{Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:Error"}, Detail: "X-Tenant-ID required", Status: 400})
	}
	var user domain.SCIMUser
	if err := c.Bind(&user); err != nil {
		return c.JSON(http.StatusBadRequest, domain.SCIMError{Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:Error"}, Detail: "Invalid request", Status: 400})
	}
	created, err := ctrl.svc.CreateUser(c.Request().Context(), tid, user)
	if err != nil {
		return c.JSON(http.StatusConflict, domain.SCIMError{Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:Error"}, Detail: err.Error(), Status: 409})
	}
	return c.JSON(http.StatusCreated, created)
}

// Update SCIM User godoc
// @Summary      Replace a SCIM user
// @Description  Replaces an existing user resource
// @Tags         SCIM
// @Accept       json
// @Produce      json
// @Param        X-Tenant-ID  header  string          true  "Tenant ID"
// @Param        id           path    string          true  "User ID"
// @Param        body         body    domain.SCIMUser true  "User resource"
// @Success      200  {object}  domain.SCIMUser
// @Failure      400  {object}  domain.SCIMError
// @Failure      404  {object}  domain.SCIMError
// @Router       /scim/v2/Users/{id} [put]
func (ctrl *Controller) updateUser(c echo.Context) error {
	tid, err := ctrl.tenantID(c)
	if err != nil {
		return c.JSON(http.StatusBadRequest, domain.SCIMError{Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:Error"}, Detail: "X-Tenant-ID required", Status: 400})
	}
	var user domain.SCIMUser
	if err := c.Bind(&user); err != nil {
		return c.JSON(http.StatusBadRequest, domain.SCIMError{Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:Error"}, Detail: "Invalid request", Status: 400})
	}
	updated, err := ctrl.svc.UpdateUser(c.Request().Context(), tid, c.Param("id"), user)
	if err != nil {
		return c.JSON(http.StatusNotFound, domain.SCIMError{Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:Error"}, Detail: err.Error(), Status: 404})
	}
	return c.JSON(http.StatusOK, updated)
}

// Patch SCIM User godoc
// @Summary      Patch a SCIM user
// @Description  Applies partial updates to a user resource
// @Tags         SCIM
// @Accept       json
// @Produce      json
// @Param        X-Tenant-ID  header  string                   true  "Tenant ID"
// @Param        id           path    string                   true  "User ID"
// @Param        body         body    domain.SCIMPatchRequest  true  "Patch operations"
// @Success      200  {object}  domain.SCIMUser
// @Failure      400  {object}  domain.SCIMError
// @Router       /scim/v2/Users/{id} [patch]
func (ctrl *Controller) patchUser(c echo.Context) error {
	tid, err := ctrl.tenantID(c)
	if err != nil {
		return c.JSON(http.StatusBadRequest, domain.SCIMError{Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:Error"}, Detail: "X-Tenant-ID required", Status: 400})
	}
	var req domain.SCIMPatchRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, domain.SCIMError{Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:Error"}, Detail: "Invalid request", Status: 400})
	}
	updated, err := ctrl.svc.PatchUser(c.Request().Context(), tid, c.Param("id"), req.Operations)
	if err != nil {
		return c.JSON(http.StatusBadRequest, domain.SCIMError{Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:Error"}, Detail: err.Error(), Status: 400})
	}
	return c.JSON(http.StatusOK, updated)
}

// Delete SCIM User godoc
// @Summary      Delete a SCIM user
// @Description  Deprovisions a user from the tenant
// @Tags         SCIM
// @Param        X-Tenant-ID  header  string  true  "Tenant ID"
// @Param        id           path    string  true  "User ID"
// @Success      204
// @Failure      400  {object}  domain.SCIMError
// @Failure      404  {object}  domain.SCIMError
// @Router       /scim/v2/Users/{id} [delete]
func (ctrl *Controller) deleteUser(c echo.Context) error {
	tid, err := ctrl.tenantID(c)
	if err != nil {
		return c.JSON(http.StatusBadRequest, domain.SCIMError{Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:Error"}, Detail: "X-Tenant-ID required", Status: 400})
	}
	if err := ctrl.svc.DeleteUser(c.Request().Context(), tid, c.Param("id")); err != nil {
		return c.JSON(http.StatusNotFound, domain.SCIMError{Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:Error"}, Detail: err.Error(), Status: 404})
	}
	return c.NoContent(http.StatusNoContent)
}

// List SCIM Groups godoc
// @Summary      List SCIM groups
// @Description  Returns a paginated list of groups for the tenant per SCIM 2.0
// @Tags         SCIM
// @Produce      json
// @Param        X-Tenant-ID  header  string  true   "Tenant ID"
// @Param        filter       query   string  false  "SCIM filter expression"
// @Param        startIndex   query   int     false  "1-based start index"
// @Param        count        query   int     false  "Page size"
// @Success      200  {object}  domain.SCIMListResponse
// @Failure      400  {object}  domain.SCIMError
// @Failure      500  {object}  domain.SCIMError
// @Router       /scim/v2/Groups [get]
func (ctrl *Controller) listGroups(c echo.Context) error {
	tid, err := ctrl.tenantID(c)
	if err != nil {
		return c.JSON(http.StatusBadRequest, domain.SCIMError{Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:Error"}, Detail: "X-Tenant-ID required", Status: 400})
	}
	filter := c.QueryParam("filter")
	startIndex, _ := strconv.Atoi(c.QueryParam("startIndex"))
	count, _ := strconv.Atoi(c.QueryParam("count"))
	if startIndex <= 0 {
		startIndex = 1
	}
	if count <= 0 {
		count = 100
	}
	resp, err := ctrl.svc.ListGroups(c.Request().Context(), tid, filter, startIndex, count)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, domain.SCIMError{Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:Error"}, Detail: err.Error(), Status: 500})
	}
	return c.JSON(http.StatusOK, resp)
}

// Get SCIM Group godoc
// @Summary      Get a SCIM group by ID
// @Description  Returns a single group resource
// @Tags         SCIM
// @Produce      json
// @Param        X-Tenant-ID  header  string  true  "Tenant ID"
// @Param        id           path    string  true  "Group ID"
// @Success      200  {object}  domain.SCIMGroup
// @Failure      400  {object}  domain.SCIMError
// @Failure      404  {object}  domain.SCIMError
// @Router       /scim/v2/Groups/{id} [get]
func (ctrl *Controller) getGroup(c echo.Context) error {
	tid, err := ctrl.tenantID(c)
	if err != nil {
		return c.JSON(http.StatusBadRequest, domain.SCIMError{Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:Error"}, Detail: "X-Tenant-ID required", Status: 400})
	}
	group, err := ctrl.svc.GetGroup(c.Request().Context(), tid, c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusNotFound, domain.SCIMError{Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:Error"}, Detail: "Group not found", Status: 404})
	}
	return c.JSON(http.StatusOK, group)
}

// Create SCIM Group godoc
// @Summary      Create a SCIM group
// @Description  Creates a new group in the tenant
// @Tags         SCIM
// @Accept       json
// @Produce      json
// @Param        X-Tenant-ID  header  string           true  "Tenant ID"
// @Param        body         body    domain.SCIMGroup true  "Group resource"
// @Success      201  {object}  domain.SCIMGroup
// @Failure      400  {object}  domain.SCIMError
// @Failure      409  {object}  domain.SCIMError
// @Router       /scim/v2/Groups [post]
func (ctrl *Controller) createGroup(c echo.Context) error {
	tid, err := ctrl.tenantID(c)
	if err != nil {
		return c.JSON(http.StatusBadRequest, domain.SCIMError{Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:Error"}, Detail: "X-Tenant-ID required", Status: 400})
	}
	var group domain.SCIMGroup
	if err := c.Bind(&group); err != nil {
		return c.JSON(http.StatusBadRequest, domain.SCIMError{Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:Error"}, Detail: "Invalid request", Status: 400})
	}
	created, err := ctrl.svc.CreateGroup(c.Request().Context(), tid, group)
	if err != nil {
		return c.JSON(http.StatusConflict, domain.SCIMError{Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:Error"}, Detail: err.Error(), Status: 409})
	}
	return c.JSON(http.StatusCreated, created)
}

// Update SCIM Group godoc
// @Summary      Replace a SCIM group
// @Description  Replaces an existing group resource
// @Tags         SCIM
// @Accept       json
// @Produce      json
// @Param        X-Tenant-ID  header  string           true  "Tenant ID"
// @Param        id           path    string           true  "Group ID"
// @Param        body         body    domain.SCIMGroup true  "Group resource"
// @Success      200  {object}  domain.SCIMGroup
// @Failure      400  {object}  domain.SCIMError
// @Failure      404  {object}  domain.SCIMError
// @Router       /scim/v2/Groups/{id} [put]
func (ctrl *Controller) updateGroup(c echo.Context) error {
	tid, err := ctrl.tenantID(c)
	if err != nil {
		return c.JSON(http.StatusBadRequest, domain.SCIMError{Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:Error"}, Detail: "X-Tenant-ID required", Status: 400})
	}
	var group domain.SCIMGroup
	if err := c.Bind(&group); err != nil {
		return c.JSON(http.StatusBadRequest, domain.SCIMError{Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:Error"}, Detail: "Invalid request", Status: 400})
	}
	updated, err := ctrl.svc.UpdateGroup(c.Request().Context(), tid, c.Param("id"), group)
	if err != nil {
		return c.JSON(http.StatusNotFound, domain.SCIMError{Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:Error"}, Detail: err.Error(), Status: 404})
	}
	return c.JSON(http.StatusOK, updated)
}

// Patch SCIM Group godoc
// @Summary      Patch a SCIM group
// @Description  Applies partial updates to a group resource
// @Tags         SCIM
// @Accept       json
// @Produce      json
// @Param        X-Tenant-ID  header  string                   true  "Tenant ID"
// @Param        id           path    string                   true  "Group ID"
// @Param        body         body    domain.SCIMPatchRequest  true  "Patch operations"
// @Success      200  {object}  domain.SCIMGroup
// @Failure      400  {object}  domain.SCIMError
// @Router       /scim/v2/Groups/{id} [patch]
func (ctrl *Controller) patchGroup(c echo.Context) error {
	tid, err := ctrl.tenantID(c)
	if err != nil {
		return c.JSON(http.StatusBadRequest, domain.SCIMError{Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:Error"}, Detail: "X-Tenant-ID required", Status: 400})
	}
	var req domain.SCIMPatchRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, domain.SCIMError{Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:Error"}, Detail: "Invalid request", Status: 400})
	}
	updated, err := ctrl.svc.PatchGroup(c.Request().Context(), tid, c.Param("id"), req.Operations)
	if err != nil {
		return c.JSON(http.StatusBadRequest, domain.SCIMError{Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:Error"}, Detail: err.Error(), Status: 400})
	}
	return c.JSON(http.StatusOK, updated)
}

// Delete SCIM Group godoc
// @Summary      Delete a SCIM group
// @Description  Removes a group from the tenant
// @Tags         SCIM
// @Param        X-Tenant-ID  header  string  true  "Tenant ID"
// @Param        id           path    string  true  "Group ID"
// @Success      204
// @Failure      400  {object}  domain.SCIMError
// @Failure      404  {object}  domain.SCIMError
// @Router       /scim/v2/Groups/{id} [delete]
func (ctrl *Controller) deleteGroup(c echo.Context) error {
	tid, err := ctrl.tenantID(c)
	if err != nil {
		return c.JSON(http.StatusBadRequest, domain.SCIMError{Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:Error"}, Detail: "X-Tenant-ID required", Status: 400})
	}
	if err := ctrl.svc.DeleteGroup(c.Request().Context(), tid, c.Param("id")); err != nil {
		return c.JSON(http.StatusNotFound, domain.SCIMError{Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:Error"}, Detail: err.Error(), Status: 404})
	}
	return c.NoContent(http.StatusNoContent)
}

// SCIM ServiceProviderConfig godoc
// @Summary      SCIM service provider configuration
// @Description  Returns the SCIM 2.0 service provider configuration
// @Tags         SCIM
// @Produce      json
// @Success      200  {object}  map[string]interface{}
// @Router       /scim/v2/ServiceProviderConfig [get]
func (ctrl *Controller) serviceProviderConfig(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]interface{}{
		"schemas":               []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
		"documentationUri":      "https://guard.corvus.dev/docs/scim",
		"patch":                 map[string]bool{"supported": true},
		"bulk":                  map[string]interface{}{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":                map[string]interface{}{"supported": true, "maxResults": 200},
		"changePassword":        map[string]bool{"supported": false},
		"sort":                  map[string]bool{"supported": false},
		"etag":                  map[string]bool{"supported": false},
		"authenticationSchemes": []map[string]string{{"type": "oauthbearertoken", "name": "OAuth Bearer Token", "description": "Authentication via API key or Bearer token"}},
	})
}

// SCIM Schemas godoc
// @Summary      SCIM schemas
// @Description  Returns the supported SCIM 2.0 schemas
// @Tags         SCIM
// @Produce      json
// @Success      200  {object}  map[string]interface{}
// @Router       /scim/v2/Schemas [get]
func (ctrl *Controller) schemas(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]interface{}{
		"schemas":      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		"totalResults": 2,
		"Resources": []map[string]interface{}{
			{"id": "urn:ietf:params:scim:schemas:core:2.0:User", "name": "User"},
			{"id": "urn:ietf:params:scim:schemas:core:2.0:Group", "name": "Group"},
		},
	})
}

// SCIM ResourceTypes godoc
// @Summary      SCIM resource types
// @Description  Returns the supported SCIM 2.0 resource types
// @Tags         SCIM
// @Produce      json
// @Success      200  {object}  map[string]interface{}
// @Router       /scim/v2/ResourceTypes [get]
func (ctrl *Controller) resourceTypes(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]interface{}{
		"schemas":      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		"totalResults": 2,
		"Resources": []map[string]interface{}{
			{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"}, "id": "User", "name": "User", "endpoint": "/scim/v2/Users", "schema": "urn:ietf:params:scim:schemas:core:2.0:User"},
			{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"}, "id": "Group", "name": "Group", "endpoint": "/scim/v2/Groups", "schema": "urn:ietf:params:scim:schemas:core:2.0:Group"},
		},
	})
}
