package controller

import (
	"net/http"
	"strconv"

	"github.com/corvusHold/guard/internal/scim/domain"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

// Controller handles SCIM 2.0 HTTP requests.
type Controller struct {
	svc domain.Service
}

// New creates a new SCIM controller.
func New(svc domain.Service) *Controller {
	return &Controller{svc: svc}
}

// Register registers SCIM 2.0 routes under /scim/v2.
func (c *Controller) Register(e *echo.Echo) {
	scim := e.Group("/scim/v2")
	scim.GET("/Users", c.listUsers)
	scim.GET("/Users/:id", c.getUser)
	scim.POST("/Users", c.createUser)
	scim.PUT("/Users/:id", c.updateUser)
	scim.PATCH("/Users/:id", c.patchUser)
	scim.DELETE("/Users/:id", c.deleteUser)
	scim.GET("/Groups", c.listGroups)
	scim.GET("/Groups/:id", c.getGroup)
	scim.POST("/Groups", c.createGroup)
	scim.PUT("/Groups/:id", c.updateGroup)
	scim.PATCH("/Groups/:id", c.patchGroup)
	scim.DELETE("/Groups/:id", c.deleteGroup)
	scim.GET("/ServiceProviderConfig", c.serviceProviderConfig)
	scim.GET("/Schemas", c.schemas)
	scim.GET("/ResourceTypes", c.resourceTypes)
}

func (ctrl *Controller) tenantID(c echo.Context) (uuid.UUID, error) {
	return uuid.Parse(c.Request().Header.Get("X-Tenant-ID"))
}

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

func (ctrl *Controller) listGroups(c echo.Context) error {
	tid, err := ctrl.tenantID(c)
	if err != nil {
		return c.JSON(http.StatusBadRequest, domain.SCIMError{Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:Error"}, Detail: "X-Tenant-ID required", Status: 400})
	}
	filter := c.QueryParam("filter")
	startIndex, _ := strconv.Atoi(c.QueryParam("startIndex"))
	count, _ := strconv.Atoi(c.QueryParam("count"))
	resp, err := ctrl.svc.ListGroups(c.Request().Context(), tid, filter, startIndex, count)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, domain.SCIMError{Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:Error"}, Detail: err.Error(), Status: 500})
	}
	return c.JSON(http.StatusOK, resp)
}

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
