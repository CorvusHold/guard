package controller

import (
	"errors"
	"net/http"
	"strings"
	"time"

	domain "github.com/corvusHold/guard/internal/auth/domain"
	evdomain "github.com/corvusHold/guard/internal/events/domain"
	"github.com/corvusHold/guard/internal/platform/validation"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

// ---- Admin: FGA (scaffold) ----

// getToken returns the access token from the Authorization header (bearer token)
// or, if empty and auth mode is "cookie", from the guard access token cookie.
func (h *Controller) getToken(c echo.Context) string {
	tok := bearerToken(c)
	if tok == "" {
		authMode := detectAuthMode(c, h.cfg.DefaultAuthMode)
		if authMode == "cookie" {
			if cookie, cerr := c.Cookie(guardAccessTokenCookieName); cerr == nil && cookie.Value != "" {
				tok = cookie.Value
			}
		}
	}
	return tok
}

// fgaCreateGroupReq represents the request to create a group.
type fgaCreateGroupReq struct {
	TenantID    string `json:"tenant_id" validate:"required,uuid4"`
	Name        string `json:"name" validate:"required,min=1"`
	Description string `json:"description" validate:"omitempty"`
}

// fgaGroupItem represents a group in API responses.
type fgaGroupItem struct {
	ID          uuid.UUID `json:"id"`
	TenantID    uuid.UUID `json:"tenant_id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
}

// fgaListGroupsResp wraps groups array.
type fgaListGroupsResp struct {
	Groups []fgaGroupItem `json:"groups"`
}

// FGA Create Group godoc
// @Summary      Create group (admin-only)
// @Description  Creates a new group for the specified tenant.
// @Tags         auth.admin
// @Security     BearerAuth
// @Accept       json
// @Produce      json
// @Param        body  body  fgaCreateGroupReq  true  "tenant_id, name, description"
// @Success      201   {object}  fgaGroupItem
// @Failure      400   {object}  map[string]string
// @Failure      409   {object}  map[string]string
// @Failure      401   {object}  map[string]string
// @Failure      403   {object}  map[string]string
// @Router       /api/v1/auth/admin/fga/groups [post]
func (h *Controller) fgaCreateGroup(c echo.Context) error {
	// JWT + admin check
	tok := h.getToken(c)
	if tok == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
	}
	in, err := h.svc.Introspect(c.Request().Context(), tok)
	if err != nil || !in.Active {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid token"})
	}
	isAdmin := false
	for _, r := range in.Roles {
		if strings.EqualFold(r, "admin") {
			isAdmin = true
			break
		}
	}
	if !isAdmin {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden"})
	}

	var req fgaCreateGroupReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid json"})
	}
	if err := c.Validate(&req); err != nil {
		return c.JSON(http.StatusBadRequest, validation.ErrorResponse(err))
	}
	tenantID, err := uuid.Parse(req.TenantID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid tenant_id"})
	}

	g, err := h.svc.CreateGroup(c.Request().Context(), tenantID, req.Name, req.Description)
	if err != nil {
		if errors.Is(err, domain.ErrDuplicateGroup) {
			return c.JSON(http.StatusConflict, map[string]string{"error": "group already exists"})
		}
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	if h.pub != nil {
		_ = h.pub.Publish(c.Request().Context(), evdomain.Event{
			Type:     "fga.group.create.success",
			TenantID: tenantID,
			UserID:   in.UserID,
			Meta: map[string]string{
				"group_id":   g.ID.String(),
				"group_name": g.Name,
			},
			Time: time.Now(),
		})
	}
	return c.JSON(http.StatusCreated, fgaGroupItem{ID: g.ID, TenantID: g.TenantID, Name: g.Name, Description: g.Description})
}

// FGA List Groups godoc
// @Summary      List groups for a tenant (admin-only)
// @Description  Lists groups for the specified tenant.
// @Tags         auth.admin
// @Security     BearerAuth
// @Produce      json
// @Param        tenant_id  query  string  true  "Tenant ID (UUID)"
// @Success      200  {object}  fgaListGroupsResp
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      403  {object}  map[string]string
// @Router       /api/v1/auth/admin/fga/groups [get]
func (h *Controller) fgaListGroups(c echo.Context) error {
	tok := h.getToken(c)
	if tok == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
	}
	in, err := h.svc.Introspect(c.Request().Context(), tok)
	if err != nil || !in.Active {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid token"})
	}
	isAdmin := false
	for _, r := range in.Roles {
		if strings.EqualFold(r, "admin") {
			isAdmin = true
			break
		}
	}
	if !isAdmin {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden"})
	}

	tenStr := c.QueryParam("tenant_id")
	if tenStr == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "tenant_id required"})
	}
	tenantID, err := uuid.Parse(tenStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid tenant_id"})
	}

	groups, err := h.svc.ListGroups(c.Request().Context(), tenantID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	out := make([]fgaGroupItem, 0, len(groups))
	for _, g := range groups {
		out = append(out, fgaGroupItem{ID: g.ID, TenantID: g.TenantID, Name: g.Name, Description: g.Description})
	}
	return c.JSON(http.StatusOK, fgaListGroupsResp{Groups: out})
}

// FGA Delete Group godoc
// @Summary      Delete group (admin-only)
// @Description  Deletes a group for the specified tenant.
// @Tags         auth.admin
// @Security     BearerAuth
// @Param        id         path   string  true  "Group ID (UUID)"
// @Param        tenant_id  query  string  true  "Tenant ID (UUID)"
// @Success      204
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      403  {object}  map[string]string
// @Router       /api/v1/auth/admin/fga/groups/{id} [delete]
func (h *Controller) fgaDeleteGroup(c echo.Context) error {
	tok := h.getToken(c)
	if tok == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
	}
	in, err := h.svc.Introspect(c.Request().Context(), tok)
	if err != nil || !in.Active {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid token"})
	}
	isAdmin := false
	for _, r := range in.Roles {
		if strings.EqualFold(r, "admin") {
			isAdmin = true
			break
		}
	}
	if !isAdmin {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden"})
	}

	groupIDStr := c.Param("id")
	groupID, err := uuid.Parse(groupIDStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid group id"})
	}
	tenStr := c.QueryParam("tenant_id")
	if tenStr == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "tenant_id required"})
	}
	tenantID, err := uuid.Parse(tenStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid tenant_id"})
	}

	if err := h.svc.DeleteGroup(c.Request().Context(), groupID, tenantID); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	if h.pub != nil {
		_ = h.pub.Publish(c.Request().Context(), evdomain.Event{
			Type:     "fga.group.delete.success",
			TenantID: tenantID,
			UserID:   in.UserID,
			Meta:     map[string]string{"group_id": groupID.String()},
			Time:     time.Now(),
		})
	}
	return c.NoContent(http.StatusNoContent)
}

// fgaModifyGroupMemberReq modifies group membership.
type fgaModifyGroupMemberReq struct {
	UserID string `json:"user_id" validate:"required,uuid4"`
}

// FGA Add Group Member godoc
// @Summary      Add user to group (admin-only)
// @Description  Adds a user to a group.
// @Tags         auth.admin
// @Security     BearerAuth
// @Accept       json
// @Param        id    path   string                  true  "Group ID (UUID)"
// @Param        body  body   fgaModifyGroupMemberReq true  "user_id"
// @Success      204
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      403  {object}  map[string]string
// @Router       /api/v1/auth/admin/fga/groups/{id}/members [post]
func (h *Controller) fgaAddGroupMember(c echo.Context) error {
	tok := h.getToken(c)
	if tok == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
	}
	in, err := h.svc.Introspect(c.Request().Context(), tok)
	if err != nil || !in.Active {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid token"})
	}
	isAdmin := false
	for _, r := range in.Roles {
		if strings.EqualFold(r, "admin") {
			isAdmin = true
			break
		}
	}
	if !isAdmin {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden"})
	}

	groupIDStr := c.Param("id")
	groupID, err := uuid.Parse(groupIDStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid group id"})
	}
	var req fgaModifyGroupMemberReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid json"})
	}
	if err := c.Validate(&req); err != nil {
		return c.JSON(http.StatusBadRequest, validation.ErrorResponse(err))
	}
	userID, err := uuid.Parse(req.UserID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid user_id"})
	}

	if err := h.svc.AddGroupMember(c.Request().Context(), groupID, userID); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	if h.pub != nil {
		_ = h.pub.Publish(c.Request().Context(), evdomain.Event{
			Type:     "fga.group.member.add.success",
			TenantID: in.TenantID,
			UserID:   in.UserID,
			Meta:     map[string]string{"group_id": groupID.String(), "member_user_id": userID.String()},
			Time:     time.Now(),
		})
	}
	return c.NoContent(http.StatusNoContent)
}

// FGA Remove Group Member godoc
// @Summary      Remove user from group (admin-only)
// @Description  Removes a user from a group.
// @Tags         auth.admin
// @Security     BearerAuth
// @Accept       json
// @Param        id    path   string                  true  "Group ID (UUID)"
// @Param        body  body   fgaModifyGroupMemberReq true  "user_id"
// @Success      204
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      403  {object}  map[string]string
// @Router       /api/v1/auth/admin/fga/groups/{id}/members [delete]
func (h *Controller) fgaRemoveGroupMember(c echo.Context) error {
	tok := h.getToken(c)
	if tok == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
	}
	in, err := h.svc.Introspect(c.Request().Context(), tok)
	if err != nil || !in.Active {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid token"})
	}
	isAdmin := false
	for _, r := range in.Roles {
		if strings.EqualFold(r, "admin") {
			isAdmin = true
			break
		}
	}
	if !isAdmin {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden"})
	}

	groupIDStr := c.Param("id")
	groupID, err := uuid.Parse(groupIDStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid group id"})
	}
	var req fgaModifyGroupMemberReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid json"})
	}
	if err := c.Validate(&req); err != nil {
		return c.JSON(http.StatusBadRequest, validation.ErrorResponse(err))
	}
	userID, err := uuid.Parse(req.UserID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid user_id"})
	}

	if err := h.svc.RemoveGroupMember(c.Request().Context(), groupID, userID); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	if h.pub != nil {
		_ = h.pub.Publish(c.Request().Context(), evdomain.Event{
			Type:     "fga.group.member.remove.success",
			TenantID: in.TenantID,
			UserID:   in.UserID,
			Meta:     map[string]string{"group_id": groupID.String(), "member_user_id": userID.String()},
			Time:     time.Now(),
		})
	}
	return c.NoContent(http.StatusNoContent)
}

// fgaCreateACLTupleReq represents a direct ACL grant to a subject.
type fgaCreateACLTupleReq struct {
	TenantID      string  `json:"tenant_id" validate:"required,uuid4"`
	SubjectType   string  `json:"subject_type" validate:"required,oneof=user group"`
	SubjectID     string  `json:"subject_id" validate:"required,uuid4"`
	PermissionKey string  `json:"permission_key" validate:"required,min=1"`
	ObjectType    string  `json:"object_type" validate:"required,min=1"`
	ObjectID      *string `json:"object_id" validate:"omitempty"`
}

// FGA Create ACL Tuple godoc
// @Summary      Create ACL tuple (admin-only)
// @Description  Creates a direct permission grant (tuple).
// @Tags         auth.admin
// @Security     BearerAuth
// @Accept       json
// @Param        body  body  fgaCreateACLTupleReq  true  "tuple payload"
// @Success      201
// @Failure      400   {object}  map[string]string
// @Failure      401   {object}  map[string]string
// @Failure      403   {object}  map[string]string
// @Router       /api/v1/auth/admin/fga/acl/tuples [post]
func (h *Controller) fgaCreateACLTuple(c echo.Context) error {
	tok := h.getToken(c)
	if tok == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
	}
	in, err := h.svc.Introspect(c.Request().Context(), tok)
	if err != nil || !in.Active {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid token"})
	}
	isAdmin := false
	for _, r := range in.Roles {
		if strings.EqualFold(r, "admin") {
			isAdmin = true
			break
		}
	}
	if !isAdmin {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden"})
	}

	var req fgaCreateACLTupleReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid json"})
	}
	if err := c.Validate(&req); err != nil {
		return c.JSON(http.StatusBadRequest, validation.ErrorResponse(err))
	}
	tenantID, err := uuid.Parse(req.TenantID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid tenant_id"})
	}
	subjectID, err := uuid.Parse(req.SubjectID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid subject_id"})
	}

	if _, err := h.svc.CreateACLTuple(c.Request().Context(), tenantID, strings.ToLower(req.SubjectType), subjectID, req.PermissionKey, req.ObjectType, req.ObjectID, &in.UserID); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	if h.pub != nil {
		meta := map[string]string{
			"subject_type":   strings.ToLower(req.SubjectType),
			"subject_id":     subjectID.String(),
			"permission_key": req.PermissionKey,
			"object_type":    req.ObjectType,
		}
		if req.ObjectID != nil {
			meta["object_id"] = *req.ObjectID
		}
		_ = h.pub.Publish(c.Request().Context(), evdomain.Event{
			Type:     "fga.acl.tuple.create.success",
			TenantID: tenantID,
			UserID:   in.UserID,
			Meta:     meta,
			Time:     time.Now(),
		})
	}
	return c.NoContent(http.StatusCreated)
}

// fgaDeleteACLTupleReq identifies a tuple to delete.
type fgaDeleteACLTupleReq struct {
	TenantID      string  `json:"tenant_id" validate:"required,uuid4"`
	SubjectType   string  `json:"subject_type" validate:"required,oneof=user group"`
	SubjectID     string  `json:"subject_id" validate:"required,uuid4"`
	PermissionKey string  `json:"permission_key" validate:"required,min=1"`
	ObjectType    string  `json:"object_type" validate:"required,min=1"`
	ObjectID      *string `json:"object_id" validate:"omitempty"`
}

// FGA Delete ACL Tuple godoc
// @Summary      Delete ACL tuple (admin-only)
// @Description  Deletes a direct permission grant (tuple).
// @Tags         auth.admin
// @Security     BearerAuth
// @Accept       json
// @Param        body  body  fgaDeleteACLTupleReq  true  "tuple selector"
// @Success      204
// @Failure      400   {object}  map[string]string
// @Failure      401   {object}  map[string]string
// @Failure      403   {object}  map[string]string
// @Router       /api/v1/auth/admin/fga/acl/tuples [delete]
func (h *Controller) fgaDeleteACLTuple(c echo.Context) error {
	tok := h.getToken(c)
	if tok == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
	}
	in, err := h.svc.Introspect(c.Request().Context(), tok)
	if err != nil || !in.Active {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid token"})
	}
	isAdmin := false
	for _, r := range in.Roles {
		if strings.EqualFold(r, "admin") {
			isAdmin = true
			break
		}
	}
	if !isAdmin {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden"})
	}

	var req fgaDeleteACLTupleReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid json"})
	}
	if err := c.Validate(&req); err != nil {
		return c.JSON(http.StatusBadRequest, validation.ErrorResponse(err))
	}
	tenantID, err := uuid.Parse(req.TenantID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid tenant_id"})
	}
	subjectID, err := uuid.Parse(req.SubjectID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid subject_id"})
	}

	if err := h.svc.DeleteACLTuple(c.Request().Context(), tenantID, strings.ToLower(req.SubjectType), subjectID, req.PermissionKey, req.ObjectType, req.ObjectID); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	if h.pub != nil {
		meta := map[string]string{
			"subject_type":   strings.ToLower(req.SubjectType),
			"subject_id":     subjectID.String(),
			"permission_key": req.PermissionKey,
			"object_type":    req.ObjectType,
		}
		if req.ObjectID != nil {
			meta["object_id"] = *req.ObjectID
		}
		_ = h.pub.Publish(c.Request().Context(), evdomain.Event{
			Type:     "fga.acl.tuple.delete.success",
			TenantID: tenantID,
			UserID:   in.UserID,
			Meta:     meta,
			Time:     time.Now(),
		})
	}
	return c.NoContent(http.StatusNoContent)
}

// fgaAuthorizeReq is the decision request payload.
type fgaAuthorizeReq struct {
	TenantID    string `json:"tenant_id" validate:"required,uuid4"`
	SubjectType string `json:"subject_type" validate:"required,oneof=self user group"`
	// SubjectID is optional when subject_type=self; otherwise required.
	// When subject_type=self, the server derives the subject from the caller's token.
	SubjectID     string  `json:"subject_id" validate:"omitempty,uuid4"`
	PermissionKey string  `json:"permission_key" validate:"required,min=1"`
	ObjectType    string  `json:"object_type" validate:"required,min=1"`
	ObjectID      *string `json:"object_id" validate:"omitempty"`
}

// fgaAuthorizeResp is the decision response.
type fgaAuthorizeResp struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
}

// Authorize godoc
// @Summary      Authorization decision
// @Description  Returns allow/deny for a subject, action (permission_key) and object. Note: subject_id is optional when subject_type=self (it will be derived from the caller token).
// @Tags         auth
// @Security     BearerAuth
// @Accept       json
// @Produce      json
// @Param        body  body  fgaAuthorizeReq  true  "decision input (subject_id optional when subject_type=self)"
// @Success      200   {object}  fgaAuthorizeResp
// @Failure      400   {object}  map[string]string
// @Failure      401   {object}  map[string]string
// @Router       /api/v1/auth/authorize [post]
func (h *Controller) fgaAuthorize(c echo.Context) error {
	// JWT check (no admin required)
	tok := h.getToken(c)
	if tok == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
	}
	in, err := h.svc.Introspect(c.Request().Context(), tok)
	if err != nil || !in.Active {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid token"})
	}

	var req fgaAuthorizeReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid json"})
	}
	if err := c.Validate(&req); err != nil {
		return c.JSON(http.StatusBadRequest, validation.ErrorResponse(err))
	}

	// If subject_type == "self", replace subject_id with caller user id
	if strings.EqualFold(req.SubjectType, "self") {
		req.SubjectType = "user"
		req.SubjectID = in.UserID.String()
	}

	// For non-self requests, subject_id must be present (validation allows omitempty)
	if strings.TrimSpace(req.SubjectID) == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "subject_id required"})
	}

	// Explicitly require object_type even if validator is a no-op in tests
	if strings.TrimSpace(req.ObjectType) == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "object_type required"})
	}

	tenantID, err := uuid.Parse(req.TenantID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid tenant_id"})
	}
	subjectID, err := uuid.Parse(req.SubjectID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid subject_id"})
	}

	allowed, reason, err := h.svc.Authorize(c.Request().Context(), tenantID, strings.ToLower(req.SubjectType), subjectID, req.PermissionKey, req.ObjectType, req.ObjectID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	return c.JSON(http.StatusOK, fgaAuthorizeResp{Allowed: allowed, Reason: reason})
}
