package controller

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/corvusHold/guard/internal/auth/domain"
	"github.com/corvusHold/guard/internal/platform/validation"
)

// --- Invitation DTOs ---

type inviteUserReq struct {
	TenantID string `json:"tenant_id" validate:"required,uuid4"`
	Email    string `json:"email" validate:"required,email"`
	Role     string `json:"role,omitempty"`
}

type inviteUserResp struct {
	ID        uuid.UUID `json:"id"`
	Email     string    `json:"email"`
	Role      string    `json:"role,omitempty"`
	Status    string    `json:"status"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
	InviteURL string    `json:"invite_url,omitempty"`
}

type acceptInvitationReq struct {
	Token     string `json:"token" validate:"required"`                        // Invitation token from the invite URL
	Password  string `json:"password" validate:"required,min=8" minLength:"8"` // Password for the new account (min 8 chars)
	FirstName string `json:"first_name"`                                       // Optional first name
	LastName  string `json:"last_name"`                                        // Optional last name
}

type invitationResp struct {
	ID         uuid.UUID  `json:"id"`
	TenantID   *uuid.UUID `json:"tenant_id,omitempty"`
	Email      string     `json:"email"`
	Role       string     `json:"role,omitempty"`
	Status     string     `json:"status"`
	ExpiresAt  time.Time  `json:"expires_at"`
	AcceptedAt *time.Time `json:"accepted_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

type invitationsListResp struct {
	Invitations []invitationResp `json:"invitations"`
}

type adminCreateUserReq struct {
	TenantID      string   `json:"tenant_id" validate:"required,uuid4"`              // Tenant ID (UUID)
	Email         string   `json:"email" validate:"required,email"`                  // User email address
	Password      string   `json:"password" validate:"required,min=8" minLength:"8"` // Password (min 8 chars)
	FirstName     string   `json:"first_name"`                                       // Optional first name
	LastName      string   `json:"last_name"`                                        // Optional last name
	Roles         []string `json:"roles,omitempty"`                                  // Optional roles to assign
	EmailVerified bool     `json:"email_verified,omitempty"`                         // Mark email as verified
	SendWelcome   bool     `json:"send_welcome,omitempty"`                           // Send welcome email to user
}

type adminCreateUserResp struct {
	ID            uuid.UUID `json:"id"`             // User ID
	Email         string    `json:"email"`          // User email
	FirstName     string    `json:"first_name"`     // First name
	LastName      string    `json:"last_name"`      // Last name
	Roles         []string  `json:"roles"`          // Assigned roles
	TenantID      string    `json:"tenant_id"`      // Tenant ID
	EmailVerified bool      `json:"email_verified"` // Whether email is verified
	IsActive      bool      `json:"is_active"`      // Whether user is active
	CreatedAt     time.Time `json:"created_at"`     // Creation timestamp
}

// --- Invitation Handlers ---

// InviteUser godoc
// @Summary      Invite a user to join a tenant (admin-only)
// @Description  Creates an invitation for a user to join a tenant. Sends an invitation email with a link to accept.
// @Tags         auth.admin
// @Security     BearerAuth
// @Accept       json
// @Produce      json
// @Param        body  body  inviteUserReq  true  "Invitation details"
// @Success      201   {object}  inviteUserResp
// @Failure      400   {object}  map[string]string
// @Failure      401   {object}  map[string]string
// @Failure      403   {object}  map[string]string
// @Failure      429   {object}  map[string]string
// @Router       /api/v1/auth/admin/invitations [post]
func (h *Controller) inviteUser(c echo.Context) error {
	tok := h.resolveAccessToken(c)
	if tok == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
	}
	in, err := h.svc.Introspect(c.Request().Context(), tok)
	if err != nil || !in.Active {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid token"})
	}

	// Require admin role
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

	var req inviteUserReq
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

	// Verify the admin is operating on their own tenant
	if tenantID != in.TenantID {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "cannot invite users to another tenant"})
	}

	// Create invitation
	inv, rawToken, err := h.svc.InviteUser(c.Request().Context(), domain.InviteUserInput{
		TenantID:  &tenantID,
		Email:     req.Email,
		Role:      req.Role,
		InvitedBy: in.UserID,
	})
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	// Build invite URL
	baseURL := h.cfg.PublicBaseURL
	if baseURL == "" {
		baseURL = "http://localhost:8080"
	}
	inviteURL := baseURL + "/accept-invitation?token=" + url.QueryEscape(rawToken)

	return c.JSON(http.StatusCreated, inviteUserResp{
		ID:        inv.ID,
		Email:     inv.Email,
		Role:      inv.Role,
		Status:    inv.Status,
		ExpiresAt: inv.ExpiresAt,
		CreatedAt: inv.CreatedAt,
		InviteURL: inviteURL,
	})
}

// ListInvitations godoc
// @Summary      List invitations for a tenant (admin-only)
// @Description  Returns all invitations for the specified tenant.
// @Tags         auth.admin
// @Security     BearerAuth
// @Produce      json
// @Param        tenant_id  query  string  true  "Tenant ID (UUID)"
// @Param        status     query  string  false "Filter by status (pending, accepted, expired, revoked)"
// @Success      200  {object}  invitationsListResp
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      403  {object}  map[string]string
// @Router       /api/v1/auth/admin/invitations [get]
func (h *Controller) listInvitations(c echo.Context) error {
	tok := h.resolveAccessToken(c)
	if tok == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
	}
	in, err := h.svc.Introspect(c.Request().Context(), tok)
	if err != nil || !in.Active {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid token"})
	}

	// Require admin role
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

	tenantIDStr := c.QueryParam("tenant_id")
	if tenantIDStr == "" {
		tenantIDStr = in.TenantID.String()
	}
	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid tenant_id"})
	}

	// Verify the admin is operating on their own tenant
	if tenantID != in.TenantID {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "cannot list invitations for another tenant"})
	}

	status := c.QueryParam("status")
	var invitations []domain.Invitation
	switch status {
	case "":
		invitations, err = h.svc.ListInvitations(c.Request().Context(), tenantID)
	case "pending":
		invitations, err = h.svc.ListPendingInvitations(c.Request().Context(), tenantID)
	case "accepted", "expired", "revoked":
		var all []domain.Invitation
		all, err = h.svc.ListInvitations(c.Request().Context(), tenantID)
		if err == nil {
			for _, inv := range all {
				if inv.Status == status {
					invitations = append(invitations, inv)
				}
			}
		}
	default:
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "unsupported status filter; use pending, accepted, expired, or revoked"})
	}
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	resp := make([]invitationResp, 0, len(invitations))
	for _, inv := range invitations {
		resp = append(resp, invitationResp{
			ID:         inv.ID,
			TenantID:   inv.TenantID,
			Email:      inv.Email,
			Role:       inv.Role,
			Status:     inv.Status,
			ExpiresAt:  inv.ExpiresAt,
			AcceptedAt: inv.AcceptedAt,
			CreatedAt:  inv.CreatedAt,
		})
	}

	return c.JSON(http.StatusOK, invitationsListResp{Invitations: resp})
}

// RevokeInvitation godoc
// @Summary      Revoke an invitation (admin-only)
// @Description  Revokes a pending invitation so it can no longer be accepted.
// @Tags         auth.admin
// @Security     BearerAuth
// @Accept       json
// @Produce      json
// @Param        id  path  string  true  "Invitation ID (UUID)"
// @Success      200  {object}  map[string]string
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      403  {object}  map[string]string
// @Router       /api/v1/auth/admin/invitations/{id}/revoke [post]
func (h *Controller) revokeInvitation(c echo.Context) error {
	tok := h.resolveAccessToken(c)
	if tok == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
	}
	in, err := h.svc.Introspect(c.Request().Context(), tok)
	if err != nil || !in.Active {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid token"})
	}

	// Require admin role
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

	invitationID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid invitation id"})
	}

	if err := h.svc.RevokeInvitation(c.Request().Context(), invitationID, in.TenantID); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, map[string]string{"message": "invitation revoked"})
}

// DeleteInvitation godoc
// @Summary      Delete an invitation (admin-only)
// @Description  Permanently deletes an invitation.
// @Tags         auth.admin
// @Security     BearerAuth
// @Produce      json
// @Param        id  path  string  true  "Invitation ID (UUID)"
// @Success      200  {object}  map[string]string
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      403  {object}  map[string]string
// @Router       /api/v1/auth/admin/invitations/{id} [delete]
func (h *Controller) deleteInvitation(c echo.Context) error {
	tok := h.resolveAccessToken(c)
	if tok == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
	}
	in, err := h.svc.Introspect(c.Request().Context(), tok)
	if err != nil || !in.Active {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid token"})
	}

	// Require admin role
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

	invitationID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid invitation id"})
	}

	if err := h.svc.DeleteInvitation(c.Request().Context(), invitationID, in.TenantID); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, map[string]string{"message": "invitation deleted"})
}

// AcceptInvitation godoc
// @Summary      Accept an invitation and create account
// @Description  Accepts an invitation using the token and creates a new user account. Returns access tokens.
// @Tags         auth.invitation
// @Accept       json
// @Produce      json
// @Param        body  body  acceptInvitationReq  true  "Invitation acceptance details"
// @Success      201   {object}  authExchangeResp
// @Failure      400   {object}  map[string]string
// @Failure      429   {object}  map[string]string
// @Router       /api/v1/auth/invitations/accept [post]
func (h *Controller) acceptInvitation(c echo.Context) error {
	authMode := detectAuthMode(c, h.cfg.DefaultAuthMode)
	var req acceptInvitationReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid json"})
	}
	if err := c.Validate(&req); err != nil {
		return c.JSON(http.StatusBadRequest, validation.ErrorResponse(err))
	}

	tok, err := h.svc.AcceptInvitation(c.Request().Context(), domain.AcceptInvitationInput{
		Token:     req.Token,
		Password:  req.Password,
		FirstName: req.FirstName,
		LastName:  req.LastName,
	})
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	return respondWithTokens(c, h.cfg, authMode, http.StatusCreated, tok.AccessToken, tok.RefreshToken)
}

// GetInvitation godoc
// @Summary      Get invitation details by token
// @Description  Returns invitation details for a given token. Used to display invitation info before accepting.
// @Tags         auth.invitation
// @Produce      json
// @Param        token  query  string  true  "Invitation token"
// @Success      200  {object}  invitationResp
// @Failure      400  {object}  map[string]string
// @Router       /api/v1/auth/invitations [get]
func (h *Controller) getInvitation(c echo.Context) error {
	token := c.QueryParam("token")
	if token == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "token is required"})
	}

	inv, err := h.svc.GetInvitationByToken(c.Request().Context(), token)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid or expired invitation"})
	}

	return c.JSON(http.StatusOK, invitationResp{
		ID:         inv.ID,
		TenantID:   inv.TenantID,
		Email:      inv.Email,
		Role:       inv.Role,
		Status:     inv.Status,
		ExpiresAt:  inv.ExpiresAt,
		AcceptedAt: inv.AcceptedAt,
		CreatedAt:  inv.CreatedAt,
	})
}

// AdminCreateUser godoc
// @Summary      Create a user directly in a tenant (admin-only)
// @Description  Creates a new user account directly in a tenant without going through the invitation flow.
// @Tags         auth.admin
// @Security     BearerAuth
// @Accept       json
// @Produce      json
// @Param        body  body  adminCreateUserReq  true  "User details"
// @Success      201   {object}  adminCreateUserResp
// @Failure      400   {object}  map[string]string
// @Failure      401   {object}  map[string]string
// @Failure      403   {object}  map[string]string
// @Failure      429   {object}  map[string]string
// @Router       /api/v1/auth/admin/users [post]
func (h *Controller) adminCreateUser(c echo.Context) error {
	tok := h.resolveAccessToken(c)
	if tok == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
	}
	in, err := h.svc.Introspect(c.Request().Context(), tok)
	if err != nil || !in.Active {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid token"})
	}

	// Require admin role
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

	var req adminCreateUserReq
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

	// Verify the admin is operating on their own tenant
	if tenantID != in.TenantID {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "cannot create users in another tenant"})
	}

	user, err := h.svc.AdminCreateUser(c.Request().Context(), domain.AdminCreateUserInput{
		TenantID:      tenantID,
		Email:         req.Email,
		Password:      req.Password,
		FirstName:     req.FirstName,
		LastName:      req.LastName,
		Roles:         req.Roles,
		EmailVerified: req.EmailVerified,
		SendWelcome:   req.SendWelcome,
	})
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusCreated, adminCreateUserResp{
		ID:            user.ID,
		Email:         req.Email, // Email comes from request since it's not stored in User
		FirstName:     user.FirstName,
		LastName:      user.LastName,
		Roles:         user.Roles,
		TenantID:      req.TenantID,
		EmailVerified: user.EmailVerified,
		IsActive:      user.IsActive,
		CreatedAt:     user.CreatedAt,
	})
}
