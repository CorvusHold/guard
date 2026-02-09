package controller

import (
	"encoding/base64"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog/log"

	authsvc "github.com/corvusHold/guard/internal/auth/service"
)

// registerSelfServiceRoutes registers user self-service endpoints.
func (h *Controller) registerSelfServiceRoutes(g *echo.Group) {
	self := g.Group("/self")
	self.GET("/profile", h.selfProfile)
	self.PUT("/profile", h.selfUpdateProfile)
	self.GET("/sessions", h.selfListSessions)
	self.DELETE("/sessions/:id", h.selfRevokeSession)
	self.GET("/mfa", h.selfMFAStatus)
	self.GET("/passkeys", h.selfListPasskeys)
	self.POST("/passkeys", h.selfRegisterPasskey)
	self.DELETE("/passkeys/:id", h.selfDeletePasskey)
}

// @Summary      Get own profile
// @Description  Returns the authenticated user's profile
// @Tags         Self-Service
// @Produce      json
// @Success      200  {object}  map[string]interface{}
// @Router       /api/v1/auth/self/profile [get]
func (h *Controller) selfProfile(c echo.Context) error {
	in, err := h.requireAuth(c)
	if err != nil {
		return nil
	}
	profile, err := h.svc.Me(c.Request().Context(), in.UserID, in.TenantID)
	if err != nil {
		log.Error().Err(err).Str("func", "selfProfile").Str("user_id", in.UserID.String()).Str("tenant_id", in.TenantID.String()).Msg("failed to load profile")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "internal server error"})
	}
	return c.JSON(http.StatusOK, profile)
}

type updateProfileRequest struct {
	FirstName *string `json:"first_name"`
	LastName  *string `json:"last_name"`
}

// @Summary      Update own profile
// @Description  Updates the authenticated user's name
// @Tags         Self-Service
// @Accept       json
// @Produce      json
// @Param        body  body  updateProfileRequest  true  "Profile updates"
// @Success      200  {object}  map[string]interface{}
// @Router       /api/v1/auth/self/profile [put]
func (h *Controller) selfUpdateProfile(c echo.Context) error {
	in, err := h.requireAuth(c)
	if err != nil {
		return nil
	}
	var req updateProfileRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid json"})
	}
	if req.FirstName == nil && req.LastName == nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "nothing to update"})
	}
	// Fetch current profile to preserve omitted fields
	prof, err := h.svc.Me(c.Request().Context(), in.UserID, in.TenantID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to load profile"})
	}
	firstName := prof.FirstName
	lastName := prof.LastName
	if req.FirstName != nil {
		firstName = *req.FirstName
	}
	if req.LastName != nil {
		lastName = *req.LastName
	}
	err = h.svc.UpdateUserNames(c.Request().Context(), in.UserID, firstName, lastName)
	if err != nil {
		log.Error().Err(err).Str("func", "selfUpdateProfile").Str("user_id", in.UserID.String()).Msg("failed to update profile")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "internal server error"})
	}
	return c.JSON(http.StatusOK, map[string]string{"status": "updated"})
}

// @Summary      List own sessions
// @Description  Returns the authenticated user's active sessions
// @Tags         Self-Service
// @Produce      json
// @Success      200  {object}  map[string]interface{}
// @Router       /api/v1/auth/self/sessions [get]
func (h *Controller) selfListSessions(c echo.Context) error {
	in, err := h.requireAuth(c)
	if err != nil {
		return nil
	}
	sessions, err := h.svc.ListUserSessions(c.Request().Context(), in.UserID, in.TenantID)
	if err != nil {
		log.Error().Err(err).Str("func", "selfListSessions").Str("user_id", in.UserID.String()).Str("tenant_id", in.TenantID.String()).Msg("failed to list sessions")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "internal server error"})
	}
	return c.JSON(http.StatusOK, map[string]interface{}{"sessions": sessions})
}

// @Summary      Revoke own session
// @Description  Revokes one of the authenticated user's sessions
// @Tags         Self-Service
// @Param        id  path  string  true  "Session (refresh token) ID"
// @Success      204
// @Router       /api/v1/auth/self/sessions/{id} [delete]
func (h *Controller) selfRevokeSession(c echo.Context) error {
	in, err := h.requireAuth(c)
	if err != nil {
		return nil
	}
	sessionID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid session id"})
	}
	// Revoke via ownership-verified service method (ensures session belongs to this user+tenant)
	if err := h.svc.RevokeSession(c.Request().Context(), in.UserID, in.TenantID, sessionID); err != nil {
		log.Error().Err(err).Str("func", "selfRevokeSession").Str("user_id", in.UserID.String()).Str("session_id", sessionID.String()).Msg("failed to revoke session")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "internal server error"})
	}
	return c.NoContent(http.StatusNoContent)
}

// @Summary      MFA status
// @Description  Returns the authenticated user's MFA enrollment status
// @Tags         Self-Service
// @Produce      json
// @Success      200  {object}  map[string]interface{}
// @Router       /api/v1/auth/self/mfa [get]
func (h *Controller) selfMFAStatus(c echo.Context) error {
	in, err := h.requireAuth(c)
	if err != nil {
		return nil
	}
	enrolled, err := h.svc.IsMFAEnrolled(c.Request().Context(), in.UserID, in.TenantID)
	if err != nil {
		log.Error().Err(err).Str("func", "selfMFAStatus").Str("user_id", in.UserID.String()).Msg("failed to check MFA status")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "internal server error"})
	}
	return c.JSON(http.StatusOK, map[string]interface{}{"mfa_enrolled": enrolled})
}

// @Summary      List passkeys
// @Description  Returns the authenticated user's registered passkeys
// @Tags         Self-Service
// @Produce      json
// @Success      200  {object}  map[string]interface{}
// @Router       /api/v1/auth/self/passkeys [get]
func (h *Controller) selfListPasskeys(c echo.Context) error {
	in, err := h.requireAuth(c)
	if err != nil {
		return nil
	}
	if h.webauthn == nil {
		return c.JSON(http.StatusOK, map[string]interface{}{"passkeys": []interface{}{}})
	}
	creds, err := h.webauthn.ListCredentials(c.Request().Context(), in.UserID, in.TenantID)
	if err != nil {
		log.Error().Err(err).Str("func", "selfListPasskeys").Str("user_id", in.UserID.String()).Msg("failed to list passkeys")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "internal server error"})
	}
	out := make([]passkeyResponse, 0, len(creds))
	for _, cr := range creds {
		out = append(out, passkeyResponse{
			ID:           cr.ID.String(),
			FriendlyName: cr.FriendlyName,
			CreatedAt:    cr.CreatedAt,
			LastUsedAt:   cr.LastUsedAt,
		})
	}
	return c.JSON(http.StatusOK, map[string]interface{}{"passkeys": out})
}

type passkeyResponse struct {
	ID           string     `json:"id"`
	FriendlyName string     `json:"friendly_name"`
	CreatedAt    time.Time  `json:"created_at"`
	LastUsedAt   *time.Time `json:"last_used_at,omitempty"`
}

type registerPasskeyRequest struct {
	CredentialID    string   `json:"credential_id" validate:"required"`
	PublicKey       string   `json:"public_key" validate:"required"`
	AttestationType string   `json:"attestation_type"`
	AAGUID          string   `json:"aaguid"`
	Transports      []string `json:"transports"`
	FriendlyName    string   `json:"friendly_name"`
}

// @Summary      Register passkey
// @Description  Stores a new WebAuthn/passkey credential for the authenticated user
// @Tags         Self-Service
// @Accept       json
// @Produce      json
// @Param        body  body  registerPasskeyRequest  true  "Passkey credential data"
// @Success      201  {object}  passkeyResponse
// @Router       /api/v1/auth/self/passkeys [post]
func (h *Controller) selfRegisterPasskey(c echo.Context) error {
	in, err := h.requireAuth(c)
	if err != nil {
		return nil
	}
	if h.webauthn == nil {
		return c.JSON(http.StatusServiceUnavailable, map[string]string{"error": "passkeys not configured"})
	}
	var req registerPasskeyRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid json"})
	}
	if err := c.Validate(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "credential_id and public_key are required"})
	}
	credID, err := base64.RawURLEncoding.DecodeString(req.CredentialID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid credential_id encoding"})
	}
	pubKey, err := base64.RawURLEncoding.DecodeString(req.PublicKey)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid public_key encoding"})
	}
	var aaguid []byte
	if req.AAGUID != "" {
		var aaguidErr error
		aaguid, aaguidErr = base64.RawURLEncoding.DecodeString(req.AAGUID)
		if aaguidErr != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid aaguid encoding"})
		}
	}
	cred := authsvc.WebAuthnCredential{
		ID:              uuid.New(),
		UserID:          in.UserID,
		TenantID:        in.TenantID,
		CredentialID:    credID,
		PublicKey:       pubKey,
		AttestationType: req.AttestationType,
		AAGUID:          aaguid,
		SignCount:       0,
		Transports:      req.Transports,
		FriendlyName:    req.FriendlyName,
		CreatedAt:       time.Now(),
	}
	if err := h.webauthn.StoreCredential(c.Request().Context(), cred); err != nil {
		log.Error().Err(err).Str("func", "selfRegisterPasskey").Str("user_id", in.UserID.String()).Msg("failed to store passkey")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "internal server error"})
	}
	return c.JSON(http.StatusCreated, passkeyResponse{
		ID:           cred.ID.String(),
		FriendlyName: cred.FriendlyName,
		CreatedAt:    cred.CreatedAt,
	})
}

// @Summary      Delete passkey
// @Description  Deletes one of the authenticated user's passkeys
// @Tags         Self-Service
// @Param        id  path  string  true  "Passkey ID"
// @Success      204
// @Router       /api/v1/auth/self/passkeys/{id} [delete]
func (h *Controller) selfDeletePasskey(c echo.Context) error {
	in, err := h.requireAuth(c)
	if err != nil {
		return nil
	}
	if h.webauthn == nil {
		return c.JSON(http.StatusServiceUnavailable, map[string]string{"error": "passkeys not configured"})
	}
	passkeyID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid passkey id"})
	}
	if err := h.webauthn.DeleteCredential(c.Request().Context(), passkeyID, in.UserID, in.TenantID); err != nil {
		log.Error().Err(err).Str("func", "selfDeletePasskey").Str("user_id", in.UserID.String()).Str("passkey_id", passkeyID.String()).Msg("failed to delete passkey")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "internal server error"})
	}
	return c.NoContent(http.StatusNoContent)
}
