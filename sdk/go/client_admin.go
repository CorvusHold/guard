package guard

import (
	"context"
	"errors"
	"net/http"
)

// AdminUser represents a user in the admin context with roles and activity status.
type AdminUser struct {
	ID            string
	Email         string
	EmailVerified bool
	IsActive      bool
	FirstName     string
	LastName      string
	Roles         []string
	CreatedAt     string
	UpdatedAt     string
	LastLoginAt   *string
}

// UpdateUserNamesRequest contains the fields that can be updated for a user.
type UpdateUserNamesRequest struct {
	FirstName *string
	LastName  *string
}

// ListUsers retrieves all users for a tenant. Requires admin role.
func (c *GuardClient) ListUsers(ctx context.Context, tenantID string) ([]AdminUser, error) {
	if tenantID == "" {
		tenantID = c.tenantID
	}
	if tenantID == "" {
		return nil, errors.New("tenant ID required")
	}

	params := &GetV1AuthAdminUsersParams{TenantId: tenantID}
	resp, err := c.inner.GetV1AuthAdminUsersWithResponse(ctx, params)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, errors.New(resp.Status())
	}

	var users []AdminUser
	if resp.JSON200.Users != nil {
		for _, u := range *resp.JSON200.Users {
			user := AdminUser{
				ID:            u.Id,
				Email:         u.Email,
				EmailVerified: u.EmailVerified,
				IsActive:      u.IsActive,
			}
			if u.FirstName != nil {
				user.FirstName = *u.FirstName
			}
			if u.LastName != nil {
				user.LastName = *u.LastName
			}
			if u.Roles != nil {
				user.Roles = *u.Roles
			}
			if u.CreatedAt != nil {
				user.CreatedAt = *u.CreatedAt
			}
			if u.UpdatedAt != nil {
				user.UpdatedAt = *u.UpdatedAt
			}
			if u.LastLoginAt != nil {
				user.LastLoginAt = u.LastLoginAt
			}
			users = append(users, user)
		}
	}

	return users, nil
}

// UpdateUserNames updates a user's first and last name. Requires admin role.
func (c *GuardClient) UpdateUserNames(ctx context.Context, userID string, req UpdateUserNamesRequest) error {
	body := ControllerUpdateUserReq{
		FirstName: req.FirstName,
		LastName:  req.LastName,
	}
	resp, err := c.inner.PatchV1AuthAdminUsersIdWithResponse(ctx, userID, body)
	if err != nil {
		return err
	}
	if resp.HTTPResponse == nil || (resp.StatusCode() != http.StatusOK && resp.StatusCode() != http.StatusNoContent) {
		return errors.New(resp.Status())
	}
	return nil
}

// BlockUser blocks a user, preventing them from logging in. Requires admin role.
func (c *GuardClient) BlockUser(ctx context.Context, userID string) error {
	resp, err := c.inner.PostV1AuthAdminUsersIdBlockWithResponse(ctx, userID)
	if err != nil {
		return err
	}
	if resp.HTTPResponse == nil || (resp.StatusCode() != http.StatusOK && resp.StatusCode() != http.StatusNoContent) {
		return errors.New(resp.Status())
	}
	return nil
}

// UnblockUser unblocks a previously blocked user. Requires admin role.
func (c *GuardClient) UnblockUser(ctx context.Context, userID string) error {
	resp, err := c.inner.PostV1AuthAdminUsersIdUnblockWithResponse(ctx, userID)
	if err != nil {
		return err
	}
	if resp.HTTPResponse == nil || (resp.StatusCode() != http.StatusOK && resp.StatusCode() != http.StatusNoContent) {
		return errors.New(resp.Status())
	}
	return nil
}
