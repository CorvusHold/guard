package middleware

import (
	"errors"
	"fmt"

	guard "github.com/corvusHold/guard/sdk/go"
	"github.com/labstack/echo/v4"
)

// GetUserID extracts the user ID from the Echo context.
// Returns empty string and error if not found or not authenticated.
func GetUserID(c echo.Context) (string, error) {
	val := c.Get(ContextKeyUserID)
	if val == nil {
		return "", errors.New("user_id not found in context (did you apply RequireAuth middleware?)")
	}
	userID, ok := val.(string)
	if !ok {
		return "", fmt.Errorf("user_id has unexpected type: %T", val)
	}
	return userID, nil
}

// GetTenantID extracts the tenant ID from the Echo context.
// Returns empty string and error if not found or not authenticated.
func GetTenantID(c echo.Context) (string, error) {
	val := c.Get(ContextKeyTenantID)
	if val == nil {
		return "", errors.New("tenant_id not found in context (did you apply RequireAuth middleware?)")
	}
	tenantID, ok := val.(string)
	if !ok {
		return "", fmt.Errorf("tenant_id has unexpected type: %T", val)
	}
	return tenantID, nil
}

// GetEmail extracts the email from the Echo context.
// Returns empty string and error if not found or not authenticated.
func GetEmail(c echo.Context) (string, error) {
	val := c.Get(ContextKeyEmail)
	if val == nil {
		return "", errors.New("email not found in context (did you apply RequireAuth middleware?)")
	}
	email, ok := val.(string)
	if !ok {
		return "", fmt.Errorf("email has unexpected type: %T", val)
	}
	return email, nil
}

// GetRoles extracts the user roles from the Echo context.
// Returns empty slice and error if not found or not authenticated.
func GetRoles(c echo.Context) ([]string, error) {
	val := c.Get(ContextKeyRoles)
	if val == nil {
		return nil, errors.New("roles not found in context (did you apply RequireAuth middleware?)")
	}
	roles, ok := val.([]string)
	if !ok {
		return nil, fmt.Errorf("roles has unexpected type: %T", val)
	}
	return roles, nil
}

// GetIntrospection extracts the full introspection response from the Echo context.
// Returns nil and error if not found or not authenticated.
func GetIntrospection(c echo.Context) (*guard.DomainIntrospection, error) {
	val := c.Get(ContextKeyIntrospection)
	if val == nil {
		return nil, errors.New("introspection not found in context (did you apply RequireAuth middleware?)")
	}
	introspection, ok := val.(*guard.DomainIntrospection)
	if !ok {
		return nil, fmt.Errorf("introspection has unexpected type: %T", val)
	}
	return introspection, nil
}
