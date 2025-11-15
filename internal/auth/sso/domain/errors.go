package domain

import "fmt"

// ErrProviderDisabled is returned when attempting to use a disabled provider.
type ErrProviderDisabled struct {
	ProviderSlug string
}

func (e ErrProviderDisabled) Error() string {
	return fmt.Sprintf("SSO provider '%s' is currently disabled", e.ProviderSlug)
}

// ErrProviderNotFound is returned when a provider doesn't exist.
type ErrProviderNotFound struct {
	ProviderSlug string
}

func (e ErrProviderNotFound) Error() string {
	return fmt.Sprintf("SSO provider '%s' not found", e.ProviderSlug)
}

// ErrDomainNotAllowed is returned when user's email domain is restricted.
type ErrDomainNotAllowed struct {
	Email          string
	Domain         string
	AllowedDomains []string
}

func (e ErrDomainNotAllowed) Error() string {
	return fmt.Sprintf("email domain '%s' is not allowed for this SSO provider", e.Domain)
}

// ErrSignupDisabled is returned when signup is disabled and user doesn't exist.
type ErrSignupDisabled struct {
	Email string
}

func (e ErrSignupDisabled) Error() string {
	return "account signup is disabled for this SSO provider"
}

// ErrInvalidState is returned for invalid/expired state tokens.
type ErrInvalidState struct{}

func (e ErrInvalidState) Error() string {
	return "invalid or expired SSO state token"
}

// ErrConfigValidation is returned when provider configuration is invalid.
type ErrConfigValidation struct {
	Field   string
	Message string
}

func (e ErrConfigValidation) Error() string {
	return fmt.Sprintf("configuration validation failed for '%s': %s", e.Field, e.Message)
}
