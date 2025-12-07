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

// ErrIdpInitiatedNotAllowed is returned when IdP-initiated SSO is attempted but not allowed.
type ErrIdpInitiatedNotAllowed struct {
	ProviderSlug string
}

func (e ErrIdpInitiatedNotAllowed) Error() string {
	return fmt.Sprintf("IdP-initiated SSO is not allowed for provider '%s'. Please initiate login from the application.", e.ProviderSlug)
}

// ErrConfigValidation is returned when provider configuration is invalid.
type ErrConfigValidation struct {
	Field   string
	Message string
}

func (e ErrConfigValidation) Error() string {
	return fmt.Sprintf("configuration validation failed for '%s': %s", e.Field, e.Message)
}

// ErrAccountExists is returned when SSO login matches an existing account but linking is disabled.
type ErrAccountExists struct {
	Email string
}

func (e ErrAccountExists) Error() string {
	return fmt.Sprintf("an account with email '%s' already exists. Please sign in with your password or contact support to link your accounts.", e.Email)
}

// ErrEmailNotVerified is returned when account linking requires verified email but it's not.
type ErrEmailNotVerified struct {
	Email  string
	Reason string // "idp" for IdP email not verified, "account" for existing account email not verified
}

func (e ErrEmailNotVerified) Error() string {
	switch e.Reason {
	case "idp":
		return "your identity provider has not verified your email address. Please verify your email with your IdP and try again."
	case "account":
		return fmt.Sprintf("please verify your existing account's email address (%s) before linking with SSO.", e.Email)
	default:
		return "email verification required for account linking"
	}
}
