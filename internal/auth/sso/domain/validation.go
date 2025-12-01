package domain

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// ValidateProviderSlug validates a provider slug.
func ValidateProviderSlug(slug string) error {
	if slug == "" {
		return errors.New("slug cannot be empty")
	}
	// Only allow alphanumeric and hyphens
	matched, _ := regexp.MatchString("^[a-z0-9-]+$", slug)
	if !matched {
		return errors.New("slug must contain only lowercase letters, numbers, and hyphens")
	}
	if len(slug) > 50 {
		return errors.New("slug must be 50 characters or less")
	}
	return nil
}

// ValidateURL validates a URL.
func ValidateURL(urlStr string) error {
	if urlStr == "" {
		return errors.New("URL cannot be empty")
	}
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return errors.New("URL must use http or https scheme")
	}
	return nil
}

// ValidateEmail validates an email address.
func ValidateEmail(email string) error {
	// Simple email validation
	if !strings.Contains(email, "@") {
		return errors.New("invalid email format")
	}
	if len(email) > 254 {
		return errors.New("email too long")
	}
	return nil
}

// ExtractEmailDomain extracts the domain from an email address.
func ExtractEmailDomain(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return ""
	}
	return strings.ToLower(parts[1])
}

// IsEmailDomainAllowed checks if an email domain is in the allowed list.
// If allowedDomains is empty, all domains are allowed.
func IsEmailDomainAllowed(email string, allowedDomains []string) bool {
	if len(allowedDomains) == 0 {
		return true
	}

	domain := ExtractEmailDomain(email)
	if domain == "" {
		return false
	}

	for _, allowed := range allowedDomains {
		if strings.EqualFold(domain, allowed) {
			return true
		}
	}

	return false
}
