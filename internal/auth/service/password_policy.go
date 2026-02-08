package service

import (
	"context"
	"fmt"
	"strings"
	"unicode"

	"github.com/google/uuid"

	sdomain "github.com/corvusHold/guard/internal/settings/domain"
)

// PasswordPolicy defines configurable password strength rules.
type PasswordPolicy struct {
	MinLength        int
	MaxLength        int
	RequireUppercase bool
	RequireLowercase bool
	RequireDigit     bool
	RequireSpecial   bool
}

// DefaultPasswordPolicy returns the baseline policy used when no tenant overrides exist.
func DefaultPasswordPolicy() PasswordPolicy {
	return PasswordPolicy{
		MinLength: 8,
		MaxLength: 128,
	}
}

// loadPasswordPolicy resolves the effective password policy for a tenant,
// falling back to defaults for any unset keys.
func (s *Service) loadPasswordPolicy(ctx context.Context, tenantID uuid.UUID) PasswordPolicy {
	p := DefaultPasswordPolicy()
	tid := &tenantID

	if v, err := s.settings.GetInt(ctx, sdomain.KeyPasswordMinLength, tid, p.MinLength); err == nil {
		p.MinLength = v
	}
	if v, err := s.settings.GetString(ctx, sdomain.KeyPasswordRequireUppercase, tid, "false"); err == nil {
		p.RequireUppercase = v == "true"
	}
	if v, err := s.settings.GetString(ctx, sdomain.KeyPasswordRequireLowercase, tid, "false"); err == nil {
		p.RequireLowercase = v == "true"
	}
	if v, err := s.settings.GetString(ctx, sdomain.KeyPasswordRequireDigit, tid, "false"); err == nil {
		p.RequireDigit = v == "true"
	}
	if v, err := s.settings.GetString(ctx, sdomain.KeyPasswordRequireSpecial, tid, "false"); err == nil {
		p.RequireSpecial = v == "true"
	}
	return p
}

// ValidatePassword checks a password against the given policy and returns
// a list of human-readable violations. An empty slice means the password is valid.
func ValidatePassword(password string, policy PasswordPolicy) []string {
	var violations []string

	if len(password) < policy.MinLength {
		violations = append(violations, fmt.Sprintf("password must be at least %d characters", policy.MinLength))
	}
	if policy.MaxLength > 0 && len(password) > policy.MaxLength {
		violations = append(violations, fmt.Sprintf("password must be at most %d characters", policy.MaxLength))
	}

	if policy.RequireUppercase {
		if !strings.ContainsFunc(password, unicode.IsUpper) {
			violations = append(violations, "password must contain at least one uppercase letter")
		}
	}
	if policy.RequireLowercase {
		if !strings.ContainsFunc(password, unicode.IsLower) {
			violations = append(violations, "password must contain at least one lowercase letter")
		}
	}
	if policy.RequireDigit {
		if !strings.ContainsFunc(password, unicode.IsDigit) {
			violations = append(violations, "password must contain at least one digit")
		}
	}
	if policy.RequireSpecial {
		hasSpecial := strings.ContainsFunc(password, func(r rune) bool {
			return !unicode.IsLetter(r) && !unicode.IsDigit(r)
		})
		if !hasSpecial {
			violations = append(violations, "password must contain at least one special character")
		}
	}

	return violations
}
