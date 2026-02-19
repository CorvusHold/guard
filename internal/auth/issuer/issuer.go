package issuer

import (
	"net/url"
	"path"
	"strings"

	"github.com/google/uuid"

	"github.com/corvusHold/guard/internal/config"
)

const (
	ModePath      = "path"
	ModeSubdomain = "subdomain"
)

// ResolveTenantIssuer returns the tenant issuer URL.
//
// Path mode (default): {PUBLIC_BASE_URL}/t/{tenant_id}
// Subdomain mode:      {scheme}://{ISSUER_SUBDOMAIN_TEMPLATE(host with {tenant})}
func ResolveTenantIssuer(cfg config.Config, tenantID uuid.UUID) string {
	base := strings.TrimRight(strings.TrimSpace(cfg.PublicBaseURL), "/")
	if base == "" {
		return ""
	}

	mode := strings.ToLower(strings.TrimSpace(cfg.IssuerMode))
	if mode == "" {
		mode = ModePath
	}

	if mode == ModeSubdomain {
		u, err := url.Parse(base)
		if err == nil {
			hostTpl := strings.TrimSpace(cfg.IssuerSubdomainTemplate)
			if hostTpl != "" && strings.Contains(hostTpl, "{tenant}") {
				host := strings.ReplaceAll(hostTpl, "{tenant}", tenantID.String())
				u.Host = host
				u.Path = ""
				u.RawQuery = ""
				u.Fragment = ""
				return strings.TrimRight(u.String(), "/")
			}
		}
	}

	prefix := strings.TrimSpace(cfg.IssuerPathPrefix)
	if prefix == "" {
		prefix = "/t"
	}
	if !strings.HasPrefix(prefix, "/") {
		prefix = "/" + prefix
	}

	u, err := url.Parse(base)
	if err != nil {
		return base + prefix + "/" + tenantID.String()
	}
	u.Path = path.Join(u.Path, prefix, tenantID.String())
	u.RawQuery = ""
	u.Fragment = ""
	return strings.TrimRight(u.String(), "/")
}

// ResolveIssuer returns the issuer URL. If tenantID is nil it returns PUBLIC_BASE_URL.
func ResolveIssuer(cfg config.Config, tenantID *uuid.UUID) string {
	base := strings.TrimRight(strings.TrimSpace(cfg.PublicBaseURL), "/")
	if tenantID == nil || *tenantID == uuid.Nil {
		return base
	}
	return ResolveTenantIssuer(cfg, *tenantID)
}

// ResolveJWKSURI returns the JWKS URI for issuer discovery.
func ResolveJWKSURI(cfg config.Config, tenantID *uuid.UUID) string {
	iss := ResolveIssuer(cfg, tenantID)
	if iss == "" {
		return ""
	}
	return iss + "/.well-known/jwks.json"
}
