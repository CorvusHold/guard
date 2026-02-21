package guard

import "testing"

func TestMapSSOProviderFromResponse_MapsOIDCAndSAMLFields(t *testing.T) {
	provider := mapSSOProviderFromResponse(map[string]interface{}{
		"id":                    "p1",
		"tenant_id":             "t1",
		"name":                  "Provider",
		"slug":                  "slug",
		"provider_type":         "oidc",
		"enabled":               true,
		"allow_signup":          true,
		"trust_email_verified":  true,
		"domains":               []interface{}{"example.com"},
		"attribute_mapping":     map[string]interface{}{"email": "mail"},
		"issuer":                "https://issuer",
		"authorization_endpoint": "https://issuer/auth",
		"token_endpoint":        "https://issuer/token",
		"userinfo_endpoint":     "https://issuer/me",
		"jwks_uri":              "https://issuer/jwks",
		"client_id":             "cid",
		"client_secret":         "sec",
		"scopes":                []interface{}{"openid", "email"},
		"response_type":         "code",
		"response_mode":         "query",
		"entity_id":             "entity",
		"acs_url":               "https://sp/acs",
		"slo_url":               "https://sp/slo",
		"idp_metadata_url":      "https://idp/meta",
		"idp_metadata_xml":      "<xml/>",
		"idp_entity_id":         "idp-entity",
		"idp_sso_url":           "https://idp/sso",
		"idp_slo_url":           "https://idp/slo",
		"idp_certificate":       "cert",
		"sp_certificate":        "spcert",
		"sp_private_key":        "spkey",
		"want_assertions_signed": true,
		"want_response_signed":   true,
		"sign_requests":          true,
		"force_authn":            true,
		"created_at":             "2025-01-01T00:00:00Z",
		"updated_at":             "2025-01-02T00:00:00Z",
	})

	if provider.ID != "p1" || provider.TenantID != "t1" || provider.Name != "Provider" || provider.Slug != "slug" {
		t.Fatalf("basic mapping failed: %+v", provider)
	}
	if provider.Issuer == nil || *provider.Issuer != "https://issuer" || provider.ClientID == nil || *provider.ClientID != "cid" {
		t.Fatalf("oidc mapping failed: %+v", provider)
	}
	if provider.EntityID == nil || *provider.EntityID != "entity" || provider.ForceAuthn == nil || !*provider.ForceAuthn {
		t.Fatalf("saml mapping failed: %+v", provider)
	}
	if len(provider.Scopes) != 2 || provider.Scopes[0] != "openid" {
		t.Fatalf("scopes mapping failed: %+v", provider.Scopes)
	}
}
