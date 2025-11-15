package domain

import "testing"

func TestProviderType_Constants(t *testing.T) {
	tests := []struct {
		name     string
		provider ProviderType
		expected string
	}{
		{"OIDC", ProviderTypeOIDC, "oidc"},
		{"SAML", ProviderTypeSAML, "saml"},
		{"OAuth2", ProviderTypeOAuth2, "oauth2"},
		{"WorkOS", ProviderTypeWorkOS, "workos"},
		{"Dev", ProviderTypeDev, "dev"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.provider) != tt.expected {
				t.Errorf("ProviderType = %v, want %v", tt.provider, tt.expected)
			}
		})
	}
}

func TestDefaultAttributeMapping(t *testing.T) {
	mapping := DefaultAttributeMapping()

	// Test that all expected keys exist
	expectedKeys := []string{"email", "first_name", "last_name", "name", "picture", "groups"}
	for _, key := range expectedKeys {
		if _, ok := mapping[key]; !ok {
			t.Errorf("DefaultAttributeMapping() missing key %q", key)
		}
	}

	// Test that email mapping contains expected values
	emailMapping, ok := mapping["email"]
	if !ok {
		t.Fatal("DefaultAttributeMapping() missing 'email' key")
	}

	expectedEmailAttrs := []string{"email", "mail"}
	for _, attr := range expectedEmailAttrs {
		found := false
		for _, v := range emailMapping {
			if v == attr {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("email mapping missing %q", attr)
		}
	}
}

func TestApplyAttributeMapping_WithNilMapping(t *testing.T) {
	profile := &Profile{
		RawAttributes: map[string]interface{}{
			"email":       "user@example.com",
			"given_name":  "John",
			"family_name": "Doe",
		},
	}

	// Apply with nil mapping - should use defaults
	ApplyAttributeMapping(profile, nil)

	if profile.Email != "user@example.com" {
		t.Errorf("Email = %v, want user@example.com", profile.Email)
	}
	if profile.FirstName != "John" {
		t.Errorf("FirstName = %v, want John", profile.FirstName)
	}
	if profile.LastName != "Doe" {
		t.Errorf("LastName = %v, want Doe", profile.LastName)
	}
}

func TestApplyAttributeMapping_PreservesExistingValues(t *testing.T) {
	profile := &Profile{
		Email:     "existing@example.com",
		FirstName: "Existing",
		RawAttributes: map[string]interface{}{
			"email":      "new@example.com",
			"given_name": "New",
		},
	}

	ApplyAttributeMapping(profile, nil)

	// Should NOT overwrite existing values
	if profile.Email != "existing@example.com" {
		t.Errorf("Email was overwritten: got %v, want existing@example.com", profile.Email)
	}
	if profile.FirstName != "Existing" {
		t.Errorf("FirstName was overwritten: got %v, want Existing", profile.FirstName)
	}
}

func TestApplyAttributeMapping_GroupsHandling(t *testing.T) {
	tests := []struct {
		name          string
		rawGroups     interface{}
		expectedCount int
	}{
		{
			name:          "string array",
			rawGroups:     []string{"admin", "users"},
			expectedCount: 2,
		},
		{
			name:          "interface array",
			rawGroups:     []interface{}{"admin", "users", "developers"},
			expectedCount: 3,
		},
		{
			name:          "single string",
			rawGroups:     "admin",
			expectedCount: 1,
		},
		{
			name:          "nil",
			rawGroups:     nil,
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile := &Profile{
				RawAttributes: map[string]interface{}{
					"groups": tt.rawGroups,
				},
			}

			ApplyAttributeMapping(profile, nil)

			if len(profile.Groups) != tt.expectedCount {
				t.Errorf("Groups length = %v, want %v", len(profile.Groups), tt.expectedCount)
			}
		})
	}
}

func TestApplyAttributeMapping_CustomMapping(t *testing.T) {
	profile := &Profile{
		RawAttributes: map[string]interface{}{
			"mail":        "user@example.com",
			"givenName":   "Jane",
			"surname":     "Smith",
			"displayName": "Jane Smith",
		},
	}

	customMapping := map[string][]string{
		"email":      {"mail", "email"},
		"first_name": {"givenName", "given_name"},
		"last_name":  {"surname", "family_name"},
		"name":       {"displayName", "name"},
	}

	ApplyAttributeMapping(profile, customMapping)

	if profile.Email != "user@example.com" {
		t.Errorf("Email = %v, want user@example.com", profile.Email)
	}
	if profile.FirstName != "Jane" {
		t.Errorf("FirstName = %v, want Jane", profile.FirstName)
	}
	if profile.LastName != "Smith" {
		t.Errorf("LastName = %v, want Smith", profile.LastName)
	}
	if profile.Name != "Jane Smith" {
		t.Errorf("Name = %v, want Jane Smith", profile.Name)
	}
}

func TestApplyAttributeMapping_FallbackPriority(t *testing.T) {
	profile := &Profile{
		RawAttributes: map[string]interface{}{
			// Only the second preference is present
			"mail": "user@example.com",
		},
	}

	mapping := map[string][]string{
		"email": {"email", "mail", "emailAddress"}, // Try in order
	}

	ApplyAttributeMapping(profile, mapping)

	// Should find "mail" as fallback
	if profile.Email != "user@example.com" {
		t.Errorf("Email = %v, want user@example.com", profile.Email)
	}
}

func TestApplyAttributeMapping_EmptyRawAttributes(t *testing.T) {
	profile := &Profile{
		RawAttributes: map[string]interface{}{},
	}

	ApplyAttributeMapping(profile, nil)

	// Should not panic and fields should remain empty
	if profile.Email != "" {
		t.Errorf("Email = %v, want empty", profile.Email)
	}
	if profile.FirstName != "" {
		t.Errorf("FirstName = %v, want empty", profile.FirstName)
	}
}

func TestApplyAttributeMapping_NonStringValues(t *testing.T) {
	profile := &Profile{
		RawAttributes: map[string]interface{}{
			"email": 12345, // Non-string value
		},
	}

	ApplyAttributeMapping(profile, nil)

	// Should handle gracefully - toString should return empty string for non-string
	if profile.Email != "" {
		t.Errorf("Email = %v, want empty (non-string should be ignored)", profile.Email)
	}
}
