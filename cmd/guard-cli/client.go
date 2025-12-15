package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// API response structures
type TenantResponse struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	IsActive  bool      `json:"is_active"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type UserResponse struct {
	ID         string    `json:"id"`
	Email      string    `json:"email"`
	FirstName  string    `json:"first_name"`
	LastName   string    `json:"last_name"`
	IsActive   bool      `json:"is_active"`
	MFAEnabled bool      `json:"mfa_enabled"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type SettingsResponse struct {
	Settings map[string]interface{} `json:"settings"`
}

type HealthResponse struct {
	Status    string            `json:"status"`
	Version   string            `json:"version"`
	Timestamp time.Time         `json:"timestamp"`
	Checks    map[string]string `json:"checks,omitempty"`
}

type ErrorResponse struct {
	Error   string `json:"error"`
	Code    string `json:"code,omitempty"`
	Details string `json:"details,omitempty"`
}

// HTTP client methods
func (c *GuardClient) makeRequest(method, path string, body interface{}) (*http.Response, error) {
	var reqBody io.Reader

	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewBuffer(jsonBody)
	}

	url := c.BaseURL + path
	logVerbose("Making %s request to %s", method, url)

	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	if c.Tenant != "" {
		req.Header.Set("X-Tenant-ID", c.Tenant)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	logVerbose("Response status: %s", resp.Status)
	return resp, nil
}

func (c *GuardClient) handleResponse(resp *http.Response, target interface{}) error {
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode >= 400 {
		var errResp ErrorResponse
		if err := json.Unmarshal(body, &errResp); err == nil {
			return fmt.Errorf("API error (%d): %s", resp.StatusCode, errResp.Error)
		}
		return fmt.Errorf("API error (%d): %s", resp.StatusCode, string(body))
	}

	if target != nil {
		if err := json.Unmarshal(body, target); err != nil {
			return fmt.Errorf("failed to unmarshal response: %w", err)
		}
	}

	return nil
}

// Tenant management methods
func (c *GuardClient) ListTenants() error {
	resp, err := c.makeRequest("GET", "/api/v1/tenants", nil)
	if err != nil {
		return err
	}

	var tenants []TenantResponse
	if err := c.handleResponse(resp, &tenants); err != nil {
		return err
	}

	if outputFmt == "table" {
		fmt.Printf("%-36s %-20s %-8s %-20s\n", "ID", "NAME", "ACTIVE", "CREATED")
		fmt.Println(strings.Repeat("-", 84))
		for _, tenant := range tenants {
			status := "No"
			if tenant.IsActive {
				status = "Yes"
			}
			fmt.Printf("%-36s %-20s %-8s %-20s\n",
				tenant.ID,
				tenant.Name,
				status,
				tenant.CreatedAt.Format("2006-01-02 15:04:05"))
		}
		fmt.Printf("\nTotal: %d tenants\n", len(tenants))
	} else {
		return formatOutput(tenants)
	}

	return nil
}

func (c *GuardClient) CreateTenant(name string) error {
	payload := map[string]interface{}{
		"name": name,
	}

	resp, err := c.makeRequest("POST", "/api/v1/tenants", payload)
	if err != nil {
		return err
	}

	var tenant TenantResponse
	if err := c.handleResponse(resp, &tenant); err != nil {
		return err
	}

	if outputFmt == "table" {
		fmt.Printf("Tenant created successfully:\n")
		fmt.Printf("ID: %s\n", tenant.ID)
		fmt.Printf("Name: %s\n", tenant.Name)
		fmt.Printf("Active: %t\n", tenant.IsActive)
		fmt.Printf("Created: %s\n", tenant.CreatedAt.Format("2006-01-02 15:04:05"))
	} else {
		return formatOutput(tenant)
	}

	return nil
}

func (c *GuardClient) GetTenant(tenantID string) error {
	resp, err := c.makeRequest("GET", "/api/v1/tenants/"+tenantID, nil)
	if err != nil {
		return err
	}

	var tenant TenantResponse
	if err := c.handleResponse(resp, &tenant); err != nil {
		return err
	}

	if outputFmt == "table" {
		fmt.Printf("Tenant Details:\n")
		fmt.Printf("ID: %s\n", tenant.ID)
		fmt.Printf("Name: %s\n", tenant.Name)
		fmt.Printf("Active: %t\n", tenant.IsActive)
		fmt.Printf("Created: %s\n", tenant.CreatedAt.Format("2006-01-02 15:04:05"))
		fmt.Printf("Updated: %s\n", tenant.UpdatedAt.Format("2006-01-02 15:04:05"))
	} else {
		return formatOutput(tenant)
	}

	return nil
}

func (c *GuardClient) DeleteTenant(tenantID string) error {
	resp, err := c.makeRequest("DELETE", "/api/v1/tenants/"+tenantID, nil)
	if err != nil {
		return err
	}

	if err := c.handleResponse(resp, nil); err != nil {
		return err
	}

	fmt.Printf("Tenant %s deleted successfully\n", tenantID)
	return nil
}

// User management methods
func (c *GuardClient) ListUsers() error {
	resp, err := c.makeRequest("GET", "/api/v1/auth/admin/users", nil)
	if err != nil {
		return err
	}

	var users []UserResponse
	if err := c.handleResponse(resp, &users); err != nil {
		return err
	}

	if outputFmt == "table" {
		fmt.Printf("%-36s %-30s %-20s %-20s %-8s %-8s\n", "ID", "EMAIL", "FIRST NAME", "LAST NAME", "ACTIVE", "MFA")
		fmt.Println(strings.Repeat("-", 130))
		for _, user := range users {
			active := "No"
			if user.IsActive {
				active = "Yes"
			}
			mfa := "No"
			if user.MFAEnabled {
				mfa = "Yes"
			}
			fmt.Printf("%-36s %-30s %-20s %-20s %-8s %-8s\n",
				user.ID,
				user.Email,
				user.FirstName,
				user.LastName,
				active,
				mfa)
		}
		fmt.Printf("\nTotal: %d users\n", len(users))
	} else {
		return formatOutput(users)
	}

	return nil
}

func (c *GuardClient) CreateUser(email, password, firstName, lastName string, enableMFA bool) error {
	payload := map[string]interface{}{
		"email":      email,
		"password":   password,
		"first_name": firstName,
		"last_name":  lastName,
	}

	resp, err := c.makeRequest("POST", "/api/v1/auth/password/signup", payload)
	if err != nil {
		return err
	}

	var result map[string]interface{}
	if err := c.handleResponse(resp, &result); err != nil {
		return err
	}

	userID, ok := result["user_id"].(string)
	if !ok {
		return fmt.Errorf("failed to get user ID from response")
	}

	// Enable MFA if requested
	if enableMFA {
		if err := c.enableUserMFA(userID); err != nil {
			fmt.Printf("Warning: Failed to enable MFA for user: %v\n", err)
		}
	}

	if outputFmt == "table" {
		fmt.Printf("User created successfully:\n")
		fmt.Printf("User ID: %s\n", userID)
		fmt.Printf("Email: %s\n", email)
		fmt.Printf("Name: %s %s\n", firstName, lastName)
		fmt.Printf("MFA Enabled: %t\n", enableMFA)
	} else {
		return formatOutput(result)
	}

	return nil
}

func (c *GuardClient) enableUserMFA(userID string) error {
	payload := map[string]interface{}{
		"user_id": userID,
	}

	resp, err := c.makeRequest("POST", "/api/v1/auth/admin/users/"+userID+"/mfa/enable", payload)
	if err != nil {
		return err
	}

	return c.handleResponse(resp, nil)
}

func (c *GuardClient) GetUser(userID string) error {
	resp, err := c.makeRequest("GET", "/api/v1/auth/admin/users/"+userID, nil)
	if err != nil {
		return err
	}

	var user UserResponse
	if err := c.handleResponse(resp, &user); err != nil {
		return err
	}

	if outputFmt == "table" {
		fmt.Printf("User Details:\n")
		fmt.Printf("ID: %s\n", user.ID)
		fmt.Printf("Email: %s\n", user.Email)
		fmt.Printf("First Name: %s\n", user.FirstName)
		fmt.Printf("Last Name: %s\n", user.LastName)
		fmt.Printf("Active: %t\n", user.IsActive)
		fmt.Printf("MFA Enabled: %t\n", user.MFAEnabled)
		fmt.Printf("Created: %s\n", user.CreatedAt.Format("2006-01-02 15:04:05"))
		fmt.Printf("Updated: %s\n", user.UpdatedAt.Format("2006-01-02 15:04:05"))
	} else {
		return formatOutput(user)
	}

	return nil
}

func (c *GuardClient) DeleteUser(userID string) error {
	resp, err := c.makeRequest("DELETE", "/api/v1/auth/admin/users/"+userID, nil)
	if err != nil {
		return err
	}

	if err := c.handleResponse(resp, nil); err != nil {
		return err
	}

	fmt.Printf("User %s deleted successfully\n", userID)
	return nil
}

// Settings management methods
func (c *GuardClient) GetSettings() error {
	resp, err := c.makeRequest("GET", "/api/v1/tenants/"+c.Tenant+"/settings", nil)
	if err != nil {
		return err
	}

	var settings SettingsResponse
	if err := c.handleResponse(resp, &settings); err != nil {
		return err
	}

	if outputFmt == "table" {
		fmt.Printf("Tenant Settings for %s:\n", c.Tenant)
		fmt.Println(strings.Repeat("-", 50))
		for key, value := range settings.Settings {
			// Mask sensitive values
			displayValue := value
			if isSensitiveKey(key) {
				displayValue = maskSensitiveValue(fmt.Sprintf("%v", value))
			}
			fmt.Printf("%-30s: %v\n", key, displayValue)
		}
	} else {
		return formatOutput(settings.Settings)
	}

	return nil
}

func (c *GuardClient) SetSetting(key, value string) error {
	payload := map[string]interface{}{
		key: value,
	}

	resp, err := c.makeRequest("PUT", "/api/v1/tenants/"+c.Tenant+"/settings", payload)
	if err != nil {
		return err
	}

	if err := c.handleResponse(resp, nil); err != nil {
		return err
	}

	fmt.Printf("Setting '%s' updated successfully\n", key)
	return nil
}

// Health check method
func (c *GuardClient) CheckHealth() error {
	resp, err := c.makeRequest("GET", "/health", nil)
	if err != nil {
		return err
	}

	var health HealthResponse
	if err := c.handleResponse(resp, &health); err != nil {
		return err
	}

	if outputFmt == "table" {
		fmt.Printf("Guard API Health Status:\n")
		fmt.Printf("Status: %s\n", health.Status)
		fmt.Printf("Version: %s\n", health.Version)
		fmt.Printf("Timestamp: %s\n", health.Timestamp.Format("2006-01-02 15:04:05"))

		if len(health.Checks) > 0 {
			fmt.Println("\nHealth Checks:")
			for check, status := range health.Checks {
				fmt.Printf("  %s: %s\n", check, status)
			}
		}
	} else {
		return formatOutput(health)
	}

	return nil
}

// Helper functions
func isSensitiveKey(key string) bool {
	sensitiveKeys := []string{
		"password", "secret", "key", "token", "api_key",
		"sso_workos_client_secret", "sso_workos_api_key",
		"email_smtp_password", "email_brevo_api_key",
	}

	keyLower := strings.ToLower(key)
	for _, sensitive := range sensitiveKeys {
		if strings.Contains(keyLower, sensitive) {
			return true
		}
	}
	return false
}

func maskSensitiveValue(value string) string {
	if len(value) <= 8 {
		return strings.Repeat("*", len(value))
	}
	return value[:4] + strings.Repeat("*", len(value)-8) + value[len(value)-4:]
}
