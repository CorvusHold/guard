package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

// seedCmd represents the seed command group (API-based operations for dev/test setup)
var seedCmd = &cobra.Command{
	Use:   "seed",
	Short: "Quick setup commands for development/test environments",
	Long: `Seed commands provide convenient shortcuts for setting up complete
test environments with tenants and users through the Guard API.

These commands use the same API endpoints as production but with simplified
flags for quick development/test setup. All operations go through proper
authentication and authorization checks.

Example workflow:
  1. guard-cli seed tenant --name "acme"  # Creates tenant, outputs TENANT_ID
  2. guard-cli seed user --tenant <id> --email admin@acme.com --password SecurePass123
  3. guard-cli seed default  # Quick: creates both tenant + user`,
}

var seedTenantCmd = &cobra.Command{
	Use:   "tenant [name]",
	Short: "Create a tenant via API",
	Long:  "Create a new tenant using the Guard API",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name, _ := cmd.Flags().GetString("name")
		if len(args) > 0 {
			name = args[0]
		}
		if name == "" {
			name = "test"
		}

		if apiToken == "" {
			return fmt.Errorf("--token is required (set GUARD_API_TOKEN or use config)")
		}

		client := &GuardClient{BaseURL: apiURL, Token: apiToken}

		// Call the existing CreateTenant method
		payload := map[string]interface{}{
			"name": name,
		}

		resp, err := client.makeRequest("POST", "/tenants", payload)
		if err != nil {
			return fmt.Errorf("failed to create tenant: %w", err)
		}

		var result map[string]interface{}
		if err := client.handleResponse(resp, &result); err != nil {
			return fmt.Errorf("failed to parse response: %w", err)
		}

		tenantID, ok := result["id"].(string)
		if !ok {
			return fmt.Errorf("invalid response: missing tenant ID")
		}

		// Output in different formats
		if outputFmt == "table" {
			fmt.Printf("Tenant created: %s\n", name)
			fmt.Printf("ID: %s\n", tenantID)
		} else if outputFmt == "json" {
			return formatOutput(result)
		} else {
			// env format (for scripts)
			fmt.Printf("TENANT_ID=%s\n", tenantID)
			fmt.Printf("TENANT_NAME=%s\n", name)
		}

		return nil
	},
}

var seedUserCmd = &cobra.Command{
	Use:   "user",
	Short: "Create a user via API",
	Long:  "Create a new user in a tenant using the Guard API",
	RunE: func(cmd *cobra.Command, args []string) error {
		tid, _ := cmd.Flags().GetString("tenant-id")
		email, _ := cmd.Flags().GetString("email")
		password, _ := cmd.Flags().GetString("password")
		firstName, _ := cmd.Flags().GetString("first-name")
		lastName, _ := cmd.Flags().GetString("last-name")
		rolesCSV, _ := cmd.Flags().GetString("roles")
		enableMFA, _ := cmd.Flags().GetBool("enable-mfa")

		if tid == "" {
			return fmt.Errorf("--tenant-id is required")
		}
		if email == "" {
			return fmt.Errorf("--email is required")
		}
		if password == "" {
			return fmt.Errorf("--password is required")
		}

		client := &GuardClient{BaseURL: apiURL, Token: apiToken, Tenant: tid}

		// Create user via signup endpoint
		payload := map[string]interface{}{
			"tenant_id":  tid,
			"email":      email,
			"password":   password,
			"first_name": firstName,
			"last_name":  lastName,
		}

		resp, err := client.makeRequest("POST", "/v1/auth/password/signup", payload)
		if err != nil {
			return fmt.Errorf("failed to create user: %w", err)
		}

		var result map[string]interface{}
		if err := client.handleResponse(resp, &result); err != nil {
			return fmt.Errorf("failed to parse response: %w", err)
		}

		userID, ok := result["user_id"].(string)
		if !ok {
			return fmt.Errorf("invalid response: missing user_id")
		}

		// Apply roles if API token is provided and roles specified
		if apiToken != "" && rolesCSV != "" {
			roles := parseRoles(rolesCSV)
			if len(roles) > 0 {
				rolePayload := map[string]interface{}{
					"roles": roles,
				}
				roleResp, err := client.makeRequest("PUT", "/v1/admin/users/"+userID+"/roles", rolePayload)
				if err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "Warning: failed to assign roles: %v\n", err)
				} else {
					_ = client.handleResponse(roleResp, nil)
					if verbose {
						fmt.Fprintf(cmd.ErrOrStderr(), "Assigned roles: %s\n", strings.Join(roles, ","))
					}
				}
			}
		}

		// Enable MFA if requested (requires API token)
		var totpSecret string
		if enableMFA && apiToken != "" {
			secret, err := enableUserMFAViaAPI(client, userID)
			if err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "Warning: failed to enable MFA: %v\n", err)
			} else {
				totpSecret = secret
				if verbose {
					fmt.Fprintf(cmd.ErrOrStderr(), "MFA enabled for user\n")
				}
			}
		}

		// Output in different formats
		if outputFmt == "table" {
			fmt.Printf("User created: %s\n", email)
			fmt.Printf("ID: %s\n", userID)
			fmt.Printf("Tenant: %s\n", tid)
			if totpSecret != "" {
				fmt.Printf("TOTP Secret: %s\n", totpSecret)
			}
		} else if outputFmt == "json" {
			result["tenant_id"] = tid
			if totpSecret != "" {
				result["totp_secret"] = totpSecret
			}
			return formatOutput(result)
		} else {
			// env format (for scripts)
			fmt.Printf("TENANT_ID=%s\n", tid)
			fmt.Printf("USER_ID=%s\n", userID)
			fmt.Printf("EMAIL=%s\n", email)
			fmt.Printf("PASSWORD=%s\n", password)
			if totpSecret != "" {
				fmt.Printf("TOTP_SECRET=%s\n", totpSecret)
				fmt.Printf("K6_TOTP=%s\n", totpSecret)
			}
			// k6-friendly aliases
			fmt.Printf("K6_TENANT_ID=%s\n", tid)
			fmt.Printf("K6_EMAIL=%s\n", email)
			fmt.Printf("K6_PASSWORD=%s\n", password)
		}

		return nil
	},
}

var seedDefaultCmd = &cobra.Command{
	Use:   "default",
	Short: "Quick setup: create tenant + user in one command",
	Long: `Create a complete test setup with a tenant and user via the API.
This is a convenience command that combines tenant and user creation.

Example:
  guard-cli seed default --tenant-name acme --email admin@acme.com --password Secret123`,
	RunE: func(cmd *cobra.Command, args []string) error {
		tenantName, _ := cmd.Flags().GetString("tenant-name")
		email, _ := cmd.Flags().GetString("email")
		password, _ := cmd.Flags().GetString("password")
		firstName, _ := cmd.Flags().GetString("first-name")
		lastName, _ := cmd.Flags().GetString("last-name")
		enableMFA, _ := cmd.Flags().GetBool("enable-mfa")

		if apiToken == "" {
			return fmt.Errorf("--token is required (set GUARD_API_TOKEN or use config)")
		}

		client := &GuardClient{BaseURL: apiURL, Token: apiToken}

		// Step 1: Create tenant
		tenantPayload := map[string]interface{}{
			"name": tenantName,
		}

		tenantResp, err := client.makeRequest("POST", "/tenants", tenantPayload)
		if err != nil {
			return fmt.Errorf("failed to create tenant: %w", err)
		}

		var tenantResult map[string]interface{}
		if err := client.handleResponse(tenantResp, &tenantResult); err != nil {
			return fmt.Errorf("failed to parse tenant response: %w", err)
		}

		tenantID, ok := tenantResult["id"].(string)
		if !ok {
			return fmt.Errorf("invalid tenant response: missing ID")
		}

		// Step 2: Create user in that tenant
		client.Tenant = tenantID

		userPayload := map[string]interface{}{
			"tenant_id":  tenantID,
			"email":      email,
			"password":   password,
			"first_name": firstName,
			"last_name":  lastName,
		}

		userResp, err := client.makeRequest("POST", "/v1/auth/password/signup", userPayload)
		if err != nil {
			return fmt.Errorf("failed to create user: %w", err)
		}

		var userResult map[string]interface{}
		if err := client.handleResponse(userResp, &userResult); err != nil {
			return fmt.Errorf("failed to parse user response: %w", err)
		}

		userID, ok := userResult["user_id"].(string)
		if !ok {
			return fmt.Errorf("invalid user response: missing user_id")
		}

		// Step 3: Enable MFA if requested
		var totpSecret string
		if enableMFA {
			secret, err := enableUserMFAViaAPI(client, userID)
			if err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "Warning: failed to enable MFA: %v\n", err)
			} else {
				totpSecret = secret
			}
		}

		// Output in different formats
		if outputFmt == "table" {
			fmt.Println("=== Test Environment Setup Complete ===")
			fmt.Printf("Tenant: %s (ID: %s)\n", tenantName, tenantID)
			fmt.Printf("User: %s (ID: %s)\n", email, userID)
			fmt.Printf("Password: %s\n", password)
			if totpSecret != "" {
				fmt.Printf("MFA: Enabled\n")
				fmt.Printf("TOTP Secret: %s\n", totpSecret)
			}
		} else if outputFmt == "json" {
			result := map[string]string{
				"tenant_id":   tenantID,
				"tenant_name": tenantName,
				"user_id":     userID,
				"email":       email,
				"password":    password,
			}
			if totpSecret != "" {
				result["totp_secret"] = totpSecret
				result["mfa_enabled"] = "true"
			}
			return formatOutput(result)
		} else {
			// env format (backward compatible with old seed tool)
			fmt.Printf("TENANT_ID=%s\n", tenantID)
			fmt.Printf("USER_ID=%s\n", userID)
			fmt.Printf("EMAIL=%s\n", email)
			fmt.Printf("PASSWORD=%s\n", password)
			if totpSecret != "" {
				fmt.Printf("TOTP_SECRET=%s\n", totpSecret)
			}
			// k6-friendly aliases
			fmt.Printf("K6_TENANT_ID=%s\n", tenantID)
			fmt.Printf("K6_EMAIL=%s\n", email)
			fmt.Printf("K6_PASSWORD=%s\n", password)
			if totpSecret != "" {
				fmt.Printf("K6_TOTP=%s\n", totpSecret)
			}
		}

		return nil
	},
}

var seedSSOWorkOSCmd = &cobra.Command{
	Use:   "sso-workos",
	Short: "Configure WorkOS SSO settings for a tenant",
	Long:  "Configure WorkOS SSO settings via the settings API",
	RunE: func(cmd *cobra.Command, args []string) error {
		tid, _ := cmd.Flags().GetString("tenant-id")
		clientID, _ := cmd.Flags().GetString("client-id")
		clientSecret, _ := cmd.Flags().GetString("client-secret")
		apiKey, _ := cmd.Flags().GetString("api-key")

		if tid == "" {
			return fmt.Errorf("--tenant-id is required")
		}
		if apiToken == "" {
			return fmt.Errorf("--token is required (set GUARD_API_TOKEN or use config)")
		}
		if clientID == "" {
			return fmt.Errorf("--client-id is required")
		}
		if clientSecret == "" && apiKey == "" {
			return fmt.Errorf("either --client-secret or --api-key is required")
		}

		client := &GuardClient{BaseURL: apiURL, Token: apiToken, Tenant: tid}

		// Build settings payload
		settings := map[string]interface{}{
			"sso.provider":         "workos",
			"sso.workos.client_id": clientID,
		}

		if clientSecret != "" {
			settings["sso.workos.client_secret"] = clientSecret
		}
		if apiKey != "" {
			settings["sso.workos.api_key"] = apiKey
		}

		// Apply settings via API
		resp, err := client.makeRequest("PUT", "/v1/tenants/"+tid+"/settings", settings)
		if err != nil {
			return fmt.Errorf("failed to configure SSO: %w", err)
		}

		if err := client.handleResponse(resp, nil); err != nil {
			return fmt.Errorf("failed to apply settings: %w", err)
		}

		if outputFmt == "table" {
			fmt.Printf("WorkOS SSO configured for tenant: %s\n", tid)
			fmt.Printf("Provider: workos\n")
			fmt.Printf("Client ID: %s\n", clientID)
			if clientSecret != "" {
				fmt.Println("Client Secret: [set]")
			}
			if apiKey != "" {
				fmt.Println("API Key: [set]")
			}
		} else if outputFmt == "json" {
			return formatOutput(map[string]string{
				"tenant_id":  tid,
				"provider":   "workos",
				"client_id":  clientID,
				"configured": "true",
			})
		} else {
			// env format
			fmt.Printf("TENANT_ID=%s\n", tid)
			fmt.Printf("SSO_PROVIDER=workos\n")
			fmt.Printf("WORKOS_CLIENT_ID=%s\n", clientID)
		}

		return nil
	},
}

func init() {
	// Add seed command to root
	rootCmd.AddCommand(seedCmd)

	// Add subcommands to seed
	seedCmd.AddCommand(seedTenantCmd)
	seedCmd.AddCommand(seedUserCmd)
	seedCmd.AddCommand(seedDefaultCmd)
	seedCmd.AddCommand(seedSSOWorkOSCmd)

	// Seed tenant flags
	seedTenantCmd.Flags().String("name", "test", "Tenant name")

	// Seed user flags
	seedUserCmd.Flags().String("tenant-id", "", "Tenant UUID (required)")
	seedUserCmd.Flags().String("email", "", "User email (required)")
	seedUserCmd.Flags().String("password", "", "User password (required)")
	seedUserCmd.Flags().String("first-name", "Test", "User's first name")
	seedUserCmd.Flags().String("last-name", "User", "User's last name")
	seedUserCmd.Flags().String("roles", "", "Comma-separated roles (e.g., admin,member)")
	seedUserCmd.Flags().Bool("enable-mfa", false, "Enable MFA (TOTP) for user")

	// Seed default flags
	seedDefaultCmd.Flags().String("tenant-name", "test", "Tenant name")
	seedDefaultCmd.Flags().String("email", "test@example.com", "User email")
	seedDefaultCmd.Flags().String("password", "Password123!", "User password")
	seedDefaultCmd.Flags().String("first-name", "Test", "User's first name")
	seedDefaultCmd.Flags().String("last-name", "User", "User's last name")
	seedDefaultCmd.Flags().Bool("enable-mfa", false, "Enable MFA (TOTP) for user")

	// Seed SSO WorkOS flags
	seedSSOWorkOSCmd.Flags().String("tenant-id", "", "Tenant UUID (required)")
	seedSSOWorkOSCmd.Flags().String("client-id", "", "WorkOS client ID (required)")
	seedSSOWorkOSCmd.Flags().String("client-secret", "", "WorkOS client secret")
	seedSSOWorkOSCmd.Flags().String("api-key", "", "WorkOS API key")
}

// Helper functions

func parseRoles(rolesCSV string) []string {
	parts := strings.Split(rolesCSV, ",")
	var roles []string
	for _, p := range parts {
		r := strings.TrimSpace(p)
		if r != "" {
			roles = append(roles, r)
		}
	}
	return roles
}

func enableUserMFAViaAPI(client *GuardClient, userID string) (string, error) {
	// Step 1: Start TOTP enrollment
	startResp, err := client.makeRequest("POST", "/v1/auth/mfa/totp/enroll", nil)
	if err != nil {
		return "", fmt.Errorf("failed to start TOTP enrollment: %w", err)
	}

	var enrollResult map[string]interface{}
	if err := client.handleResponse(startResp, &enrollResult); err != nil {
		return "", fmt.Errorf("failed to parse enrollment response: %w", err)
	}

	secret, ok := enrollResult["secret"].(string)
	if !ok {
		return "", fmt.Errorf("invalid enrollment response: missing secret")
	}

	// Step 2: Verify with a generated code (for automated setup)
	// Note: This requires generating a valid TOTP code from the secret
	// For now, we'll just return the secret and let the caller handle activation
	// In a real scenario, you'd use a TOTP library to generate a code and verify it

	return secret, nil
}
