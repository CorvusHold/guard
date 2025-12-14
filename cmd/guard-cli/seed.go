package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/pquerna/otp/totp"
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
		switch outputFmt {
		case "table":
			fmt.Printf("Tenant created: %s\n", name)
			fmt.Printf("ID: %s\n", tenantID)
		case "json":
			return formatOutput(result)
		case "env":
			printEnvVars(map[string]string{
				"TENANT_ID":   tenantID,
				"TENANT_NAME": name,
			})
		default:
			printEnvVars(map[string]string{
				"TENANT_ID":   tenantID,
				"TENANT_NAME": name,
			})
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

		resp, err := client.makeRequest("POST", "/api/v1/auth/password/signup", payload)
		if err != nil {
			return fmt.Errorf("failed to create user: %w", err)
		}

		var result map[string]interface{}
		if err := client.handleResponse(resp, &result); err != nil {
			return fmt.Errorf("failed to parse response: %w", err)
		}

		accessToken, _ := result["access_token"].(string)
		userID, _ := result["user_id"].(string)
		if userID == "" {
			if accessToken != "" {
				prof, err := lookupUserProfile(accessToken)
				if err != nil {
					if verbose {
						fmt.Fprintf(cmd.ErrOrStderr(), "warning: failed to resolve user profile from access token: %v\n", err)
					}
				} else if prof.ID != "" {
					userID = prof.ID
				}
			} else if verbose {
				fmt.Fprintf(cmd.ErrOrStderr(), "warning: signup response missing user_id and access_token; continuing without user id\n")
			}
		}

		// Apply roles if API token is provided and roles specified
		if apiToken != "" && rolesCSV != "" {
			roles := parseRoles(rolesCSV)
			if len(roles) > 0 {
				rolePayload := map[string]interface{}{
					"roles": roles,
				}
				roleResp, err := client.makeRequest("POST", "/api/v1/auth/admin/users/"+userID+"/roles", rolePayload)
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

		// Enable MFA if requested (requires API token) using the *user* access token
		var totpSecret string
		if enableMFA && apiToken != "" {
			if accessToken == "" {
				fmt.Fprintf(cmd.ErrOrStderr(), "Warning: cannot enable MFA: missing access token in signup response\n")
			} else {
				secret, err := enableUserMFAViaAPI(client, accessToken)
				if err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "Warning: failed to enable MFA: %v\n", err)
				} else {
					totpSecret = secret
					if verbose {
						fmt.Fprintf(cmd.ErrOrStderr(), "MFA enabled for user\n")
					}
				}
			}
		}

		// Output in different formats
		switch outputFmt {
		case "table":
			fmt.Printf("User created: %s\n", email)
			fmt.Printf("ID: %s\n", userID)
			fmt.Printf("Tenant: %s\n", tid)
			if totpSecret != "" {
				fmt.Printf("TOTP Secret: %s\n", totpSecret)
			}
		case "json":
			result["tenant_id"] = tid
			if totpSecret != "" {
				result["totp_secret"] = totpSecret
			}
			return formatOutput(result)
		case "env":
			printEnvVars(buildUserEnv(tid, userID, email, password, totpSecret))
		default:
			printEnvVars(buildUserEnv(tid, userID, email, password, totpSecret))
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

		// Step 1: Find or create tenant by name (idempotent)
		tenantID, err := findOrCreateTenantByName(client, tenantName)
		if err != nil {
			return err
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

		userResp, err := client.makeRequest("POST", "/api/v1/auth/password/signup", userPayload)
		if err != nil {
			return fmt.Errorf("failed to create user: %w", err)
		}

		var userResult map[string]interface{}
		if err := client.handleResponse(userResp, &userResult); err != nil {
			return fmt.Errorf("failed to parse user response: %w", err)
		}

		accessToken, _ := userResult["access_token"].(string)
		userID, _ := userResult["user_id"].(string)
		if userID == "" {
			if accessToken != "" {
				prof, err := lookupUserProfile(accessToken)
				if err != nil {
					if verbose {
						fmt.Fprintf(cmd.ErrOrStderr(), "warning: failed to resolve user profile from access token: %v\n", err)
					}
				} else if prof.ID != "" {
					userID = prof.ID
				}
			} else if verbose {
				fmt.Fprintf(cmd.ErrOrStderr(), "warning: signup response missing user_id and access_token; continuing without user id\n")
			}
		}

		// Step 3: Enable MFA if requested using the *user* access token
		var totpSecret string
		if enableMFA {
			if accessToken == "" {
				fmt.Fprintf(cmd.ErrOrStderr(), "Warning: cannot enable MFA: missing access token in signup response\n")
			} else {
				secret, err := enableUserMFAViaAPI(client, accessToken)
				if err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "Warning: failed to enable MFA: %v\n", err)
				} else {
					totpSecret = secret
				}
			}
		}

		// Output in different formats
		switch outputFmt {
		case "table":
			fmt.Println("=== Test Environment Setup Complete ===")
			fmt.Printf("Tenant: %s (ID: %s)\n", tenantName, tenantID)
			fmt.Printf("User: %s (ID: %s)\n", email, userID)
			fmt.Printf("Password: %s\n", password)
			if totpSecret != "" {
				fmt.Printf("MFA: Enabled\n")
				fmt.Printf("TOTP Secret: %s\n", totpSecret)
			}
		case "json":
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
		case "env":
			vars := map[string]string{
				"TENANT_ID": tenantID,
				"USER_ID":   userID,
				"EMAIL":     email,
				"PASSWORD":  password,
			}
			if totpSecret != "" {
				vars["TOTP_SECRET"] = totpSecret
				vars["K6_TOTP"] = totpSecret
			}
			vars["K6_TENANT_ID"] = tenantID
			vars["K6_EMAIL"] = email
			vars["K6_PASSWORD"] = password
			printEnvVars(vars)
		default:
			vars := map[string]string{
				"TENANT_ID": tenantID,
				"USER_ID":   userID,
				"EMAIL":     email,
				"PASSWORD":  password,
			}
			if totpSecret != "" {
				vars["TOTP_SECRET"] = totpSecret
				vars["K6_TOTP"] = totpSecret
			}
			vars["K6_TENANT_ID"] = tenantID
			vars["K6_EMAIL"] = email
			vars["K6_PASSWORD"] = password
			printEnvVars(vars)
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
		resp, err := client.makeRequest("PUT", "/api/v1/tenants/"+tid+"/settings", settings)
		if err != nil {
			return fmt.Errorf("failed to configure SSO: %w", err)
		}

		if err := client.handleResponse(resp, nil); err != nil {
			return fmt.Errorf("failed to apply settings: %w", err)
		}

		// Output in different formats
		switch outputFmt {
		case "table":
			fmt.Printf("WorkOS SSO configured for tenant: %s\n", tid)
			fmt.Printf("Provider: workos\n")
			fmt.Printf("Client ID: %s\n", clientID)
			if clientSecret != "" {
				fmt.Println("Client Secret: [set]")
			}
			if apiKey != "" {
				fmt.Println("API Key: [set]")
			}
		case "json":
			return formatOutput(map[string]string{
				"tenant_id":  tid,
				"provider":   "workos",
				"client_id":  clientID,
				"configured": "true",
			})
		case "env":
			printEnvVars(map[string]string{
				"TENANT_ID":        tid,
				"SSO_PROVIDER":     "workos",
				"WORKOS_CLIENT_ID": clientID,
			})
		default:
			printEnvVars(map[string]string{
				"TENANT_ID":        tid,
				"SSO_PROVIDER":     "workos",
				"WORKOS_CLIENT_ID": clientID,
			})
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

func enableUserMFAViaAPI(client *GuardClient, userAccessToken string) (string, error) {
	if strings.TrimSpace(userAccessToken) == "" {
		return "", fmt.Errorf("user access token required to enable MFA")
	}

	// Use a copy of the client so we preserve base URL / tenant but swap auth
	userClient := *client
	userClient.Token = userAccessToken

	// Step 1: Start TOTP enrollment as the user
	startResp, err := userClient.makeRequest("POST", "/api/v1/auth/mfa/totp/start", nil)
	if err != nil {
		return "", fmt.Errorf("failed to start TOTP enrollment: %w", err)
	}

	var startResult map[string]interface{}
	if err := client.handleResponse(startResp, &startResult); err != nil {
		return "", fmt.Errorf("failed to parse enrollment response: %w", err)
	}

	secret, ok := startResult["secret"].(string)
	if !ok || secret == "" {
		return "", fmt.Errorf("invalid enrollment response: missing secret")
	}

	// Step 2: Verify with a generated code (for automated setup)
	// Generate a valid TOTP code from the secret
	// and call the TOTP activation endpoint so MFA is fully enabled
	// This mirrors the server-side integration tests for TOTP enrollment.
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		return "", fmt.Errorf("failed to generate TOTP code: %w", err)
	}

	activatePayload := map[string]interface{}{
		"code": code,
	}
	activateResp, err := userClient.makeRequest("POST", "/api/v1/auth/mfa/totp/activate", activatePayload)
	if err != nil {
		return "", fmt.Errorf("failed to activate TOTP: %w", err)
	}
	if err := client.handleResponse(activateResp, nil); err != nil {
		return "", fmt.Errorf("failed to parse TOTP activate response: %w", err)
	}

	return secret, nil
}

func buildUserEnv(tenantID, userID, email, password, totpSecret string) map[string]string {
	vars := map[string]string{
		"TENANT_ID":    tenantID,
		"USER_ID":      userID,
		"EMAIL":        email,
		"PASSWORD":     password,
		"K6_TENANT_ID": tenantID,
		"K6_EMAIL":     email,
		"K6_PASSWORD":  password,
	}
	if totpSecret != "" {
		vars["TOTP_SECRET"] = totpSecret
		vars["K6_TOTP"] = totpSecret
	}
	return vars
}

func printEnvVars(vars map[string]string) {
	keys := make([]string, 0, len(vars))
	for k := range vars {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Printf("%s=%s\n", k, vars[k])
	}
}

// userProfile is a minimal view of /v1/auth/me used by seeding helpers to
// recover the created user's ID when password signup returns only tokens.
type userProfile struct {
	ID       string `json:"id"`
	TenantID string `json:"tenant_id"`
	Email    string `json:"email"`
}

func lookupUserProfile(accessToken string) (userProfile, error) {
	if accessToken == "" {
		return userProfile{}, fmt.Errorf("access token required")
	}
	// apiURL is populated by initConfig in main.go; fall back to default for safety.
	base := apiURL
	if base == "" {
		base = "http://localhost:8080"
	}
	req, err := http.NewRequest("GET", strings.TrimRight(base, "/")+"/api/v1/auth/me", nil)
	if err != nil {
		return userProfile{}, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return userProfile{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		return userProfile{}, fmt.Errorf("/api/v1/auth/me failed: %s: %s", resp.Status, string(b))
	}
	var prof userProfile
	if err := json.NewDecoder(resp.Body).Decode(&prof); err != nil {
		return userProfile{}, err
	}
	if prof.ID == "" {
		return userProfile{}, fmt.Errorf("/api/v1/auth/me response missing id")
	}
	return prof, nil
}

// findOrCreateTenantByName provides idempotent tenant creation semantics for
// seed helpers. It first tries GET /tenants/by-name/{name}; when the tenant
// exists it returns its ID, otherwise it falls back to POST /tenants.
func findOrCreateTenantByName(c *GuardClient, name string) (string, error) {
	if strings.TrimSpace(name) == "" {
		name = "test"
	}
	// 1) Try lookup by name
	lookupPath := "/api/v1/tenants/by-name/" + url.PathEscape(name)
	resp, err := c.makeRequest("GET", lookupPath, nil)
	if err != nil {
		return "", fmt.Errorf("failed to lookup tenant by name: %w", err)
	}
	if resp.StatusCode == http.StatusOK {
		var t TenantResponse
		if err := c.handleResponse(resp, &t); err != nil {
			return "", fmt.Errorf("failed to parse tenant lookup response: %w", err)
		}
		if t.ID == "" {
			return "", fmt.Errorf("invalid tenant lookup response: missing id")
		}
		return t.ID, nil
	}
	// For non-404 errors, surface details
	if resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return "", fmt.Errorf("tenant lookup failed: %s: %s", resp.Status, string(body))
	}
	resp.Body.Close()

	// 2) Create tenant when not found
	payload := map[string]interface{}{"name": name}
	createResp, err := c.makeRequest("POST", "/api/v1/tenants", payload)
	if err != nil {
		return "", fmt.Errorf("failed to create tenant: %w", err)
	}
	var created TenantResponse
	if err := c.handleResponse(createResp, &created); err != nil {
		// If the API reports "tenant name already exists" (e.g. from a race or
		// prior run), treat this as success and resolve the existing tenant ID.
		if strings.Contains(err.Error(), "tenant name already exists") {
			resp2, err2 := c.makeRequest("GET", lookupPath, nil)
			if err2 != nil {
				return "", fmt.Errorf("tenant exists but lookup failed: %w", err2)
			}
			var t TenantResponse
			if err3 := c.handleResponse(resp2, &t); err3 != nil {
				return "", fmt.Errorf("tenant exists but lookup parse failed: %w", err3)
			}
			if t.ID == "" {
				return "", fmt.Errorf("tenant exists but lookup returned empty id")
			}
			return t.ID, nil
		}
		return "", fmt.Errorf("failed to parse tenant create response: %w", err)
	}
	if created.ID == "" {
		return "", fmt.Errorf("invalid tenant create response: missing id")
	}
	return created.ID, nil
}
