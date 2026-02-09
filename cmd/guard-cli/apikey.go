package main

// API key management commands for guard-cli.

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// API key response types
type APIKeyCreateResponse struct {
	ID        string     `json:"id"`
	TenantID  string     `json:"tenant_id"`
	Name      string     `json:"name"`
	KeyPrefix string     `json:"key_prefix"`
	Scopes    []string   `json:"scopes"`
	RawKey    string     `json:"raw_key"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

type APIKeyItem struct {
	ID         string     `json:"id"`
	TenantID   string     `json:"tenant_id"`
	Name       string     `json:"name"`
	KeyPrefix  string     `json:"key_prefix"`
	Scopes     []string   `json:"scopes"`
	CreatedBy  *string    `json:"created_by,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

type APIKeysListResponse struct {
	APIKeys []APIKeyItem `json:"api_keys"`
}

var uuidRe = regexp.MustCompile(`^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$`)

var apikeyCmd = &cobra.Command{
	Use:   "apikey",
	Short: "API key management commands",
	Long:  "Create, list, and revoke API keys for service-to-service authentication.",
}

var apikeyCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new API key",
	Long:  "Creates a new API key for the current tenant. The raw key is shown only once.",
	RunE: func(cmd *cobra.Command, args []string) error {
		name, err := cmd.Flags().GetString("name")
		if err != nil {
			return err
		}
		scopesStr, err := cmd.Flags().GetString("scopes")
		if err != nil {
			return err
		}
		expiresStr, err := cmd.Flags().GetString("expires")
		if err != nil {
			return err
		}

		client := &GuardClient{BaseURL: apiURL, Token: apiToken, Tenant: tenantID}

		body := map[string]interface{}{
			"name": name,
		}
		if scopesStr != "" {
			body["scopes"] = strings.Split(scopesStr, ",")
		}
		if expiresStr != "" {
			body["expires_at"] = expiresStr
		}

		resp, err := client.makeRequest("POST", "/api/v1/auth/admin/api-keys", body)
		if err != nil {
			return err
		}

		var result APIKeyCreateResponse
		if err := client.handleResponse(resp, &result); err != nil {
			return err
		}

		if outputFmt == "json" {
			out, err := json.MarshalIndent(result, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to marshal api key response: %w", err)
			}
			fmt.Println(string(out))
		} else {
			fmt.Println("API Key created successfully!")
			fmt.Println()
			fmt.Printf("  ID:        %s\n", result.ID)
			fmt.Printf("  Name:      %s\n", result.Name)
			fmt.Printf("  Prefix:    %s\n", result.KeyPrefix)
			fmt.Printf("  Scopes:    %s\n", strings.Join(result.Scopes, ", "))
			if result.ExpiresAt != nil {
				fmt.Printf("  Expires:   %s\n", result.ExpiresAt.Format(time.RFC3339))
			}
			fmt.Println()
			fmt.Printf("  Raw Key:   %s\n", result.RawKey)
			fmt.Println()
			fmt.Println("  ⚠ Save this key now — it will not be shown again.")
		}

		return nil
	},
}

var apikeyListCmd = &cobra.Command{
	Use:   "list",
	Short: "List API keys for the current tenant",
	RunE: func(cmd *cobra.Command, args []string) error {
		client := &GuardClient{BaseURL: apiURL, Token: apiToken, Tenant: tenantID}

		resp, err := client.makeRequest("GET", "/api/v1/auth/admin/api-keys", nil)
		if err != nil {
			return err
		}

		var result APIKeysListResponse
		if err := client.handleResponse(resp, &result); err != nil {
			return err
		}

		if outputFmt == "json" {
			out, err := json.MarshalIndent(result, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to marshal api keys list: %w", err)
			}
			fmt.Println(string(out))
		} else {
			if len(result.APIKeys) == 0 {
				fmt.Println("No API keys found.")
				return nil
			}
			fmt.Printf("%-36s %-20s %-12s %-20s %-10s\n", "ID", "NAME", "PREFIX", "CREATED", "STATUS")
			fmt.Println(strings.Repeat("-", 100))
			for _, k := range result.APIKeys {
				status := "active"
				if k.RevokedAt != nil {
					status = "revoked"
				} else if k.ExpiresAt != nil && time.Now().After(*k.ExpiresAt) {
					status = "expired"
				}
				fmt.Printf("%-36s %-20s %-12s %-20s %-10s\n",
					k.ID,
					truncate(k.Name, 20),
					k.KeyPrefix,
					k.CreatedAt.Format("2006-01-02 15:04"),
					status,
				)
			}
		}

		return nil
	},
}

var apikeyRevokeCmd = &cobra.Command{
	Use:   "revoke",
	Short: "Revoke an API key",
	RunE: func(cmd *cobra.Command, args []string) error {
		id, err := cmd.Flags().GetString("id")
		if err != nil {
			return err
		}
		if !uuidRe.MatchString(id) {
			return fmt.Errorf("invalid API key id: must be a UUID")
		}

		client := &GuardClient{BaseURL: apiURL, Token: apiToken, Tenant: tenantID}

		resp, err := client.makeRequest("POST", "/api/v1/auth/admin/api-keys/"+id+"/revoke", nil)
		if err != nil {
			return err
		}

		if err := client.handleResponse(resp, nil); err != nil {
			return err
		}

		fmt.Printf("API key %s revoked successfully.\n", id)
		return nil
	},
}

func truncate(s string, max int) string {
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	if max <= 3 {
		return string(runes[:max])
	}
	return string(runes[:max-3]) + "..."
}

func init() {
	apikeyCreateCmd.Flags().String("name", "", "Name for the API key (required)")
	apikeyCreateCmd.Flags().String("scopes", "", "Comma-separated scopes (e.g., users:read,invitations:write)")
	apikeyCreateCmd.Flags().String("expires", "", "Expiration time in RFC3339 format")
	_ = apikeyCreateCmd.MarkFlagRequired("name")

	apikeyRevokeCmd.Flags().String("id", "", "API key ID to revoke (required)")
	_ = apikeyRevokeCmd.MarkFlagRequired("id")

	apikeyCmd.AddCommand(apikeyCreateCmd)
	apikeyCmd.AddCommand(apikeyListCmd)
	apikeyCmd.AddCommand(apikeyRevokeCmd)
}
