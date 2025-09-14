package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile   string
	apiURL    string
	apiToken  string
	tenantID  string
	verbose   bool
	outputFmt string
)

// Config holds CLI configuration
type Config struct {
	APIURL   string `mapstructure:"api_url"`
	APIToken string `mapstructure:"api_token"`
	TenantID string `mapstructure:"tenant_id"`
}

// GuardClient represents the API client
type GuardClient struct {
	BaseURL string
	Token   string
	Tenant  string
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "guard-cli",
	Short: "Corvus Guard CLI - Tenant and user management tool",
	Long: `Guard CLI provides command-line access to Corvus Guard authentication service.
Manage tenants, users, settings, and monitor system health from the terminal.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		initConfig()
		if verbose {
			fmt.Printf("API URL: %s\n", apiURL)
			fmt.Printf("Tenant ID: %s\n", tenantID)
		}
	},
}

func init() {
	cobra.OnInitialize(initConfig)

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.guard-cli.yaml)")
	rootCmd.PersistentFlags().StringVar(&apiURL, "api-url", "", "Guard API base URL")
	rootCmd.PersistentFlags().StringVar(&apiToken, "token", "", "API authentication token")
	rootCmd.PersistentFlags().StringVar(&tenantID, "tenant", "", "Tenant ID for operations")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
	rootCmd.PersistentFlags().StringVarP(&outputFmt, "output", "o", "table", "output format (table, json, yaml)")

	// Bind flags to viper
	viper.BindPFlag("api_url", rootCmd.PersistentFlags().Lookup("api-url"))
	viper.BindPFlag("api_token", rootCmd.PersistentFlags().Lookup("token"))
	viper.BindPFlag("tenant_id", rootCmd.PersistentFlags().Lookup("tenant"))

	// Add subcommands
	rootCmd.AddCommand(tenantCmd)
	rootCmd.AddCommand(userCmd)
	rootCmd.AddCommand(settingsCmd)
	rootCmd.AddCommand(healthCmd)
	rootCmd.AddCommand(configCmd)
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".guard-cli")
	}

	// Environment variables
	viper.SetEnvPrefix("GUARD")
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))

	if err := viper.ReadInConfig(); err == nil && verbose {
		fmt.Printf("Using config file: %s\n", viper.ConfigFileUsed())
	}

	// Set values from viper
	if apiURL == "" {
		apiURL = viper.GetString("api_url")
	}
	if apiToken == "" {
		apiToken = viper.GetString("api_token")
	}
	if tenantID == "" {
		tenantID = viper.GetString("tenant_id")
	}

	// Default values
	if apiURL == "" {
		apiURL = "http://localhost:8080"
	}
}

// Tenant management commands
var tenantCmd = &cobra.Command{
	Use:   "tenant",
	Short: "Tenant management commands",
	Long:  "Create, list, update, and manage tenants",
}

var tenantListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all tenants",
	Long:  "List all tenants with their status and basic information",
	RunE: func(cmd *cobra.Command, args []string) error {
		client := &GuardClient{BaseURL: apiURL, Token: apiToken}
		return client.ListTenants()
	},
}

var tenantCreateCmd = &cobra.Command{
	Use:   "create [name]",
	Short: "Create a new tenant",
	Long:  "Create a new tenant with the specified name",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client := &GuardClient{BaseURL: apiURL, Token: apiToken}
		return client.CreateTenant(args[0])
	},
}

var tenantGetCmd = &cobra.Command{
	Use:   "get [tenant-id]",
	Short: "Get tenant details",
	Long:  "Get detailed information about a specific tenant",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client := &GuardClient{BaseURL: apiURL, Token: apiToken}
		return client.GetTenant(args[0])
	},
}

var tenantDeleteCmd = &cobra.Command{
	Use:   "delete [tenant-id]",
	Short: "Delete a tenant",
	Long:  "Delete a tenant and all associated data (WARNING: This is irreversible)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client := &GuardClient{BaseURL: apiURL, Token: apiToken}
		
		// Confirmation prompt
		fmt.Printf("Are you sure you want to delete tenant '%s'? This action cannot be undone.\n", args[0])
		fmt.Print("Type 'yes' to confirm: ")
		var confirmation string
		fmt.Scanln(&confirmation)
		
		if confirmation != "yes" {
			fmt.Println("Operation cancelled.")
			return nil
		}
		
		return client.DeleteTenant(args[0])
	},
}

func init() {
	tenantCmd.AddCommand(tenantListCmd)
	tenantCmd.AddCommand(tenantCreateCmd)
	tenantCmd.AddCommand(tenantGetCmd)
	tenantCmd.AddCommand(tenantDeleteCmd)
}

// User management commands
var userCmd = &cobra.Command{
	Use:   "user",
	Short: "User management commands",
	Long:  "Create, list, update, and manage users within tenants",
}

var userListCmd = &cobra.Command{
	Use:   "list",
	Short: "List users in a tenant",
	Long:  "List all users in the specified tenant",
	RunE: func(cmd *cobra.Command, args []string) error {
		if tenantID == "" {
			return fmt.Errorf("tenant ID is required (use --tenant flag)")
		}
		client := &GuardClient{BaseURL: apiURL, Token: apiToken, Tenant: tenantID}
		return client.ListUsers()
	},
}

var userCreateCmd = &cobra.Command{
	Use:   "create [email] [password]",
	Short: "Create a new user",
	Long:  "Create a new user in the specified tenant",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		if tenantID == "" {
			return fmt.Errorf("tenant ID is required (use --tenant flag)")
		}
		
		firstName, _ := cmd.Flags().GetString("first-name")
		lastName, _ := cmd.Flags().GetString("last-name")
		enableMFA, _ := cmd.Flags().GetBool("enable-mfa")
		
		client := &GuardClient{BaseURL: apiURL, Token: apiToken, Tenant: tenantID}
		return client.CreateUser(args[0], args[1], firstName, lastName, enableMFA)
	},
}

var userGetCmd = &cobra.Command{
	Use:   "get [user-id]",
	Short: "Get user details",
	Long:  "Get detailed information about a specific user",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if tenantID == "" {
			return fmt.Errorf("tenant ID is required (use --tenant flag)")
		}
		client := &GuardClient{BaseURL: apiURL, Token: apiToken, Tenant: tenantID}
		return client.GetUser(args[0])
	},
}

var userDeleteCmd = &cobra.Command{
	Use:   "delete [user-id]",
	Short: "Delete a user",
	Long:  "Delete a user from the tenant",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if tenantID == "" {
			return fmt.Errorf("tenant ID is required (use --tenant flag)")
		}
		
		client := &GuardClient{BaseURL: apiURL, Token: apiToken, Tenant: tenantID}
		
		// Confirmation prompt
		fmt.Printf("Are you sure you want to delete user '%s'?\n", args[0])
		fmt.Print("Type 'yes' to confirm: ")
		var confirmation string
		fmt.Scanln(&confirmation)
		
		if confirmation != "yes" {
			fmt.Println("Operation cancelled.")
			return nil
		}
		
		return client.DeleteUser(args[0])
	},
}

func init() {
	userCmd.AddCommand(userListCmd)
	userCmd.AddCommand(userCreateCmd)
	userCmd.AddCommand(userGetCmd)
	userCmd.AddCommand(userDeleteCmd)
	
	// User create flags
	userCreateCmd.Flags().String("first-name", "", "User's first name")
	userCreateCmd.Flags().String("last-name", "", "User's last name")
	userCreateCmd.Flags().Bool("enable-mfa", false, "Enable MFA for the user")
}

// Settings management commands
var settingsCmd = &cobra.Command{
	Use:   "settings",
	Short: "Tenant settings management",
	Long:  "View and update tenant configuration settings",
}

var settingsGetCmd = &cobra.Command{
	Use:   "get",
	Short: "Get tenant settings",
	Long:  "Get all configuration settings for a tenant",
	RunE: func(cmd *cobra.Command, args []string) error {
		if tenantID == "" {
			return fmt.Errorf("tenant ID is required (use --tenant flag)")
		}
		client := &GuardClient{BaseURL: apiURL, Token: apiToken, Tenant: tenantID}
		return client.GetSettings()
	},
}

var settingsSetCmd = &cobra.Command{
	Use:   "set [key] [value]",
	Short: "Set a tenant setting",
	Long:  "Set a specific configuration setting for a tenant",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		if tenantID == "" {
			return fmt.Errorf("tenant ID is required (use --tenant flag)")
		}
		client := &GuardClient{BaseURL: apiURL, Token: apiToken, Tenant: tenantID}
		return client.SetSetting(args[0], args[1])
	},
}

func init() {
	settingsCmd.AddCommand(settingsGetCmd)
	settingsCmd.AddCommand(settingsSetCmd)
}

// Health check commands
var healthCmd = &cobra.Command{
	Use:   "health",
	Short: "Check system health",
	Long:  "Check the health status of the Guard API service",
	RunE: func(cmd *cobra.Command, args []string) error {
		client := &GuardClient{BaseURL: apiURL, Token: apiToken}
		return client.CheckHealth()
	},
}

// Configuration commands
var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Configuration management",
	Long:  "Manage CLI configuration settings",
}

var configInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize configuration",
	Long:  "Initialize CLI configuration with interactive prompts",
	RunE: func(cmd *cobra.Command, args []string) error {
		return initializeConfig()
	},
}

var configShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show current configuration",
	Long:  "Display current CLI configuration settings",
	RunE: func(cmd *cobra.Command, args []string) error {
		return showConfig()
	},
}

func init() {
	configCmd.AddCommand(configInitCmd)
	configCmd.AddCommand(configShowCmd)
}

// Helper functions for configuration
func initializeConfig() error {
	fmt.Println("Guard CLI Configuration Setup")
	fmt.Println("=============================")
	
	var config Config
	
	fmt.Print("Guard API URL [http://localhost:8080]: ")
	var url string
	fmt.Scanln(&url)
	if url == "" {
		url = "http://localhost:8080"
	}
	config.APIURL = url
	
	fmt.Print("API Token: ")
	var token string
	fmt.Scanln(&token)
	config.APIToken = token
	
	fmt.Print("Default Tenant ID (optional): ")
	var tenant string
	fmt.Scanln(&tenant)
	config.TenantID = tenant
	
	// Save configuration
	viper.Set("api_url", config.APIURL)
	viper.Set("api_token", config.APIToken)
	viper.Set("tenant_id", config.TenantID)
	
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %w", err)
	}
	
	configPath := fmt.Sprintf("%s/.guard-cli.yaml", home)
	if err := viper.WriteConfigAs(configPath); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}
	
	fmt.Printf("Configuration saved to %s\n", configPath)
	return nil
}

func showConfig() error {
	fmt.Println("Current Configuration:")
	fmt.Printf("API URL: %s\n", viper.GetString("api_url"))
	fmt.Printf("API Token: %s\n", maskToken(viper.GetString("api_token")))
	fmt.Printf("Default Tenant ID: %s\n", viper.GetString("tenant_id"))
	
	if viper.ConfigFileUsed() != "" {
		fmt.Printf("Config file: %s\n", viper.ConfigFileUsed())
	}
	
	return nil
}

func maskToken(token string) string {
	if len(token) <= 8 {
		return strings.Repeat("*", len(token))
	}
	return token[:4] + strings.Repeat("*", len(token)-8) + token[len(token)-4:]
}

// Output formatting helpers
func formatOutput(data interface{}) error {
	switch outputFmt {
	case "json":
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(data)
	case "yaml":
		// Would need yaml package for proper YAML output
		return json.NewEncoder(os.Stdout).Encode(data)
	default: // table
		return formatTable(data)
	}
}

func formatTable(data interface{}) error {
	// Simple table formatting - would be enhanced with a proper table library
	switch v := data.(type) {
	case map[string]interface{}:
		for key, value := range v {
			fmt.Printf("%-20s: %v\n", key, value)
		}
	case []interface{}:
		for i, item := range v {
			fmt.Printf("%d: %v\n", i+1, item)
		}
	default:
		fmt.Printf("%v\n", data)
	}
	return nil
}

// Utility functions
func envOr(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func envOrBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if parsed, err := strconv.ParseBool(value); err == nil {
			return parsed
		}
	}
	return defaultValue
}

func logVerbose(format string, args ...interface{}) {
	if verbose {
		log.Printf("[VERBOSE] "+format, args...)
	}
}
