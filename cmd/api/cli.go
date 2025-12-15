package main

import (
	"database/sql"
	"fmt"
	"os"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/corvusHold/guard/internal/config"
)

const (
	exitOK      = 0
	exitUsage   = 2
	exitConfig  = 3
	exitMigrate = 4
)

var (
	migrateRunner = realMigrateRunner
	osExit        = os.Exit
)

func handleCLICommand(args []string) bool {
	if len(args) == 0 {
		return false
	}
	switch args[0] {
	case "migrate":
		code := runMigrate(args[1:])
		osExit(code)
		return true
	case "help", "-h", "--help":
		printHelp()
		osExit(exitOK)
		return true
	default:
		return false
	}
}

func runMigrate(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "missing migrate subcommand (up|down|status)")
		return exitUsage
	}
	subcmd := args[0]
	switch subcmd {
	case "up", "down", "status":
	default:
		fmt.Fprintf(os.Stderr, "unknown migrate subcommand: %s\n", subcmd)
		return exitUsage
	}

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		return exitConfig
	}

	if migrateRunner == nil {
		migrateRunner = realMigrateRunner
	}

	if err := migrateRunner(subcmd, cfg.DatabaseURL); err != nil {
		fmt.Fprintf(os.Stderr, "migrate %s failed: %v\n", subcmd, err)
		return exitMigrate
	}

	return exitOK
}

func realMigrateRunner(subcmd, databaseURL string) error {
	if databaseURL == "" {
		return fmt.Errorf("DATABASE_URL is empty")
	}

	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return err
	}
	defer func() {
		_ = db.Close()
	}()

	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("set goose dialect: %w", err)
	}
	const migrationsDir = "./migrations"

	switch subcmd {
	case "up":
		return goose.Up(db, migrationsDir)
	case "down":
		return goose.Down(db, migrationsDir)
	case "status":
		return goose.Status(db, migrationsDir)
	default:
		return fmt.Errorf("unsupported migrate subcommand %q", subcmd)
	}
}

func printHelp() {
	fmt.Println("Guard CLI")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  guard                 Start API server")
	fmt.Println("  guard migrate up      Apply all pending migrations")
	fmt.Println("  guard migrate down    Roll back one migration")
	fmt.Println("  guard migrate status  Show migration status")
}
