package main

import (
	"errors"
	"os"
	"testing"
)

func TestRunMigrate_HappyUp(t *testing.T) {
	origRunner := migrateRunner
	defer func() { migrateRunner = origRunner }()

	called := false
	var gotSubcmd string
	var gotURL string
	migrateRunner = func(subcmd, databaseURL string) error {
		called = true
		gotSubcmd = subcmd
		gotURL = databaseURL
		return nil
	}

	// Ensure DATABASE_URL is non-empty (config.Load has a default, but be explicit)
	origEnv := os.Getenv("DATABASE_URL")
	defer os.Setenv("DATABASE_URL", origEnv)
	if origEnv == "" {
		_ = os.Setenv("DATABASE_URL", "postgres://guard:guard@localhost:5433/guard?sslmode=disable")
	}

	code := runMigrate([]string{"up"})
	if code != exitOK {
		t.Fatalf("expected exitOK (%d), got %d", exitOK, code)
	}
	if !called {
		t.Fatalf("expected migrateRunner to be called")
	}
	if gotSubcmd != "up" {
		t.Fatalf("expected subcmd 'up', got %q", gotSubcmd)
	}
	if gotURL == "" {
		t.Fatalf("expected non-empty database URL")
	}
}

func TestRunMigrate_MissingSubcommand(t *testing.T) {
	code := runMigrate(nil)
	if code != exitUsage {
		t.Fatalf("expected exitUsage (%d), got %d", exitUsage, code)
	}
}

func TestRunMigrate_UnknownSubcommand(t *testing.T) {
	code := runMigrate([]string{"foo"})
	if code != exitUsage {
		t.Fatalf("expected exitUsage (%d), got %d", exitUsage, code)
	}
}

func TestRunMigrate_RunnerError(t *testing.T) {
	origRunner := migrateRunner
	defer func() { migrateRunner = origRunner }()

	migrateRunner = func(subcmd, databaseURL string) error {
		return errors.New("boom")
	}

	code := runMigrate([]string{"up"})
	if code != exitMigrate {
		t.Fatalf("expected exitMigrate (%d), got %d", exitMigrate, code)
	}
}

func TestRealMigrateRunner_EmptyURL(t *testing.T) {
	if err := realMigrateRunner("up", ""); err == nil {
		t.Fatalf("expected error for empty DATABASE_URL, got nil")
	}
}

func TestHandleCLICommand_NoArgs(t *testing.T) {
	origExit := osExit
	defer func() { osExit = origExit }()

	calledExit := false
	osExit = func(code int) { calledExit = true }

	if handled := handleCLICommand(nil); handled {
		t.Fatalf("expected handled=false for no args")
	}
	if calledExit {
		t.Fatalf("expected osExit not to be called")
	}
}

func TestHandleCLICommand_NonMigrate(t *testing.T) {
	origExit := osExit
	defer func() { osExit = origExit }()

	calledExit := false
	osExit = func(code int) { calledExit = true }

	if handled := handleCLICommand([]string{"server"}); handled {
		t.Fatalf("expected handled=false for non-migrate command")
	}
	if calledExit {
		t.Fatalf("expected osExit not to be called")
	}
}

func TestHandleCLICommand_MigrateUp(t *testing.T) {
	origExit := osExit
	origRunner := migrateRunner
	defer func() { osExit = origExit; migrateRunner = origRunner }()

	calledExit := false
	var exitCode int
	osExit = func(code int) {
		calledExit = true
		exitCode = code
	}

	calledRunner := false
	var gotSubcmd string
	migrateRunner = func(subcmd, databaseURL string) error {
		calledRunner = true
		gotSubcmd = subcmd
		return nil
	}

	handled := handleCLICommand([]string{"migrate", "up"})
	if !handled {
		t.Fatalf("expected handled=true for migrate command")
	}
	if !calledRunner {
		t.Fatalf("expected migrateRunner to be called")
	}
	if gotSubcmd != "up" {
		t.Fatalf("expected subcmd 'up', got %q", gotSubcmd)
	}
	if !calledExit {
		t.Fatalf("expected osExit to be called")
	}
	if exitCode != exitOK {
		t.Fatalf("expected osExit called with exitOK (%d), got %d", exitOK, exitCode)
	}
}

func TestHandleCLICommand_Help(t *testing.T) {
	origExit := osExit
	defer func() { osExit = origExit }()

	calledExit := false
	var exitCode int
	osExit = func(code int) {
		calledExit = true
		exitCode = code
	}

	handled := handleCLICommand([]string{"help"})
	if !handled {
		t.Fatalf("expected handled=true for help command")
	}
	if !calledExit {
		t.Fatalf("expected osExit to be called for help command")
	}
	if exitCode != exitOK {
		t.Fatalf("expected osExit called with exitOK (%d), got %d", exitOK, exitCode)
	}
}
