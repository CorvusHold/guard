package main

import (
	"context"
	"os/exec"
	"os"
	"testing"
	"time"
	"strings"

	authrepo "github.com/corvusHold/guard/internal/auth/repository"
	trepo "github.com/corvusHold/guard/internal/tenants/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestCLI_UserRolesFlag_UpdatesRoles(t *testing.T) {
	if os.Getenv("DATABASE_URL") == "" {
		t.Skip("skipping CLI integration test: DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil { t.Fatalf("db connect: %v", err) }
	defer pool.Close()

	// Create tenant directly using repo
	tr := trepo.New(pool)
	tenantID := uuid.New()
	name := "cli-user-roles-itest-" + tenantID.String()
	if err := tr.Create(ctx, tenantID, name); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	time.Sleep(25 * time.Millisecond)

	repo := authrepo.New(pool)

	email := "cli.roles." + tenantID.String() + "@example.com"
	password := "Password!123"

	// Run the seed CLI to create/update user with roles, using intentionally messy roles to test normalization
	cmd := exec.Command("go", "run", ".", "user", "--tenant-id", tenantID.String(), "--email", email, "--password", password, "--roles", "Admin, member,ADMIN,,member ")
    // Run from the current package directory (this test resides in cmd/seed)
    cmd.Dir = "."
    cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("seed user failed: %v\n%s", err, string(out))
	}

	// Verify roles via repository
	ai, err := repo.GetAuthIdentityByEmailTenant(ctx, tenantID, strings.ToLower(email))
	if err != nil { t.Fatalf("lookup identity: %v", err) }
	u, err := repo.GetUserByID(ctx, ai.UserID)
	if err != nil { t.Fatalf("get user: %v", err) }
	if len(u.Roles) != 2 { t.Fatalf("expected 2 roles, got %v", u.Roles) }
	if !contains(u.Roles, "admin") || !contains(u.Roles, "member") {
        t.Fatalf("roles mismatch, expected [admin member], got %v", u.Roles)
    }
}

func contains(ss []string, v string) bool {
	for _, s := range ss { if s == v { return true } }
	return false
}
