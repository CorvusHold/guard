package guard_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	guard "github.com/corvusHold/guard/sdk/go"
)

func TestAdminAndSessionAndBulkRoleMethods(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPatch && r.URL.Path == "/api/v1/auth/admin/users/user-1":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/auth/admin/users/user-1/block":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/auth/admin/users/user-1/unblock":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/auth/sessions/s1/revoke":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/auth/admin/rbac/users/user-1/roles":
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodDelete && r.URL.Path == "/api/v1/auth/admin/rbac/users/user-1/roles":
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := guard.NewGuardClient(server.URL, guard.WithTenantID("tenant-1"))
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	ctx := context.Background()

	name := "John"
	if err := client.UpdateUserNames(ctx, "user-1", guard.UpdateUserNamesRequest{FirstName: &name}); err != nil {
		t.Fatalf("UpdateUserNames: %v", err)
	}
	if err := client.BlockUser(ctx, "user-1"); err != nil {
		t.Fatalf("BlockUser: %v", err)
	}
	if err := client.UnblockUser(ctx, "user-1"); err != nil {
		t.Fatalf("UnblockUser: %v", err)
	}
	if err := client.RevokeSession(ctx, "s1"); err != nil {
		t.Fatalf("RevokeSession: %v", err)
	}
	if err := client.ModifyUserRoles(ctx, "user-1", "tenant-1", []string{"role-1", "role-2"}, "add"); err != nil {
		t.Fatalf("ModifyUserRoles(add): %v", err)
	}
	if err := client.ModifyUserRoles(ctx, "user-1", "tenant-1", []string{"role-1"}, "remove"); err != nil {
		t.Fatalf("ModifyUserRoles(remove): %v", err)
	}
}

func TestBulkRoleAndFGAErrorBranches(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/auth/admin/rbac/users/user-1/roles":
			http.Error(w, "nope", http.StatusBadRequest)
		case r.Method == http.MethodDelete && r.URL.Path == "/api/v1/auth/admin/fga/groups/g1/members":
			http.Error(w, "nope", http.StatusBadRequest)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := guard.NewGuardClient(server.URL, guard.WithTenantID("tenant-1"))
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	ctx := context.Background()

	if err := client.ModifyUserRoles(ctx, "user-1", "tenant-1", []string{"role-1"}, "add"); err == nil {
		t.Fatal("expected ModifyUserRoles status error")
	}
	if err := client.ModifyFGAGroupMembers(ctx, "g1", []string{"u1"}, "remove"); err == nil {
		t.Fatal("expected ModifyFGAGroupMembers status error")
	}
	if err := client.UpdateFGAGroup(ctx, "g1", guard.UpdateFGAGroupRequest{}); err == nil {
		t.Fatal("expected unsupported UpdateFGAGroup error")
	}
}
