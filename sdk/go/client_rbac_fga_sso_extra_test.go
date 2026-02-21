package guard_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	guard "github.com/corvusHold/guard/sdk/go"
)

func TestModifyUserRoles_InvalidAction(t *testing.T) {
	client, err := guard.NewGuardClient("http://localhost:8080")
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	if err := client.ModifyUserRoles(context.Background(), "u1", "t1", []string{"r1"}, "noop"); err == nil {
		t.Fatal("expected invalid action error")
	}
}

func TestGetUserRoleObjects_MapsAssignedRoleIDsToRoleObjects(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/auth/admin/rbac/users/user-1/roles":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"role_ids": []string{"role-a"}})
		case "/api/v1/auth/admin/rbac/roles":
			if got := r.URL.Query().Get("tenant_id"); got != "tenant-1" {
				t.Fatalf("expected tenant_id tenant-1, got %q", got)
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"roles": []map[string]any{{"id": "role-a", "name": "Admin"}, {"id": "role-b", "name": "Viewer"}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := guard.NewGuardClient(server.URL, guard.WithTenantID("tenant-1"))
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	roles, err := client.GetUserRoleObjects(context.Background(), "user-1", "tenant-1")
	if err != nil {
		t.Fatalf("GetUserRoleObjects failed: %v", err)
	}
	if len(roles) != 1 || roles[0].ID != "role-a" || roles[0].Name != "Admin" {
		t.Fatalf("unexpected mapped roles: %+v", roles)
	}
}

func TestFGA_BulkActionValidationAndDeleteLimitation(t *testing.T) {
	client, err := guard.NewGuardClient("http://localhost:8080")
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	if err := client.ModifyFGAGroupMembers(context.Background(), "g1", []string{"u1"}, "noop"); err == nil {
		t.Fatal("expected invalid action error for ModifyFGAGroupMembers")
	}
	if err := client.ModifyFGAACLTuples(context.Background(), nil, "noop"); err == nil {
		t.Fatal("expected invalid action error for ModifyFGAACLTuples")
	}
	if err := client.DeleteFGAACLTuple(context.Background(), "tuple-1"); err == nil || !strings.Contains(err.Error(), "requires full ACL tuple details") {
		t.Fatalf("expected delete limitation error, got %v", err)
	}

	tuples, err := client.ListFGAACLTuples(context.Background(), "tenant-1")
	if err != nil {
		t.Fatalf("ListFGAACLTuples error: %v", err)
	}
	if len(tuples) != 0 {
		t.Fatalf("expected empty tuple list from placeholder implementation, got %+v", tuples)
	}
}

func TestListSSOProviders_WithoutProvidersKeyReturnsEmptyList(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/sso/providers" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	}))
	defer server.Close()

	client, err := guard.NewGuardClient(server.URL)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	providers, err := client.ListSSOProviders(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListSSOProviders failed: %v", err)
	}
	if len(providers) != 0 {
		t.Fatalf("expected empty providers list when providers key missing, got %+v", providers)
	}
}
