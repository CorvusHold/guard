package guard_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	guard "github.com/corvusHold/guard/sdk/go"
)

func TestRBAC_AdminSurfaceMethods(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPatch && r.URL.Path == "/api/v1/auth/admin/rbac/roles/role-1":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodDelete && r.URL.Path == "/api/v1/auth/admin/rbac/roles/role-1":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/auth/admin/rbac/roles/role-1/permissions":
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodDelete && r.URL.Path == "/api/v1/auth/admin/rbac/roles/role-1/permissions":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/auth/admin/rbac/users/user-1/roles":
			_ = json.NewEncoder(w).Encode(map[string]any{"role_ids": []string{"role-1", "role-2"}})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/auth/admin/rbac/users/user-1/roles":
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodDelete && r.URL.Path == "/api/v1/auth/admin/rbac/users/user-1/roles":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/auth/admin/rbac/users/user-1/permissions/resolve":
			_ = json.NewEncoder(w).Encode(map[string]any{"grants": []map[string]any{{"key": "users:read"}}})
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

	name := "Editor"
	desc := "Updated"
	if err := client.UpdateRole(ctx, "role-1", guard.UpdateRoleRequest{Name: &name, Description: &desc}); err != nil {
		t.Fatalf("UpdateRole: %v", err)
	}
	if err := client.DeleteRole(ctx, "role-1"); err != nil {
		t.Fatalf("DeleteRole: %v", err)
	}
	if err := client.UpsertRolePermission(ctx, "role-1", guard.RolePermissionRequest{PermissionKey: "users:read"}); err != nil {
		t.Fatalf("UpsertRolePermission: %v", err)
	}
	if err := client.DeleteRolePermission(ctx, "role-1", "users:read"); err != nil {
		t.Fatalf("DeleteRolePermission: %v", err)
	}
	roles, err := client.ListUserRoles(ctx, "user-1", "tenant-1")
	if err != nil || len(roles) != 2 || roles[0].ID != "role-1" {
		t.Fatalf("ListUserRoles unexpected result: roles=%+v err=%v", roles, err)
	}
	if err := client.AddUserRole(ctx, "user-1", guard.UserRoleRequest{TenantID: "tenant-1", RoleID: "role-1"}); err != nil {
		t.Fatalf("AddUserRole: %v", err)
	}
	if err := client.RemoveUserRole(ctx, "user-1", guard.UserRoleRequest{TenantID: "tenant-1", RoleID: "role-1"}); err != nil {
		t.Fatalf("RemoveUserRole: %v", err)
	}
	perms, err := client.ResolveUserPermissions(ctx, "user-1", "tenant-1")
	if err != nil || len(perms) != 1 || perms[0].Key != "users:read" {
		t.Fatalf("ResolveUserPermissions unexpected result: perms=%+v err=%v", perms, err)
	}
}

func TestFGAAndSSOAndTenantSurfaceMethods(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/auth/admin/fga/groups":
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "g1", "tenant_id": "tenant-1", "name": "Group"})
		case r.Method == http.MethodDelete && r.URL.Path == "/api/v1/auth/admin/fga/groups/g1":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/auth/admin/fga/groups":
			_ = json.NewEncoder(w).Encode(map[string]any{"groups": []map[string]any{{"id": "g1"}}})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/auth/admin/fga/groups/g1/members":
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodDelete && r.URL.Path == "/api/v1/auth/admin/fga/groups/g1/members":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/auth/admin/fga/acl/tuples":
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodDelete && r.URL.Path == "/api/v1/auth/admin/fga/acl/tuples":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/sso/providers/provider-1":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "provider-1", "name": "Main", "provider_type": "oidc"})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/sso/providers":
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "provider-2", "name": "Created", "provider_type": "oidc"})
		case r.Method == http.MethodPut && r.URL.Path == "/api/v1/sso/providers/provider-1":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "provider-1", "name": "Updated", "provider_type": "oidc"})
		case r.Method == http.MethodDelete && r.URL.Path == "/api/v1/sso/providers/provider-1":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/sso/providers/provider-1/test":
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "metadata": map[string]any{"latency_ms": 5}})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/tenants/tenant-1":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "tenant-1", "name": "Acme", "is_active": true})
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

	grp, err := client.CreateFGAGroup(ctx, guard.CreateFGAGroupRequest{Name: "Group"})
	if err != nil || grp.ID != "g1" {
		t.Fatalf("CreateFGAGroup unexpected result: grp=%+v err=%v", grp, err)
	}
	if err := client.DeleteFGAGroup(ctx, "g1"); err != nil {
		t.Fatalf("DeleteFGAGroup: %v", err)
	}
	members, err := client.ListFGAGroupMembers(ctx, "g1")
	if err != nil || len(members) != 0 {
		t.Fatalf("ListFGAGroupMembers unexpected result: members=%+v err=%v", members, err)
	}
	if err := client.AddFGAGroupMember(ctx, "g1", guard.AddFGAGroupMemberRequest{UserID: "u1"}); err != nil {
		t.Fatalf("AddFGAGroupMember: %v", err)
	}
	if err := client.RemoveFGAGroupMember(ctx, "g1", "u1"); err != nil {
		t.Fatalf("RemoveFGAGroupMember: %v", err)
	}
	if err := client.ModifyFGAGroupMembers(ctx, "g1", []string{"u1"}, "add"); err != nil {
		t.Fatalf("ModifyFGAGroupMembers(add): %v", err)
	}
	if err := client.ModifyFGAACLTuples(ctx, []guard.CreateFGAACLTupleRequest{{TenantID: "tenant-1", SubjectType: "user", SubjectID: "u1", PermissionKey: "users:read", ObjectType: "user"}}, "create"); err != nil {
		t.Fatalf("ModifyFGAACLTuples(create): %v", err)
	}
	if err := client.ModifyFGAACLTuples(ctx, []guard.CreateFGAACLTupleRequest{{TenantID: "tenant-1", SubjectType: "user", SubjectID: "u1", PermissionKey: "users:read", ObjectType: "user"}}, "delete"); err != nil {
		t.Fatalf("ModifyFGAACLTuples(delete): %v", err)
	}

	provider, err := client.GetSSOProvider(ctx, "provider-1")
	if err != nil || provider.ID != "provider-1" {
		t.Fatalf("GetSSOProvider unexpected result: provider=%+v err=%v", provider, err)
	}
	created, err := client.CreateSSOProvider(ctx, guard.CreateSSOProviderRequest{TenantID: "tenant-1", Name: "Created", Slug: "created", ProviderType: "oidc"})
	if err != nil || created.ID != "provider-2" {
		t.Fatalf("CreateSSOProvider unexpected result: provider=%+v err=%v", created, err)
	}
	updated, err := client.UpdateSSOProvider(ctx, "provider-1", guard.UpdateSSOProviderRequest{Name: &[]string{"Updated"}[0]})
	if err != nil || updated.Name != "Updated" {
		t.Fatalf("UpdateSSOProvider unexpected result: provider=%+v err=%v", updated, err)
	}
	if err := client.DeleteSSOProvider(ctx, "provider-1"); err != nil {
		t.Fatalf("DeleteSSOProvider: %v", err)
	}
	testResp, err := client.TestSSOProvider(ctx, "provider-1")
	if err != nil || !testResp.Success {
		t.Fatalf("TestSSOProvider unexpected result: resp=%+v err=%v", testResp, err)
	}

	tenant, err := client.GetTenant(ctx, "")
	if err != nil || tenant.ID != "tenant-1" {
		t.Fatalf("GetTenant unexpected result: tenant=%+v err=%v", tenant, err)
	}
}
