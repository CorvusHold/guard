package controller

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	adomain "github.com/corvusHold/guard/internal/auth/domain"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

type rbacPermSvcStub struct {
	adomain.Service

	introspection adomain.Introspection
	introspectErr error

	upsertErr error
	deleteErr error

	resolveOut adomain.ResolvedPermissions
	resolveErr error

	listPermsOut []adomain.Permission
	listPermsErr error

	listRolesOut []adomain.Role
	listRolesErr error

	createRoleOut adomain.Role
	createRoleErr error

	updateRoleOut adomain.Role
	updateRoleErr error
	deleteRoleErr error

	listUserRolesOut  []adomain.Role
	listUserRolesErr  error
	addUserRoleErr    error
	removeUserRoleErr error
}

func (s *rbacPermSvcStub) Introspect(context.Context, string) (adomain.Introspection, error) {
	if s.introspectErr != nil {
		return adomain.Introspection{}, s.introspectErr
	}
	return s.introspection, nil
}

func (s *rbacPermSvcStub) UpsertRolePermission(context.Context, uuid.UUID, string, string, *string, *string) error {
	return s.upsertErr
}
func (s *rbacPermSvcStub) DeleteRolePermission(context.Context, uuid.UUID, string, string, *string, *string) error {
	return s.deleteErr
}
func (s *rbacPermSvcStub) ResolveUserPermissions(context.Context, uuid.UUID, uuid.UUID) (adomain.ResolvedPermissions, error) {
	if s.resolveErr != nil {
		return adomain.ResolvedPermissions{}, s.resolveErr
	}
	return s.resolveOut, nil
}

func (s *rbacPermSvcStub) ListPermissions(context.Context) ([]adomain.Permission, error) {
	if s.listPermsErr != nil {
		return nil, s.listPermsErr
	}
	return s.listPermsOut, nil
}

func (s *rbacPermSvcStub) ListRoles(context.Context, uuid.UUID) ([]adomain.Role, error) {
	if s.listRolesErr != nil {
		return nil, s.listRolesErr
	}
	return s.listRolesOut, nil
}

func (s *rbacPermSvcStub) CreateRole(context.Context, uuid.UUID, string, string) (adomain.Role, error) {
	if s.createRoleErr != nil {
		return adomain.Role{}, s.createRoleErr
	}
	return s.createRoleOut, nil
}

func (s *rbacPermSvcStub) UpdateRole(context.Context, uuid.UUID, uuid.UUID, string, string) (adomain.Role, error) {
	if s.updateRoleErr != nil {
		return adomain.Role{}, s.updateRoleErr
	}
	return s.updateRoleOut, nil
}

func (s *rbacPermSvcStub) DeleteRole(context.Context, uuid.UUID, uuid.UUID) error {
	return s.deleteRoleErr
}

func (s *rbacPermSvcStub) ListUserRoles(context.Context, uuid.UUID, uuid.UUID) ([]adomain.Role, error) {
	if s.listUserRolesErr != nil {
		return nil, s.listUserRolesErr
	}
	return s.listUserRolesOut, nil
}

func (s *rbacPermSvcStub) AddUserRole(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) error {
	return s.addUserRoleErr
}

func (s *rbacPermSvcStub) RemoveUserRole(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) error {
	return s.removeUserRoleErr
}

func TestRBACPermissionHandlers_ExtraBranches(t *testing.T) {
	e := echo.New()
	e.Validator = noopValidator{}
	tenantID := uuid.New()
	svc := &rbacPermSvcStub{introspection: adomain.Introspection{Active: true, UserID: uuid.New(), TenantID: tenantID, Roles: []string{"admin"}}}
	h := &Controller{svc: svc}
	auth := "Bearer token"

	t.Run("rbacListPermissions, listRoles, createRole branches", func(t *testing.T) {
		svc.listPermsErr = errors.New("list permissions failed")
		reqPermErr := httptest.NewRequest(http.MethodGet, "/api/v1/auth/admin/rbac/permissions", nil)
		reqPermErr.Header.Set("Authorization", auth)
		recPermErr := httptest.NewRecorder()
		cPermErr := e.NewContext(reqPermErr, recPermErr)
		if err := h.rbacListPermissions(cPermErr); err != nil {
			t.Fatalf("rbacListPermissions returned err=%v", err)
		}
		if recPermErr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 list permissions error, got %d", recPermErr.Code)
		}

		svc.listPermsErr = nil
		svc.listPermsOut = []adomain.Permission{{ID: uuid.New(), Key: "users:read"}}
		reqPermOK := httptest.NewRequest(http.MethodGet, "/api/v1/auth/admin/rbac/permissions", nil)
		reqPermOK.Header.Set("Authorization", auth)
		recPermOK := httptest.NewRecorder()
		cPermOK := e.NewContext(reqPermOK, recPermOK)
		if err := h.rbacListPermissions(cPermOK); err != nil {
			t.Fatalf("rbacListPermissions returned err=%v", err)
		}
		if recPermOK.Code != http.StatusOK {
			t.Fatalf("expected 200 list permissions success, got %d", recPermOK.Code)
		}

		reqRolesMissingTenant := httptest.NewRequest(http.MethodGet, "/api/v1/auth/admin/rbac/roles", nil)
		reqRolesMissingTenant.Header.Set("Authorization", auth)
		recRolesMissingTenant := httptest.NewRecorder()
		cRolesMissingTenant := e.NewContext(reqRolesMissingTenant, recRolesMissingTenant)
		if err := h.rbacListRoles(cRolesMissingTenant); err != nil {
			t.Fatalf("rbacListRoles returned err=%v", err)
		}
		if recRolesMissingTenant.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 missing tenant_id, got %d", recRolesMissingTenant.Code)
		}

		svc.listRolesErr = errors.New("list roles failed")
		reqRolesErr := httptest.NewRequest(http.MethodGet, "/api/v1/auth/admin/rbac/roles?tenant_id="+tenantID.String(), nil)
		reqRolesErr.Header.Set("Authorization", auth)
		recRolesErr := httptest.NewRecorder()
		cRolesErr := e.NewContext(reqRolesErr, recRolesErr)
		if err := h.rbacListRoles(cRolesErr); err != nil {
			t.Fatalf("rbacListRoles returned err=%v", err)
		}
		if recRolesErr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 list roles error, got %d", recRolesErr.Code)
		}

		svc.listRolesErr = nil
		svc.listRolesOut = []adomain.Role{{ID: uuid.New(), TenantID: tenantID, Name: "admin"}}
		reqRolesOK := httptest.NewRequest(http.MethodGet, "/api/v1/auth/admin/rbac/roles?tenant_id="+tenantID.String(), nil)
		reqRolesOK.Header.Set("Authorization", auth)
		recRolesOK := httptest.NewRecorder()
		cRolesOK := e.NewContext(reqRolesOK, recRolesOK)
		if err := h.rbacListRoles(cRolesOK); err != nil {
			t.Fatalf("rbacListRoles returned err=%v", err)
		}
		if recRolesOK.Code != http.StatusOK {
			t.Fatalf("expected 200 list roles success, got %d", recRolesOK.Code)
		}

		reqCreateBadJSON := httptest.NewRequest(http.MethodPost, "/api/v1/auth/admin/rbac/roles", bytes.NewBufferString("{"))
		reqCreateBadJSON.Header.Set("Authorization", auth)
		reqCreateBadJSON.Header.Set("Content-Type", "application/json")
		recCreateBadJSON := httptest.NewRecorder()
		cCreateBadJSON := e.NewContext(reqCreateBadJSON, recCreateBadJSON)
		if err := h.rbacCreateRole(cCreateBadJSON); err != nil {
			t.Fatalf("rbacCreateRole returned err=%v", err)
		}
		if recCreateBadJSON.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 invalid json, got %d", recCreateBadJSON.Code)
		}

		svc.createRoleErr = errors.New("create role failed")
		reqCreateErr := httptest.NewRequest(http.MethodPost, "/api/v1/auth/admin/rbac/roles", bytes.NewBufferString(`{"tenant_id":"`+tenantID.String()+`","name":"editor"}`))
		reqCreateErr.Header.Set("Authorization", auth)
		reqCreateErr.Header.Set("Content-Type", "application/json")
		recCreateErr := httptest.NewRecorder()
		cCreateErr := e.NewContext(reqCreateErr, recCreateErr)
		if err := h.rbacCreateRole(cCreateErr); err != nil {
			t.Fatalf("rbacCreateRole returned err=%v", err)
		}
		if recCreateErr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 create role error, got %d", recCreateErr.Code)
		}

		svc.createRoleErr = nil
		svc.createRoleOut = adomain.Role{ID: uuid.New(), TenantID: tenantID, Name: "editor"}
		reqCreateOK := httptest.NewRequest(http.MethodPost, "/api/v1/auth/admin/rbac/roles", bytes.NewBufferString(`{"tenant_id":"`+tenantID.String()+`","name":"editor"}`))
		reqCreateOK.Header.Set("Authorization", auth)
		reqCreateOK.Header.Set("Content-Type", "application/json")
		recCreateOK := httptest.NewRecorder()
		cCreateOK := e.NewContext(reqCreateOK, recCreateOK)
		if err := h.rbacCreateRole(cCreateOK); err != nil {
			t.Fatalf("rbacCreateRole returned err=%v", err)
		}
		if recCreateOK.Code != http.StatusCreated {
			t.Fatalf("expected 201 create role success, got %d", recCreateOK.Code)
		}
	})

	t.Run("rbacUpdateDeleteAndUserRoleHandlers branches", func(t *testing.T) {
		roleID := uuid.New()
		userID := uuid.New()

		svc.updateRoleErr = errors.New("update role failed")
		reqUpdErr := httptest.NewRequest(http.MethodPatch, "/api/v1/auth/admin/rbac/roles/"+roleID.String(), bytes.NewBufferString(`{"tenant_id":"`+tenantID.String()+`","name":"editor"}`))
		reqUpdErr.Header.Set("Authorization", auth)
		reqUpdErr.Header.Set("Content-Type", "application/json")
		recUpdErr := httptest.NewRecorder()
		cUpdErr := e.NewContext(reqUpdErr, recUpdErr)
		cUpdErr.SetParamNames("id")
		cUpdErr.SetParamValues(roleID.String())
		if err := h.rbacUpdateRole(cUpdErr); err != nil {
			t.Fatalf("rbacUpdateRole returned err=%v", err)
		}
		if recUpdErr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 update role error, got %d", recUpdErr.Code)
		}

		svc.updateRoleErr = nil
		svc.updateRoleOut = adomain.Role{ID: roleID, TenantID: tenantID, Name: "editor"}
		reqUpdOK := httptest.NewRequest(http.MethodPatch, "/api/v1/auth/admin/rbac/roles/"+roleID.String(), bytes.NewBufferString(`{"tenant_id":"`+tenantID.String()+`","name":"editor"}`))
		reqUpdOK.Header.Set("Authorization", auth)
		reqUpdOK.Header.Set("Content-Type", "application/json")
		recUpdOK := httptest.NewRecorder()
		cUpdOK := e.NewContext(reqUpdOK, recUpdOK)
		cUpdOK.SetParamNames("id")
		cUpdOK.SetParamValues(roleID.String())
		if err := h.rbacUpdateRole(cUpdOK); err != nil {
			t.Fatalf("rbacUpdateRole returned err=%v", err)
		}
		if recUpdOK.Code != http.StatusOK {
			t.Fatalf("expected 200 update role success, got %d", recUpdOK.Code)
		}

		svc.deleteRoleErr = errors.New("delete role failed")
		reqDelErr := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/admin/rbac/roles/"+roleID.String()+"?tenant_id="+tenantID.String(), nil)
		reqDelErr.Header.Set("Authorization", auth)
		recDelErr := httptest.NewRecorder()
		cDelErr := e.NewContext(reqDelErr, recDelErr)
		cDelErr.SetParamNames("id")
		cDelErr.SetParamValues(roleID.String())
		if err := h.rbacDeleteRole(cDelErr); err != nil {
			t.Fatalf("rbacDeleteRole returned err=%v", err)
		}
		if recDelErr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 delete role error, got %d", recDelErr.Code)
		}

		svc.deleteRoleErr = nil
		reqDelOK := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/admin/rbac/roles/"+roleID.String()+"?tenant_id="+tenantID.String(), nil)
		reqDelOK.Header.Set("Authorization", auth)
		recDelOK := httptest.NewRecorder()
		cDelOK := e.NewContext(reqDelOK, recDelOK)
		cDelOK.SetParamNames("id")
		cDelOK.SetParamValues(roleID.String())
		if err := h.rbacDeleteRole(cDelOK); err != nil {
			t.Fatalf("rbacDeleteRole returned err=%v", err)
		}
		if recDelOK.Code != http.StatusNoContent {
			t.Fatalf("expected 204 delete role success, got %d", recDelOK.Code)
		}

		svc.listUserRolesErr = errors.New("list user roles failed")
		reqListUserRolesErr := httptest.NewRequest(http.MethodGet, "/api/v1/auth/admin/rbac/users/"+userID.String()+"/roles?tenant_id="+tenantID.String(), nil)
		reqListUserRolesErr.Header.Set("Authorization", auth)
		recListUserRolesErr := httptest.NewRecorder()
		cListUserRolesErr := e.NewContext(reqListUserRolesErr, recListUserRolesErr)
		cListUserRolesErr.SetParamNames("id")
		cListUserRolesErr.SetParamValues(userID.String())
		if err := h.rbacListUserRoles(cListUserRolesErr); err != nil {
			t.Fatalf("rbacListUserRoles returned err=%v", err)
		}
		if recListUserRolesErr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 list user roles error, got %d", recListUserRolesErr.Code)
		}

		svc.listUserRolesErr = nil
		svc.listUserRolesOut = []adomain.Role{{ID: roleID, TenantID: tenantID, Name: "editor"}}
		reqListUserRolesOK := httptest.NewRequest(http.MethodGet, "/api/v1/auth/admin/rbac/users/"+userID.String()+"/roles?tenant_id="+tenantID.String(), nil)
		reqListUserRolesOK.Header.Set("Authorization", auth)
		recListUserRolesOK := httptest.NewRecorder()
		cListUserRolesOK := e.NewContext(reqListUserRolesOK, recListUserRolesOK)
		cListUserRolesOK.SetParamNames("id")
		cListUserRolesOK.SetParamValues(userID.String())
		if err := h.rbacListUserRoles(cListUserRolesOK); err != nil {
			t.Fatalf("rbacListUserRoles returned err=%v", err)
		}
		if recListUserRolesOK.Code != http.StatusOK {
			t.Fatalf("expected 200 list user roles success, got %d", recListUserRolesOK.Code)
		}

		svc.addUserRoleErr = errors.New("add user role failed")
		reqAddErr := httptest.NewRequest(http.MethodPost, "/api/v1/auth/admin/rbac/users/"+userID.String()+"/roles", bytes.NewBufferString(`{"tenant_id":"`+tenantID.String()+`","role_id":"`+roleID.String()+`"}`))
		reqAddErr.Header.Set("Authorization", auth)
		reqAddErr.Header.Set("Content-Type", "application/json")
		recAddErr := httptest.NewRecorder()
		cAddErr := e.NewContext(reqAddErr, recAddErr)
		cAddErr.SetParamNames("id")
		cAddErr.SetParamValues(userID.String())
		if err := h.rbacAddUserRole(cAddErr); err != nil {
			t.Fatalf("rbacAddUserRole returned err=%v", err)
		}
		if recAddErr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 add user role error, got %d", recAddErr.Code)
		}

		svc.addUserRoleErr = nil
		reqAddOK := httptest.NewRequest(http.MethodPost, "/api/v1/auth/admin/rbac/users/"+userID.String()+"/roles", bytes.NewBufferString(`{"tenant_id":"`+tenantID.String()+`","role_id":"`+roleID.String()+`"}`))
		reqAddOK.Header.Set("Authorization", auth)
		reqAddOK.Header.Set("Content-Type", "application/json")
		recAddOK := httptest.NewRecorder()
		cAddOK := e.NewContext(reqAddOK, recAddOK)
		cAddOK.SetParamNames("id")
		cAddOK.SetParamValues(userID.String())
		if err := h.rbacAddUserRole(cAddOK); err != nil {
			t.Fatalf("rbacAddUserRole returned err=%v", err)
		}
		if recAddOK.Code != http.StatusNoContent {
			t.Fatalf("expected 204 add user role success, got %d", recAddOK.Code)
		}

		svc.removeUserRoleErr = errors.New("remove user role failed")
		reqRemErr := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/admin/rbac/users/"+userID.String()+"/roles", bytes.NewBufferString(`{"tenant_id":"`+tenantID.String()+`","role_id":"`+roleID.String()+`"}`))
		reqRemErr.Header.Set("Authorization", auth)
		reqRemErr.Header.Set("Content-Type", "application/json")
		recRemErr := httptest.NewRecorder()
		cRemErr := e.NewContext(reqRemErr, recRemErr)
		cRemErr.SetParamNames("id")
		cRemErr.SetParamValues(userID.String())
		if err := h.rbacRemoveUserRole(cRemErr); err != nil {
			t.Fatalf("rbacRemoveUserRole returned err=%v", err)
		}
		if recRemErr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 remove user role error, got %d", recRemErr.Code)
		}

		svc.removeUserRoleErr = nil
		reqRemOK := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/admin/rbac/users/"+userID.String()+"/roles", bytes.NewBufferString(`{"tenant_id":"`+tenantID.String()+`","role_id":"`+roleID.String()+`"}`))
		reqRemOK.Header.Set("Authorization", auth)
		reqRemOK.Header.Set("Content-Type", "application/json")
		recRemOK := httptest.NewRecorder()
		cRemOK := e.NewContext(reqRemOK, recRemOK)
		cRemOK.SetParamNames("id")
		cRemOK.SetParamValues(userID.String())
		if err := h.rbacRemoveUserRole(cRemOK); err != nil {
			t.Fatalf("rbacRemoveUserRole returned err=%v", err)
		}
		if recRemOK.Code != http.StatusNoContent {
			t.Fatalf("expected 204 remove user role success, got %d", recRemOK.Code)
		}
	})

	t.Run("rbacUpsertRolePermission branches", func(t *testing.T) {
		reqBadRole := httptest.NewRequest(http.MethodPost, "/api/v1/auth/admin/rbac/roles/bad/permissions", bytes.NewBufferString(`{"permission_key":"users:read","scope_type":"tenant"}`))
		reqBadRole.Header.Set("Authorization", auth)
		reqBadRole.Header.Set("Content-Type", "application/json")
		recBadRole := httptest.NewRecorder()
		cBadRole := e.NewContext(reqBadRole, recBadRole)
		cBadRole.SetParamNames("id")
		cBadRole.SetParamValues("bad")
		if err := h.rbacUpsertRolePermission(cBadRole); err != nil {
			t.Fatalf("rbacUpsertRolePermission returned err=%v", err)
		}
		if recBadRole.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 invalid role id, got %d", recBadRole.Code)
		}

		svc.upsertErr = errors.New("upsert failed")
		roleID := uuid.New()
		reqErr := httptest.NewRequest(http.MethodPost, "/api/v1/auth/admin/rbac/roles/"+roleID.String()+"/permissions", bytes.NewBufferString(`{"permission_key":"users:read","scope_type":"tenant","resource_type":"doc","resource_id":"1"}`))
		reqErr.Header.Set("Authorization", auth)
		reqErr.Header.Set("Content-Type", "application/json")
		recErr := httptest.NewRecorder()
		cErr := e.NewContext(reqErr, recErr)
		cErr.SetParamNames("id")
		cErr.SetParamValues(roleID.String())
		if err := h.rbacUpsertRolePermission(cErr); err != nil {
			t.Fatalf("rbacUpsertRolePermission returned err=%v", err)
		}
		if recErr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 upsert error, got %d", recErr.Code)
		}

		svc.upsertErr = nil
		reqOK := httptest.NewRequest(http.MethodPost, "/api/v1/auth/admin/rbac/roles/"+roleID.String()+"/permissions", bytes.NewBufferString(`{"permission_key":"users:read","scope_type":"tenant"}`))
		reqOK.Header.Set("Authorization", auth)
		reqOK.Header.Set("Content-Type", "application/json")
		recOK := httptest.NewRecorder()
		cOK := e.NewContext(reqOK, recOK)
		cOK.SetParamNames("id")
		cOK.SetParamValues(roleID.String())
		if err := h.rbacUpsertRolePermission(cOK); err != nil {
			t.Fatalf("rbacUpsertRolePermission returned err=%v", err)
		}
		if recOK.Code != http.StatusNoContent {
			t.Fatalf("expected 204 upsert success, got %d", recOK.Code)
		}
	})

	t.Run("rbacDeleteRolePermission branches", func(t *testing.T) {
		reqBadRole := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/admin/rbac/roles/bad/permissions", bytes.NewBufferString(`{"permission_key":"users:read","scope_type":"tenant"}`))
		reqBadRole.Header.Set("Authorization", auth)
		reqBadRole.Header.Set("Content-Type", "application/json")
		recBadRole := httptest.NewRecorder()
		cBadRole := e.NewContext(reqBadRole, recBadRole)
		cBadRole.SetParamNames("id")
		cBadRole.SetParamValues("bad")
		if err := h.rbacDeleteRolePermission(cBadRole); err != nil {
			t.Fatalf("rbacDeleteRolePermission returned err=%v", err)
		}
		if recBadRole.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 invalid role id, got %d", recBadRole.Code)
		}

		svc.deleteErr = errors.New("delete failed")
		roleID := uuid.New()
		reqErr := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/admin/rbac/roles/"+roleID.String()+"/permissions", bytes.NewBufferString(`{"permission_key":"users:read","scope_type":"tenant"}`))
		reqErr.Header.Set("Authorization", auth)
		reqErr.Header.Set("Content-Type", "application/json")
		recErr := httptest.NewRecorder()
		cErr := e.NewContext(reqErr, recErr)
		cErr.SetParamNames("id")
		cErr.SetParamValues(roleID.String())
		if err := h.rbacDeleteRolePermission(cErr); err != nil {
			t.Fatalf("rbacDeleteRolePermission returned err=%v", err)
		}
		if recErr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 delete error, got %d", recErr.Code)
		}

		svc.deleteErr = nil
		reqOK := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/admin/rbac/roles/"+roleID.String()+"/permissions", bytes.NewBufferString(`{"permission_key":"users:read","scope_type":"tenant"}`))
		reqOK.Header.Set("Authorization", auth)
		reqOK.Header.Set("Content-Type", "application/json")
		recOK := httptest.NewRecorder()
		cOK := e.NewContext(reqOK, recOK)
		cOK.SetParamNames("id")
		cOK.SetParamValues(roleID.String())
		if err := h.rbacDeleteRolePermission(cOK); err != nil {
			t.Fatalf("rbacDeleteRolePermission returned err=%v", err)
		}
		if recOK.Code != http.StatusNoContent {
			t.Fatalf("expected 204 delete success, got %d", recOK.Code)
		}

		// Optional resource scope branch
		reqScoped := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/admin/rbac/roles/"+roleID.String()+"/permissions", bytes.NewBufferString(`{"permission_key":"users:read","scope_type":"resource","resource_type":"document","resource_id":"abc"}`))
		reqScoped.Header.Set("Authorization", auth)
		reqScoped.Header.Set("Content-Type", "application/json")
		recScoped := httptest.NewRecorder()
		cScoped := e.NewContext(reqScoped, recScoped)
		cScoped.SetParamNames("id")
		cScoped.SetParamValues(roleID.String())
		if err := h.rbacDeleteRolePermission(cScoped); err != nil {
			t.Fatalf("rbacDeleteRolePermission returned err=%v", err)
		}
		if recScoped.Code != http.StatusNoContent {
			t.Fatalf("expected 204 scoped delete success, got %d", recScoped.Code)
		}
	})

	t.Run("rbacResolveUserPermissions branches", func(t *testing.T) {
		reqBadUser := httptest.NewRequest(http.MethodGet, "/api/v1/auth/admin/rbac/users/bad/permissions/resolve?tenant_id="+tenantID.String(), nil)
		reqBadUser.Header.Set("Authorization", auth)
		recBadUser := httptest.NewRecorder()
		cBadUser := e.NewContext(reqBadUser, recBadUser)
		cBadUser.SetParamNames("id")
		cBadUser.SetParamValues("bad")
		if err := h.rbacResolveUserPermissions(cBadUser); err != nil {
			t.Fatalf("rbacResolveUserPermissions returned err=%v", err)
		}
		if recBadUser.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 invalid user id, got %d", recBadUser.Code)
		}

		reqNoTenant := httptest.NewRequest(http.MethodGet, "/api/v1/auth/admin/rbac/users/"+uuid.New().String()+"/permissions/resolve", nil)
		reqNoTenant.Header.Set("Authorization", auth)
		recNoTenant := httptest.NewRecorder()
		cNoTenant := e.NewContext(reqNoTenant, recNoTenant)
		cNoTenant.SetParamNames("id")
		cNoTenant.SetParamValues(uuid.New().String())
		if err := h.rbacResolveUserPermissions(cNoTenant); err != nil {
			t.Fatalf("rbacResolveUserPermissions returned err=%v", err)
		}
		if recNoTenant.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 tenant required, got %d", recNoTenant.Code)
		}

		svc.resolveErr = errors.New("resolve failed")
		userID := uuid.New()
		reqErr := httptest.NewRequest(http.MethodGet, "/api/v1/auth/admin/rbac/users/"+userID.String()+"/permissions/resolve?tenant_id="+tenantID.String(), nil)
		reqErr.Header.Set("Authorization", auth)
		recErr := httptest.NewRecorder()
		cErr := e.NewContext(reqErr, recErr)
		cErr.SetParamNames("id")
		cErr.SetParamValues(userID.String())
		if err := h.rbacResolveUserPermissions(cErr); err != nil {
			t.Fatalf("rbacResolveUserPermissions returned err=%v", err)
		}
		if recErr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 resolve error, got %d", recErr.Code)
		}

		svc.resolveErr = nil
		svc.resolveOut = adomain.ResolvedPermissions{Grants: []adomain.PermissionGrant{{Key: "users:read", ObjectType: "tenant"}}}
		reqOK := httptest.NewRequest(http.MethodGet, "/api/v1/auth/admin/rbac/users/"+userID.String()+"/permissions/resolve?tenant_id="+tenantID.String(), nil)
		reqOK.Header.Set("Authorization", auth)
		recOK := httptest.NewRecorder()
		cOK := e.NewContext(reqOK, recOK)
		cOK.SetParamNames("id")
		cOK.SetParamValues(userID.String())
		if err := h.rbacResolveUserPermissions(cOK); err != nil {
			t.Fatalf("rbacResolveUserPermissions returned err=%v", err)
		}
		if recOK.Code != http.StatusOK {
			t.Fatalf("expected 200 resolve success, got %d", recOK.Code)
		}
	})
}
