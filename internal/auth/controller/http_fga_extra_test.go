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

type fgaSvcStub struct {
	adomain.Service

	introspection adomain.Introspection
	introspectErr error

	createGroupOut adomain.Group
	createGroupErr error
	listGroupsOut  []adomain.Group
	listGroupsErr  error
	deleteGroupErr error

	addMemberErr    error
	removeMemberErr error

	createTupleErr error
	deleteTupleErr error

	authorizeAllowed bool
	authorizeReason  string
	authorizeErr     error
}

func (s *fgaSvcStub) Introspect(context.Context, string) (adomain.Introspection, error) {
	if s.introspectErr != nil {
		return adomain.Introspection{}, s.introspectErr
	}
	return s.introspection, nil
}

func (s *fgaSvcStub) CreateGroup(context.Context, uuid.UUID, string, string) (adomain.Group, error) {
	if s.createGroupErr != nil {
		return adomain.Group{}, s.createGroupErr
	}
	return s.createGroupOut, nil
}

func (s *fgaSvcStub) ListGroups(context.Context, uuid.UUID) ([]adomain.Group, error) {
	if s.listGroupsErr != nil {
		return nil, s.listGroupsErr
	}
	return s.listGroupsOut, nil
}

func (s *fgaSvcStub) DeleteGroup(context.Context, uuid.UUID, uuid.UUID) error {
	return s.deleteGroupErr
}
func (s *fgaSvcStub) AddGroupMember(context.Context, uuid.UUID, uuid.UUID) error {
	return s.addMemberErr
}
func (s *fgaSvcStub) RemoveGroupMember(context.Context, uuid.UUID, uuid.UUID) error {
	return s.removeMemberErr
}

func (s *fgaSvcStub) CreateACLTuple(context.Context, uuid.UUID, string, uuid.UUID, string, string, *string, *uuid.UUID) (adomain.ACLTuple, error) {
	if s.createTupleErr != nil {
		return adomain.ACLTuple{}, s.createTupleErr
	}
	return adomain.ACLTuple{ID: uuid.New()}, nil
}

func (s *fgaSvcStub) DeleteACLTuple(context.Context, uuid.UUID, string, uuid.UUID, string, string, *string) error {
	return s.deleteTupleErr
}

func (s *fgaSvcStub) Authorize(context.Context, uuid.UUID, string, uuid.UUID, string, string, *string) (bool, string, error) {
	if s.authorizeErr != nil {
		return false, "", s.authorizeErr
	}
	return s.authorizeAllowed, s.authorizeReason, nil
}

func TestFGAHandlers_ExtraBranches(t *testing.T) {
	e := echo.New()
	e.Validator = noopValidator{}
	tenantID := uuid.New()
	uid := uuid.New()
	svc := &fgaSvcStub{introspection: adomain.Introspection{Active: true, UserID: uid, TenantID: tenantID, Roles: []string{"admin"}}}
	h := &Controller{svc: svc}
	authHeader := "Bearer token"

	t.Run("group handlers", func(t *testing.T) {
		reqCreateBad := httptest.NewRequest(http.MethodPost, "/api/v1/auth/admin/fga/groups", bytes.NewBufferString("{"))
		reqCreateBad.Header.Set("Content-Type", "application/json")
		recCreateBad := httptest.NewRecorder()
		cCreateBad := e.NewContext(reqCreateBad, recCreateBad)
		if err := h.fgaCreateGroup(cCreateBad); err != nil {
			t.Fatalf("fgaCreateGroup returned err=%v", err)
		}
		if recCreateBad.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 invalid json, got %d", recCreateBad.Code)
		}

		reqCreateInvTen := httptest.NewRequest(http.MethodPost, "/api/v1/auth/admin/fga/groups", bytes.NewBufferString(`{"tenant_id":"bad","name":"eng"}`))
		reqCreateInvTen.Header.Set("Authorization", authHeader)
		reqCreateInvTen.Header.Set("Content-Type", "application/json")
		recCreateInvTen := httptest.NewRecorder()
		cCreateInvTen := e.NewContext(reqCreateInvTen, recCreateInvTen)
		if err := h.fgaCreateGroup(cCreateInvTen); err != nil {
			t.Fatalf("fgaCreateGroup returned err=%v", err)
		}
		if recCreateInvTen.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 invalid tenant, got %d", recCreateInvTen.Code)
		}

		svc.createGroupErr = adomain.ErrDuplicateGroup
		reqCreateDup := httptest.NewRequest(http.MethodPost, "/api/v1/auth/admin/fga/groups", bytes.NewBufferString(`{"tenant_id":"`+tenantID.String()+`","name":"eng"}`))
		reqCreateDup.Header.Set("Authorization", authHeader)
		reqCreateDup.Header.Set("Content-Type", "application/json")
		recCreateDup := httptest.NewRecorder()
		cCreateDup := e.NewContext(reqCreateDup, recCreateDup)
		if err := h.fgaCreateGroup(cCreateDup); err != nil {
			t.Fatalf("fgaCreateGroup returned err=%v", err)
		}
		if recCreateDup.Code != http.StatusConflict {
			t.Fatalf("expected 409 duplicate, got %d", recCreateDup.Code)
		}

		svc.createGroupErr = nil
		svc.createGroupOut = adomain.Group{ID: uuid.New(), TenantID: tenantID, Name: "eng"}
		reqCreateOK := httptest.NewRequest(http.MethodPost, "/api/v1/auth/admin/fga/groups", bytes.NewBufferString(`{"tenant_id":"`+tenantID.String()+`","name":"eng"}`))
		reqCreateOK.Header.Set("Authorization", authHeader)
		reqCreateOK.Header.Set("Content-Type", "application/json")
		recCreateOK := httptest.NewRecorder()
		cCreateOK := e.NewContext(reqCreateOK, recCreateOK)
		if err := h.fgaCreateGroup(cCreateOK); err != nil {
			t.Fatalf("fgaCreateGroup returned err=%v", err)
		}
		if recCreateOK.Code != http.StatusCreated {
			t.Fatalf("expected 201 create success, got %d", recCreateOK.Code)
		}

		reqListBad := httptest.NewRequest(http.MethodGet, "/api/v1/auth/admin/fga/groups", nil)
		reqListBad.Header.Set("Authorization", authHeader)
		recListBad := httptest.NewRecorder()
		cListBad := e.NewContext(reqListBad, recListBad)
		if err := h.fgaListGroups(cListBad); err != nil {
			t.Fatalf("fgaListGroups returned err=%v", err)
		}
		if recListBad.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 tenant required, got %d", recListBad.Code)
		}

		svc.listGroupsErr = errors.New("list failed")
		reqListErr := httptest.NewRequest(http.MethodGet, "/api/v1/auth/admin/fga/groups?tenant_id="+tenantID.String(), nil)
		reqListErr.Header.Set("Authorization", authHeader)
		recListErr := httptest.NewRecorder()
		cListErr := e.NewContext(reqListErr, recListErr)
		if err := h.fgaListGroups(cListErr); err != nil {
			t.Fatalf("fgaListGroups returned err=%v", err)
		}
		if recListErr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 list error, got %d", recListErr.Code)
		}

		svc.listGroupsErr = nil
		svc.listGroupsOut = []adomain.Group{{ID: uuid.New(), TenantID: tenantID, Name: "eng"}}
		reqListOK := httptest.NewRequest(http.MethodGet, "/api/v1/auth/admin/fga/groups?tenant_id="+tenantID.String(), nil)
		reqListOK.Header.Set("Authorization", authHeader)
		recListOK := httptest.NewRecorder()
		cListOK := e.NewContext(reqListOK, recListOK)
		if err := h.fgaListGroups(cListOK); err != nil {
			t.Fatalf("fgaListGroups returned err=%v", err)
		}
		if recListOK.Code != http.StatusOK {
			t.Fatalf("expected 200 list success, got %d", recListOK.Code)
		}

		reqDelBadID := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/admin/fga/groups/bad?tenant_id="+tenantID.String(), nil)
		reqDelBadID.Header.Set("Authorization", authHeader)
		recDelBadID := httptest.NewRecorder()
		cDelBadID := e.NewContext(reqDelBadID, recDelBadID)
		cDelBadID.SetParamNames("id")
		cDelBadID.SetParamValues("bad")
		if err := h.fgaDeleteGroup(cDelBadID); err != nil {
			t.Fatalf("fgaDeleteGroup returned err=%v", err)
		}
		if recDelBadID.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 invalid group id, got %d", recDelBadID.Code)
		}

		reqDelNoTenant := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/admin/fga/groups/"+uuid.New().String(), nil)
		reqDelNoTenant.Header.Set("Authorization", authHeader)
		recDelNoTenant := httptest.NewRecorder()
		cDelNoTenant := e.NewContext(reqDelNoTenant, recDelNoTenant)
		cDelNoTenant.SetParamNames("id")
		cDelNoTenant.SetParamValues(uuid.New().String())
		if err := h.fgaDeleteGroup(cDelNoTenant); err != nil {
			t.Fatalf("fgaDeleteGroup returned err=%v", err)
		}
		if recDelNoTenant.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 tenant required, got %d", recDelNoTenant.Code)
		}

		svc.deleteGroupErr = errors.New("delete failed")
		gid := uuid.New()
		reqDelErr := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/admin/fga/groups/"+gid.String()+"?tenant_id="+tenantID.String(), nil)
		reqDelErr.Header.Set("Authorization", authHeader)
		recDelErr := httptest.NewRecorder()
		cDelErr := e.NewContext(reqDelErr, recDelErr)
		cDelErr.SetParamNames("id")
		cDelErr.SetParamValues(gid.String())
		if err := h.fgaDeleteGroup(cDelErr); err != nil {
			t.Fatalf("fgaDeleteGroup returned err=%v", err)
		}
		if recDelErr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 delete error, got %d", recDelErr.Code)
		}

		svc.deleteGroupErr = nil
		reqDelOK := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/admin/fga/groups/"+gid.String()+"?tenant_id="+tenantID.String(), nil)
		reqDelOK.Header.Set("Authorization", authHeader)
		recDelOK := httptest.NewRecorder()
		cDelOK := e.NewContext(reqDelOK, recDelOK)
		cDelOK.SetParamNames("id")
		cDelOK.SetParamValues(gid.String())
		if err := h.fgaDeleteGroup(cDelOK); err != nil {
			t.Fatalf("fgaDeleteGroup returned err=%v", err)
		}
		if recDelOK.Code != http.StatusNoContent {
			t.Fatalf("expected 204 delete success, got %d", recDelOK.Code)
		}
	})

	t.Run("group membership handlers", func(t *testing.T) {
		gid := uuid.New()
		reqAddBadID := httptest.NewRequest(http.MethodPost, "/api/v1/auth/admin/fga/groups/bad/members", bytes.NewBufferString(`{"user_id":"`+uid.String()+`"}`))
		reqAddBadID.Header.Set("Authorization", authHeader)
		reqAddBadID.Header.Set("Content-Type", "application/json")
		recAddBadID := httptest.NewRecorder()
		cAddBadID := e.NewContext(reqAddBadID, recAddBadID)
		cAddBadID.SetParamNames("id")
		cAddBadID.SetParamValues("bad")
		if err := h.fgaAddGroupMember(cAddBadID); err != nil {
			t.Fatalf("fgaAddGroupMember returned err=%v", err)
		}
		if recAddBadID.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 invalid group id, got %d", recAddBadID.Code)
		}

		svc.addMemberErr = errors.New("add failed")
		reqAddErr := httptest.NewRequest(http.MethodPost, "/api/v1/auth/admin/fga/groups/"+gid.String()+"/members", bytes.NewBufferString(`{"user_id":"`+uid.String()+`"}`))
		reqAddErr.Header.Set("Authorization", authHeader)
		reqAddErr.Header.Set("Content-Type", "application/json")
		recAddErr := httptest.NewRecorder()
		cAddErr := e.NewContext(reqAddErr, recAddErr)
		cAddErr.SetParamNames("id")
		cAddErr.SetParamValues(gid.String())
		if err := h.fgaAddGroupMember(cAddErr); err != nil {
			t.Fatalf("fgaAddGroupMember returned err=%v", err)
		}
		if recAddErr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 add error, got %d", recAddErr.Code)
		}
		svc.addMemberErr = nil

		reqAddOK := httptest.NewRequest(http.MethodPost, "/api/v1/auth/admin/fga/groups/"+gid.String()+"/members", bytes.NewBufferString(`{"user_id":"`+uid.String()+`"}`))
		reqAddOK.Header.Set("Authorization", authHeader)
		reqAddOK.Header.Set("Content-Type", "application/json")
		recAddOK := httptest.NewRecorder()
		cAddOK := e.NewContext(reqAddOK, recAddOK)
		cAddOK.SetParamNames("id")
		cAddOK.SetParamValues(gid.String())
		if err := h.fgaAddGroupMember(cAddOK); err != nil {
			t.Fatalf("fgaAddGroupMember returned err=%v", err)
		}
		if recAddOK.Code != http.StatusNoContent {
			t.Fatalf("expected 204 add success, got %d", recAddOK.Code)
		}

		svc.removeMemberErr = errors.New("remove failed")
		reqDelErr := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/admin/fga/groups/"+gid.String()+"/members", bytes.NewBufferString(`{"user_id":"`+uid.String()+`"}`))
		reqDelErr.Header.Set("Authorization", authHeader)
		reqDelErr.Header.Set("Content-Type", "application/json")
		recDelErr := httptest.NewRecorder()
		cDelErr := e.NewContext(reqDelErr, recDelErr)
		cDelErr.SetParamNames("id")
		cDelErr.SetParamValues(gid.String())
		if err := h.fgaRemoveGroupMember(cDelErr); err != nil {
			t.Fatalf("fgaRemoveGroupMember returned err=%v", err)
		}
		if recDelErr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 remove error, got %d", recDelErr.Code)
		}

		svc.removeMemberErr = nil
		reqDelBadJSON := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/admin/fga/groups/"+gid.String()+"/members", bytes.NewBufferString("{"))
		reqDelBadJSON.Header.Set("Authorization", authHeader)
		reqDelBadJSON.Header.Set("Content-Type", "application/json")
		recDelBadJSON := httptest.NewRecorder()
		cDelBadJSON := e.NewContext(reqDelBadJSON, recDelBadJSON)
		cDelBadJSON.SetParamNames("id")
		cDelBadJSON.SetParamValues(gid.String())
		if err := h.fgaRemoveGroupMember(cDelBadJSON); err != nil {
			t.Fatalf("fgaRemoveGroupMember returned err=%v", err)
		}
		if recDelBadJSON.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 invalid json, got %d", recDelBadJSON.Code)
		}

		reqDelBadUser := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/admin/fga/groups/"+gid.String()+"/members", bytes.NewBufferString(`{"user_id":"bad"}`))
		reqDelBadUser.Header.Set("Authorization", authHeader)
		reqDelBadUser.Header.Set("Content-Type", "application/json")
		recDelBadUser := httptest.NewRecorder()
		cDelBadUser := e.NewContext(reqDelBadUser, recDelBadUser)
		cDelBadUser.SetParamNames("id")
		cDelBadUser.SetParamValues(gid.String())
		if err := h.fgaRemoveGroupMember(cDelBadUser); err != nil {
			t.Fatalf("fgaRemoveGroupMember returned err=%v", err)
		}
		if recDelBadUser.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 invalid user_id, got %d", recDelBadUser.Code)
		}

		reqDelOK := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/admin/fga/groups/"+gid.String()+"/members", bytes.NewBufferString(`{"user_id":"`+uid.String()+`"}`))
		reqDelOK.Header.Set("Authorization", authHeader)
		reqDelOK.Header.Set("Content-Type", "application/json")
		recDelOK := httptest.NewRecorder()
		cDelOK := e.NewContext(reqDelOK, recDelOK)
		cDelOK.SetParamNames("id")
		cDelOK.SetParamValues(gid.String())
		if err := h.fgaRemoveGroupMember(cDelOK); err != nil {
			t.Fatalf("fgaRemoveGroupMember returned err=%v", err)
		}
		if recDelOK.Code != http.StatusNoContent {
			t.Fatalf("expected 204 remove success, got %d", recDelOK.Code)
		}
	})

	t.Run("acl tuple and authorize handlers", func(t *testing.T) {
		reqTupleBad := httptest.NewRequest(http.MethodPost, "/api/v1/auth/admin/fga/acl/tuples", bytes.NewBufferString("{"))
		reqTupleBad.Header.Set("Content-Type", "application/json")
		recTupleBad := httptest.NewRecorder()
		cTupleBad := e.NewContext(reqTupleBad, recTupleBad)
		if err := h.fgaCreateACLTuple(cTupleBad); err != nil {
			t.Fatalf("fgaCreateACLTuple returned err=%v", err)
		}
		if recTupleBad.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 invalid json, got %d", recTupleBad.Code)
		}

		svc.createTupleErr = errors.New("create tuple failed")
		reqTupleErr := httptest.NewRequest(http.MethodPost, "/api/v1/auth/admin/fga/acl/tuples", bytes.NewBufferString(`{"tenant_id":"`+tenantID.String()+`","subject_type":"user","subject_id":"`+uid.String()+`","permission_key":"users:read","object_type":"tenant"}`))
		reqTupleErr.Header.Set("Authorization", authHeader)
		reqTupleErr.Header.Set("Content-Type", "application/json")
		recTupleErr := httptest.NewRecorder()
		cTupleErr := e.NewContext(reqTupleErr, recTupleErr)
		if err := h.fgaCreateACLTuple(cTupleErr); err != nil {
			t.Fatalf("fgaCreateACLTuple returned err=%v", err)
		}
		if recTupleErr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 tuple error, got %d", recTupleErr.Code)
		}

		svc.createTupleErr = nil
		reqTupleOK := httptest.NewRequest(http.MethodPost, "/api/v1/auth/admin/fga/acl/tuples", bytes.NewBufferString(`{"tenant_id":"`+tenantID.String()+`","subject_type":"user","subject_id":"`+uid.String()+`","permission_key":"users:read","object_type":"tenant"}`))
		reqTupleOK.Header.Set("Authorization", authHeader)
		reqTupleOK.Header.Set("Content-Type", "application/json")
		recTupleOK := httptest.NewRecorder()
		cTupleOK := e.NewContext(reqTupleOK, recTupleOK)
		if err := h.fgaCreateACLTuple(cTupleOK); err != nil {
			t.Fatalf("fgaCreateACLTuple returned err=%v", err)
		}
		if recTupleOK.Code != http.StatusCreated {
			t.Fatalf("expected 201 tuple success, got %d", recTupleOK.Code)
		}

		reqDelTupleBad := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/admin/fga/acl/tuples", bytes.NewBufferString("{"))
		reqDelTupleBad.Header.Set("Content-Type", "application/json")
		recDelTupleBad := httptest.NewRecorder()
		cDelTupleBad := e.NewContext(reqDelTupleBad, recDelTupleBad)
		if err := h.fgaDeleteACLTuple(cDelTupleBad); err != nil {
			t.Fatalf("fgaDeleteACLTuple returned err=%v", err)
		}
		if recDelTupleBad.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 invalid json, got %d", recDelTupleBad.Code)
		}

		reqDelTupleBadTenant := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/admin/fga/acl/tuples", bytes.NewBufferString(`{"tenant_id":"bad","subject_type":"user","subject_id":"`+uid.String()+`","permission_key":"users:read","object_type":"tenant"}`))
		reqDelTupleBadTenant.Header.Set("Authorization", authHeader)
		reqDelTupleBadTenant.Header.Set("Content-Type", "application/json")
		recDelTupleBadTenant := httptest.NewRecorder()
		cDelTupleBadTenant := e.NewContext(reqDelTupleBadTenant, recDelTupleBadTenant)
		if err := h.fgaDeleteACLTuple(cDelTupleBadTenant); err != nil {
			t.Fatalf("fgaDeleteACLTuple returned err=%v", err)
		}
		if recDelTupleBadTenant.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 invalid tenant_id, got %d", recDelTupleBadTenant.Code)
		}

		reqDelTupleBadSubject := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/admin/fga/acl/tuples", bytes.NewBufferString(`{"tenant_id":"`+tenantID.String()+`","subject_type":"user","subject_id":"bad","permission_key":"users:read","object_type":"tenant"}`))
		reqDelTupleBadSubject.Header.Set("Authorization", authHeader)
		reqDelTupleBadSubject.Header.Set("Content-Type", "application/json")
		recDelTupleBadSubject := httptest.NewRecorder()
		cDelTupleBadSubject := e.NewContext(reqDelTupleBadSubject, recDelTupleBadSubject)
		if err := h.fgaDeleteACLTuple(cDelTupleBadSubject); err != nil {
			t.Fatalf("fgaDeleteACLTuple returned err=%v", err)
		}
		if recDelTupleBadSubject.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 invalid subject_id, got %d", recDelTupleBadSubject.Code)
		}

		svc.deleteTupleErr = errors.New("delete tuple failed")
		reqDelTupleErr := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/admin/fga/acl/tuples", bytes.NewBufferString(`{"tenant_id":"`+tenantID.String()+`","subject_type":"user","subject_id":"`+uid.String()+`","permission_key":"users:read","object_type":"tenant"}`))
		reqDelTupleErr.Header.Set("Authorization", authHeader)
		reqDelTupleErr.Header.Set("Content-Type", "application/json")
		recDelTupleErr := httptest.NewRecorder()
		cDelTupleErr := e.NewContext(reqDelTupleErr, recDelTupleErr)
		if err := h.fgaDeleteACLTuple(cDelTupleErr); err != nil {
			t.Fatalf("fgaDeleteACLTuple returned err=%v", err)
		}
		if recDelTupleErr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 tuple delete error, got %d", recDelTupleErr.Code)
		}

		svc.deleteTupleErr = nil
		reqDelTupleOK := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/admin/fga/acl/tuples", bytes.NewBufferString(`{"tenant_id":"`+tenantID.String()+`","subject_type":"user","subject_id":"`+uid.String()+`","permission_key":"users:read","object_type":"tenant"}`))
		reqDelTupleOK.Header.Set("Authorization", authHeader)
		reqDelTupleOK.Header.Set("Content-Type", "application/json")
		recDelTupleOK := httptest.NewRecorder()
		cDelTupleOK := e.NewContext(reqDelTupleOK, recDelTupleOK)
		if err := h.fgaDeleteACLTuple(cDelTupleOK); err != nil {
			t.Fatalf("fgaDeleteACLTuple returned err=%v", err)
		}
		if recDelTupleOK.Code != http.StatusNoContent {
			t.Fatalf("expected 204 tuple delete success, got %d", recDelTupleOK.Code)
		}

		reqAuthNoToken := httptest.NewRequest(http.MethodPost, "/api/v1/auth/authorize", bytes.NewBufferString(`{"tenant_id":"`+tenantID.String()+`"}`))
		reqAuthNoToken.Header.Set("Content-Type", "application/json")
		recAuthNoToken := httptest.NewRecorder()
		cAuthNoToken := e.NewContext(reqAuthNoToken, recAuthNoToken)
		if err := h.fgaAuthorize(cAuthNoToken); err != nil {
			t.Fatalf("fgaAuthorize returned err=%v", err)
		}
		if recAuthNoToken.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 missing token, got %d", recAuthNoToken.Code)
		}

		svc.authorizeErr = errors.New("authorize failed")
		reqAuthErr := httptest.NewRequest(http.MethodPost, "/api/v1/auth/authorize", bytes.NewBufferString(`{"tenant_id":"`+tenantID.String()+`","subject_type":"self","permission_key":"users:read","object_type":"tenant"}`))
		reqAuthErr.Header.Set("Authorization", authHeader)
		reqAuthErr.Header.Set("Content-Type", "application/json")
		recAuthErr := httptest.NewRecorder()
		cAuthErr := e.NewContext(reqAuthErr, recAuthErr)
		if err := h.fgaAuthorize(cAuthErr); err != nil {
			t.Fatalf("fgaAuthorize returned err=%v", err)
		}
		if recAuthErr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 authorize error, got %d", recAuthErr.Code)
		}

		reqAuthMissingSubject := httptest.NewRequest(http.MethodPost, "/api/v1/auth/authorize", bytes.NewBufferString(`{"tenant_id":"`+tenantID.String()+`","subject_type":"user","permission_key":"users:read","object_type":"tenant"}`))
		reqAuthMissingSubject.Header.Set("Authorization", authHeader)
		reqAuthMissingSubject.Header.Set("Content-Type", "application/json")
		recAuthMissingSubject := httptest.NewRecorder()
		cAuthMissingSubject := e.NewContext(reqAuthMissingSubject, recAuthMissingSubject)
		if err := h.fgaAuthorize(cAuthMissingSubject); err != nil {
			t.Fatalf("fgaAuthorize returned err=%v", err)
		}
		if recAuthMissingSubject.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 missing subject_id, got %d", recAuthMissingSubject.Code)
		}

		reqAuthMissingObject := httptest.NewRequest(http.MethodPost, "/api/v1/auth/authorize", bytes.NewBufferString(`{"tenant_id":"`+tenantID.String()+`","subject_type":"self","permission_key":"users:read","object_type":""}`))
		reqAuthMissingObject.Header.Set("Authorization", authHeader)
		reqAuthMissingObject.Header.Set("Content-Type", "application/json")
		recAuthMissingObject := httptest.NewRecorder()
		cAuthMissingObject := e.NewContext(reqAuthMissingObject, recAuthMissingObject)
		if err := h.fgaAuthorize(cAuthMissingObject); err != nil {
			t.Fatalf("fgaAuthorize returned err=%v", err)
		}
		if recAuthMissingObject.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 missing object_type, got %d", recAuthMissingObject.Code)
		}

		svc.authorizeErr = nil
		svc.authorizeAllowed = true
		svc.authorizeReason = "granted"
		reqAuthOK := httptest.NewRequest(http.MethodPost, "/api/v1/auth/authorize", bytes.NewBufferString(`{"tenant_id":"`+tenantID.String()+`","subject_type":"self","permission_key":"users:read","object_type":"tenant"}`))
		reqAuthOK.Header.Set("Authorization", authHeader)
		reqAuthOK.Header.Set("Content-Type", "application/json")
		recAuthOK := httptest.NewRecorder()
		cAuthOK := e.NewContext(reqAuthOK, recAuthOK)
		if err := h.fgaAuthorize(cAuthOK); err != nil {
			t.Fatalf("fgaAuthorize returned err=%v", err)
		}
		if recAuthOK.Code != http.StatusOK {
			t.Fatalf("expected 200 authorize success, got %d", recAuthOK.Code)
		}
	})
}
