package controller

import (
	"bytes"
	"context"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	adomain "github.com/corvusHold/guard/internal/auth/domain"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

type platformBulkSvcStub struct {
	adomain.Service

	introspection adomain.Introspection
	introspectErr error

	hasPerm    bool
	hasPermErr error

	listTenantsOut []adomain.TenantStats
	listTenantsErr error

	searchUsersOut []adomain.UserSearchResult
	searchUsersErr error

	auditLogsOut   []adomain.AuditLogEntry
	auditTotalOut  int
	auditLogsErr   error
	lastAuditTID   *uuid.UUID
	lastAuditUID   *uuid.UUID
	lastAuditAct   string
	lastAuditLimit int
	lastAuditOff   int

	platformStatsOut adomain.PlatformStatsResult
	platformStatsErr error

	listUsersOut []adomain.UserExport
	listUsersErr error

	adminCreateErr error
	adminCreateN   int
}

func (s *platformBulkSvcStub) Introspect(context.Context, string) (adomain.Introspection, error) {
	if s.introspectErr != nil {
		return adomain.Introspection{}, s.introspectErr
	}
	return s.introspection, nil
}

func (s *platformBulkSvcStub) HasPermission(context.Context, uuid.UUID, uuid.UUID, string, string, *string) (bool, error) {
	if s.hasPermErr != nil {
		return false, s.hasPermErr
	}
	return s.hasPerm, nil
}

func (s *platformBulkSvcStub) ListAllTenantsWithStats(context.Context, int, int) ([]adomain.TenantStats, error) {
	if s.listTenantsErr != nil {
		return nil, s.listTenantsErr
	}
	return s.listTenantsOut, nil
}

func (s *platformBulkSvcStub) SearchUsersGlobal(context.Context, string) ([]adomain.UserSearchResult, error) {
	if s.searchUsersErr != nil {
		return nil, s.searchUsersErr
	}
	return s.searchUsersOut, nil
}

func (s *platformBulkSvcStub) QueryAuditLogs(ctx context.Context, tenantID *uuid.UUID, userID *uuid.UUID, action string, limit, offset int) ([]adomain.AuditLogEntry, int, error) {
	s.lastAuditTID = tenantID
	s.lastAuditUID = userID
	s.lastAuditAct = action
	s.lastAuditLimit = limit
	s.lastAuditOff = offset
	if s.auditLogsErr != nil {
		return nil, 0, s.auditLogsErr
	}
	return s.auditLogsOut, s.auditTotalOut, nil
}

func (s *platformBulkSvcStub) PlatformStats(context.Context) (adomain.PlatformStatsResult, error) {
	if s.platformStatsErr != nil {
		return adomain.PlatformStatsResult{}, s.platformStatsErr
	}
	return s.platformStatsOut, nil
}

func (s *platformBulkSvcStub) ListUsersByTenant(context.Context, uuid.UUID, int, int) ([]adomain.UserExport, error) {
	if s.listUsersErr != nil {
		return nil, s.listUsersErr
	}
	return s.listUsersOut, nil
}

func (s *platformBulkSvcStub) AdminCreateUser(context.Context, adomain.AdminCreateUserInput) (adomain.User, error) {
	s.adminCreateN++
	if s.adminCreateErr != nil {
		return adomain.User{}, s.adminCreateErr
	}
	return adomain.User{ID: uuid.New()}, nil
}

func TestPlatformComplianceBulkHandlers_ExtraBranches(t *testing.T) {
	e := echo.New()
	svc := &platformBulkSvcStub{introspection: adomain.Introspection{Active: true, UserID: uuid.New(), TenantID: uuid.New()}, hasPerm: true}
	h := &Controller{svc: svc}
	authHeader := "Bearer token"

	t.Run("platform list/search/stats/audit branches", func(t *testing.T) {
		svc.hasPerm = false
		reqForbidden := httptest.NewRequest(http.MethodGet, "/api/v1/auth/admin/platform/stats", nil)
		reqForbidden.Header.Set("Authorization", authHeader)
		recForbidden := httptest.NewRecorder()
		cForbidden := e.NewContext(reqForbidden, recForbidden)
		if err := h.platformStats(cForbidden); err != nil {
			t.Fatalf("platformStats returned err=%v", err)
		}
		if recForbidden.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d body=%s", recForbidden.Code, recForbidden.Body.String())
		}

		svc.hasPerm = true
		svc.listTenantsErr = context.DeadlineExceeded
		reqTenErr := httptest.NewRequest(http.MethodGet, "/api/v1/auth/admin/platform/tenants", nil)
		reqTenErr.Header.Set("Authorization", authHeader)
		recTenErr := httptest.NewRecorder()
		cTenErr := e.NewContext(reqTenErr, recTenErr)
		if err := h.platformListTenants(cTenErr); err != nil {
			t.Fatalf("platformListTenants returned err=%v", err)
		}
		if recTenErr.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500, got %d", recTenErr.Code)
		}

		svc.listTenantsErr = nil
		svc.listTenantsOut = []adomain.TenantStats{{ID: uuid.New(), Name: "Tenant A"}}
		reqTenOK := httptest.NewRequest(http.MethodGet, "/api/v1/auth/admin/platform/tenants?limit=10&offset=1", nil)
		reqTenOK.Header.Set("Authorization", authHeader)
		recTenOK := httptest.NewRecorder()
		cTenOK := e.NewContext(reqTenOK, recTenOK)
		if err := h.platformListTenants(cTenOK); err != nil {
			t.Fatalf("platformListTenants returned err=%v", err)
		}
		if recTenOK.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d body=%s", recTenOK.Code, recTenOK.Body.String())
		}

		reqSearchBad := httptest.NewRequest(http.MethodGet, "/api/v1/auth/admin/platform/users/search", nil)
		reqSearchBad.Header.Set("Authorization", authHeader)
		recSearchBad := httptest.NewRecorder()
		cSearchBad := e.NewContext(reqSearchBad, recSearchBad)
		if err := h.platformSearchUsers(cSearchBad); err != nil {
			t.Fatalf("platformSearchUsers returned err=%v", err)
		}
		if recSearchBad.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 missing q, got %d", recSearchBad.Code)
		}

		svc.searchUsersOut = []adomain.UserSearchResult{{ID: uuid.New(), Email: "u@example.com"}}
		reqSearchOK := httptest.NewRequest(http.MethodGet, "/api/v1/auth/admin/platform/users/search?q=u@example.com", nil)
		reqSearchOK.Header.Set("Authorization", authHeader)
		recSearchOK := httptest.NewRecorder()
		cSearchOK := e.NewContext(reqSearchOK, recSearchOK)
		if err := h.platformSearchUsers(cSearchOK); err != nil {
			t.Fatalf("platformSearchUsers returned err=%v", err)
		}
		if recSearchOK.Code != http.StatusOK {
			t.Fatalf("expected 200 search, got %d", recSearchOK.Code)
		}

		tenantID := uuid.New()
		userID := uuid.New()
		svc.auditLogsOut = []adomain.AuditLogEntry{{ID: 1}}
		svc.auditTotalOut = 1
		reqAuditOK := httptest.NewRequest(http.MethodGet, "/api/v1/auth/admin/platform/audit-logs?tenant_id="+tenantID.String()+"&user_id="+userID.String()+"&action=login&limit=2&offset=3", nil)
		reqAuditOK.Header.Set("Authorization", authHeader)
		recAuditOK := httptest.NewRecorder()
		cAuditOK := e.NewContext(reqAuditOK, recAuditOK)
		if err := h.platformAuditLogs(cAuditOK); err != nil {
			t.Fatalf("platformAuditLogs returned err=%v", err)
		}
		if recAuditOK.Code != http.StatusOK {
			t.Fatalf("expected 200 audit, got %d", recAuditOK.Code)
		}
		if svc.lastAuditTID == nil || *svc.lastAuditTID != tenantID || svc.lastAuditUID == nil || *svc.lastAuditUID != userID {
			t.Fatalf("expected parsed tenant/user IDs, got tid=%v uid=%v", svc.lastAuditTID, svc.lastAuditUID)
		}

		svc.platformStatsErr = context.Canceled
		reqStatsErr := httptest.NewRequest(http.MethodGet, "/api/v1/auth/admin/platform/stats", nil)
		reqStatsErr.Header.Set("Authorization", authHeader)
		recStatsErr := httptest.NewRecorder()
		cStatsErr := e.NewContext(reqStatsErr, recStatsErr)
		if err := h.platformStats(cStatsErr); err != nil {
			t.Fatalf("platformStats returned err=%v", err)
		}
		if recStatsErr.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500 stats err, got %d", recStatsErr.Code)
		}

		svc.platformStatsErr = nil
		svc.platformStatsOut = adomain.PlatformStatsResult{TotalTenants: 1, TotalUsers: 2}
		reqStatsOK := httptest.NewRequest(http.MethodGet, "/api/v1/auth/admin/platform/stats", nil)
		reqStatsOK.Header.Set("Authorization", authHeader)
		recStatsOK := httptest.NewRecorder()
		cStatsOK := e.NewContext(reqStatsOK, recStatsOK)
		if err := h.platformStats(cStatsOK); err != nil {
			t.Fatalf("platformStats returned err=%v", err)
		}
		if recStatsOK.Code != http.StatusOK {
			t.Fatalf("expected 200 stats, got %d", recStatsOK.Code)
		}
	})

	t.Run("compliance and bulk export branches", func(t *testing.T) {
		svc.platformStatsErr = context.DeadlineExceeded
		reqCompErr := httptest.NewRequest(http.MethodGet, "/api/v1/auth/admin/compliance/report", nil)
		reqCompErr.Header.Set("Authorization", authHeader)
		recCompErr := httptest.NewRecorder()
		cCompErr := e.NewContext(reqCompErr, recCompErr)
		if err := h.complianceReport(cCompErr); err != nil {
			t.Fatalf("complianceReport returned err=%v", err)
		}
		if recCompErr.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500 compliance err, got %d", recCompErr.Code)
		}

		svc.platformStatsErr = nil
		svc.platformStatsOut = adomain.PlatformStatsResult{TotalTenants: 3, TotalUsers: 9, ActiveSessions: 4, TotalAPIKeys: 2}
		reqCompOK := httptest.NewRequest(http.MethodGet, "/api/v1/auth/admin/compliance/report", nil)
		reqCompOK.Header.Set("Authorization", authHeader)
		recCompOK := httptest.NewRecorder()
		cCompOK := e.NewContext(reqCompOK, recCompOK)
		if err := h.complianceReport(cCompOK); err != nil {
			t.Fatalf("complianceReport returned err=%v", err)
		}
		if recCompOK.Code != http.StatusOK {
			t.Fatalf("expected 200 compliance, got %d", recCompOK.Code)
		}

		svc.listUsersErr = context.DeadlineExceeded
		reqBulkErr := httptest.NewRequest(http.MethodGet, "/api/v1/auth/admin/bulk/users/export", nil)
		reqBulkErr.Header.Set("Authorization", authHeader)
		recBulkErr := httptest.NewRecorder()
		cBulkErr := e.NewContext(reqBulkErr, recBulkErr)
		if err := h.bulkExportUsers(cBulkErr); err != nil {
			t.Fatalf("bulkExportUsers returned err=%v", err)
		}
		if recBulkErr.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500 bulk export err, got %d", recBulkErr.Code)
		}

		svc.listUsersErr = nil
		svc.listUsersOut = []adomain.UserExport{{ID: uuid.New(), Email: "u@example.com", FirstName: "U", LastName: "Ser", CreatedAt: time.Now()}}
		reqBulkCSV := httptest.NewRequest(http.MethodGet, "/api/v1/auth/admin/bulk/users/export?format=csv&limit=1", nil)
		reqBulkCSV.Header.Set("Authorization", authHeader)
		recBulkCSV := httptest.NewRecorder()
		cBulkCSV := e.NewContext(reqBulkCSV, recBulkCSV)
		if err := h.bulkExportUsers(cBulkCSV); err != nil {
			t.Fatalf("bulkExportUsers returned err=%v", err)
		}
		if recBulkCSV.Code != http.StatusOK {
			t.Fatalf("expected 200 CSV export, got %d", recBulkCSV.Code)
		}
		if ct := recBulkCSV.Header().Get("Content-Type"); !strings.Contains(ct, "text/csv") {
			t.Fatalf("expected text/csv content type, got %q", ct)
		}

		reqImportMissing := httptest.NewRequest(http.MethodPost, "/api/v1/auth/admin/bulk/users/import", nil)
		reqImportMissing.Header.Set("Authorization", authHeader)
		recImportMissing := httptest.NewRecorder()
		cImportMissing := e.NewContext(reqImportMissing, recImportMissing)
		if err := h.bulkImportUsers(cImportMissing); err != nil {
			t.Fatalf("bulkImportUsers returned err=%v", err)
		}
		if recImportMissing.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 missing file, got %d", recImportMissing.Code)
		}
	})

	t.Run("bulk import permission/parse/success branches", func(t *testing.T) {
		// Permission denied path
		svc.hasPerm = false
		reqDenied := httptest.NewRequest(http.MethodPost, "/api/v1/auth/admin/bulk/users/import", nil)
		reqDenied.Header.Set("Authorization", authHeader)
		recDenied := httptest.NewRecorder()
		cDenied := e.NewContext(reqDenied, recDenied)
		if err := h.bulkImportUsers(cDenied); err != nil {
			t.Fatalf("bulkImportUsers returned err=%v", err)
		}
		if recDenied.Code != http.StatusForbidden {
			t.Fatalf("expected 403 admin required, got %d", recDenied.Code)
		}
		svc.hasPerm = true

		// Invalid JSON file path
		var badBuf bytes.Buffer
		badMw := multipart.NewWriter(&badBuf)
		badPart, err := badMw.CreateFormFile("file", "users.json")
		if err != nil {
			t.Fatalf("CreateFormFile: %v", err)
		}
		_, _ = badPart.Write([]byte("{"))
		_ = badMw.Close()
		reqBadJSON := httptest.NewRequest(http.MethodPost, "/api/v1/auth/admin/bulk/users/import", &badBuf)
		reqBadJSON.Header.Set("Authorization", authHeader)
		reqBadJSON.Header.Set("Content-Type", badMw.FormDataContentType())
		recBadJSON := httptest.NewRecorder()
		cBadJSON := e.NewContext(reqBadJSON, recBadJSON)
		if err := h.bulkImportUsers(cBadJSON); err != nil {
			t.Fatalf("bulkImportUsers returned err=%v", err)
		}
		if recBadJSON.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 invalid JSON import, got %d", recBadJSON.Code)
		}

		// Valid JSON import path
		svc.adminCreateN = 0
		var okBuf bytes.Buffer
		okMw := multipart.NewWriter(&okBuf)
		okPart, err := okMw.CreateFormFile("file", "users.json")
		if err != nil {
			t.Fatalf("CreateFormFile: %v", err)
		}
		_, _ = okPart.Write([]byte(`[{"email":"u@example.com","first_name":"U","last_name":"Ser","password":"Password!123"},{"email":"","first_name":"X"}]`))
		_ = okMw.Close()
		reqOK := httptest.NewRequest(http.MethodPost, "/api/v1/auth/admin/bulk/users/import", &okBuf)
		reqOK.Header.Set("Authorization", authHeader)
		reqOK.Header.Set("Content-Type", okMw.FormDataContentType())
		recOK := httptest.NewRecorder()
		cOK := e.NewContext(reqOK, recOK)
		if err := h.bulkImportUsers(cOK); err != nil {
			t.Fatalf("bulkImportUsers returned err=%v", err)
		}
		if recOK.Code != http.StatusOK {
			t.Fatalf("expected 200 import success, got %d", recOK.Code)
		}
		if svc.adminCreateN != 1 {
			t.Fatalf("expected one created user call, got %d", svc.adminCreateN)
		}

		// CSV import path with one valid and one skipped row
		svc.adminCreateN = 0
		var csvBuf bytes.Buffer
		csvMw := multipart.NewWriter(&csvBuf)
		csvPart, err := csvMw.CreateFormFile("file", "users.csv")
		if err != nil {
			t.Fatalf("CreateFormFile: %v", err)
		}
		_, _ = csvPart.Write([]byte("email,first_name,last_name,password,role\nvalid@example.com,Va,Lid,Password!123,member\n,No,Email,Password!123,member\n"))
		_ = csvMw.Close()
		reqCSV := httptest.NewRequest(http.MethodPost, "/api/v1/auth/admin/bulk/users/import", &csvBuf)
		reqCSV.Header.Set("Authorization", authHeader)
		reqCSV.Header.Set("Content-Type", csvMw.FormDataContentType())
		recCSV := httptest.NewRecorder()
		cCSV := e.NewContext(reqCSV, recCSV)
		if err := h.bulkImportUsers(cCSV); err != nil {
			t.Fatalf("bulkImportUsers returned err=%v", err)
		}
		if recCSV.Code != http.StatusOK {
			t.Fatalf("expected 200 CSV import success, got %d", recCSV.Code)
		}
		if svc.adminCreateN != 1 {
			t.Fatalf("expected one CSV create call, got %d", svc.adminCreateN)
		}

		// Admin create error should be surfaced in result but still return 200
		svc.adminCreateErr = context.Canceled
		svc.adminCreateN = 0
		var errBuf bytes.Buffer
		errMw := multipart.NewWriter(&errBuf)
		errPart, err := errMw.CreateFormFile("file", "users.json")
		if err != nil {
			t.Fatalf("CreateFormFile: %v", err)
		}
		_, _ = errPart.Write([]byte(`[{"email":"e1@example.com","password":"Password!123"}]`))
		_ = errMw.Close()
		reqCreateErr := httptest.NewRequest(http.MethodPost, "/api/v1/auth/admin/bulk/users/import", &errBuf)
		reqCreateErr.Header.Set("Authorization", authHeader)
		reqCreateErr.Header.Set("Content-Type", errMw.FormDataContentType())
		recCreateErr := httptest.NewRecorder()
		cCreateErr := e.NewContext(reqCreateErr, recCreateErr)
		if err := h.bulkImportUsers(cCreateErr); err != nil {
			t.Fatalf("bulkImportUsers returned err=%v", err)
		}
		if recCreateErr.Code != http.StatusOK {
			t.Fatalf("expected 200 create-error import response, got %d", recCreateErr.Code)
		}
		svc.adminCreateErr = nil
	})
}
