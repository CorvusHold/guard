package controller

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
)

func TestHandlers_RequireAuthOrAdmin_MissingTokenBranches(t *testing.T) {
	e := echo.New()
	e.Validator = noopValidator{}
	h := &Controller{}

	tests := []struct {
		name    string
		method  string
		path    string
		body    string
		handler func(echo.Context) error
		params  map[string]string
	}{
		{name: "changePassword unauthorized", method: http.MethodPost, path: "/api/v1/auth/password/change", handler: h.changePassword},
		{name: "sso portal link unauthorized", method: http.MethodGet, path: "/api/v1/auth/sso/workos/portal-link", handler: h.ssoOrganizationPortalLinkGenerator, params: map[string]string{"provider": "workos"}},
		{name: "totpStart unauthorized", method: http.MethodPost, path: "/api/v1/auth/mfa/totp/start", handler: h.totpStart},
		{name: "totpActivate unauthorized", method: http.MethodPost, path: "/api/v1/auth/mfa/totp/activate", body: `{"code":"123456"}`, handler: h.totpActivate},
		{name: "totpDisable unauthorized", method: http.MethodPost, path: "/api/v1/auth/mfa/totp/disable", handler: h.totpDisable},
		{name: "backupGenerate unauthorized", method: http.MethodPost, path: "/api/v1/auth/mfa/backup/generate", handler: h.backupGenerate},
		{name: "backupConsume unauthorized", method: http.MethodPost, path: "/api/v1/auth/mfa/backup/consume", body: `{"code":"abc"}`, handler: h.backupConsume},
		{name: "backupCount unauthorized", method: http.MethodGet, path: "/api/v1/auth/mfa/backup/count", handler: h.backupCount},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body *bytes.Buffer
			if tt.body != "" {
				body = bytes.NewBufferString(tt.body)
			} else {
				body = bytes.NewBuffer(nil)
			}
			req := httptest.NewRequest(tt.method, tt.path, body)
			if tt.body != "" {
				req.Header.Set("Content-Type", "application/json")
			}
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			if tt.params != nil {
				names := make([]string, 0, len(tt.params))
				vals := make([]string, 0, len(tt.params))
				for k, v := range tt.params {
					names = append(names, k)
					vals = append(vals, v)
				}
				c.SetParamNames(names...)
				c.SetParamValues(vals...)
			}
			if err := tt.handler(c); err != nil {
				t.Fatalf("handler returned error: %v", err)
			}
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("expected 401, got %d body=%s", rec.Code, rec.Body.String())
			}
		})
	}
}
