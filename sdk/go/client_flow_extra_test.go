package guard_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	guard "github.com/corvusHold/guard/sdk/go"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestRefresh_AndLogout_Flows(t *testing.T) {
	t.Run("refresh requires stored refresh token", func(t *testing.T) {
		client, err := guard.NewGuardClient("http://localhost:8080")
		if err != nil {
			t.Fatalf("new client: %v", err)
		}

		if _, err := client.Refresh(context.Background()); err == nil || !strings.Contains(err.Error(), "no refresh token available") {
			t.Fatalf("expected no refresh token error, got %v", err)
		}
	})

	t.Run("refresh success persists rotated tokens", func(t *testing.T) {
		store := &testTokenStore{refresh: "old-refresh"}
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/v1/auth/refresh" {
				t.Fatalf("unexpected path: %s", r.URL.Path)
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token":  "new-access",
				"refresh_token": "new-refresh",
			})
		}))
		defer server.Close()

		client, err := guard.NewGuardClient(server.URL, guard.WithTokenStore(store))
		if err != nil {
			t.Fatalf("new client: %v", err)
		}
		resp, err := client.Refresh(context.Background())
		if err != nil {
			t.Fatalf("refresh failed: %v", err)
		}
		if resp.AccessToken == nil || *resp.AccessToken != "new-access" {
			t.Fatalf("unexpected refresh response: %+v", resp)
		}
		if store.access != "new-access" || store.refresh != "new-refresh" {
			t.Fatalf("expected rotated tokens persisted, got access=%q refresh=%q", store.access, store.refresh)
		}
	})

	t.Run("logout clears local tokens even on server error", func(t *testing.T) {
		store := &testTokenStore{access: "old-access", refresh: "old-refresh"}
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/v1/auth/logout" {
				t.Fatalf("unexpected path: %s", r.URL.Path)
			}
			http.Error(w, "boom", http.StatusInternalServerError)
		}))
		defer server.Close()

		client, err := guard.NewGuardClient(server.URL, guard.WithTokenStore(store))
		if err != nil {
			t.Fatalf("new client: %v", err)
		}
		err = client.Logout(context.Background())
		if err != nil {
			t.Fatalf("logout should ignore non-2xx status and return transport error only, got %v", err)
		}
		if store.access != "" || store.refresh != "" {
			t.Fatalf("expected local tokens cleared despite server error, got access=%q refresh=%q", store.access, store.refresh)
		}
	})
}

func TestMFAAndSessionsFlows(t *testing.T) {
	store := &testTokenStore{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/auth/mfa/backup/count":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"count": 7})
		case "/api/v1/auth/mfa/backup/generate":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"codes": []string{"c1", "c2"}})
		case "/api/v1/auth/mfa/backup/consume":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"consumed": true})
		case "/api/v1/auth/mfa/totp/start":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"secret": "abc", "otpauth_url": "otpauth://totp/app:user?secret=abc"})
		case "/api/v1/auth/mfa/totp/activate", "/api/v1/auth/mfa/totp/disable":
			w.WriteHeader(http.StatusNoContent)
		case "/api/v1/auth/mfa/verify":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "mfa-access", "refresh_token": "mfa-refresh"})
		case "/api/v1/auth/sessions":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"sessions": []map[string]any{{"id": "s1"}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := guard.NewGuardClient(server.URL, guard.WithTokenStore(store))
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	count, err := client.MFABackupCount(context.Background())
	if err != nil || count != 7 {
		t.Fatalf("MFABackupCount expected 7, got count=%d err=%v", count, err)
	}

	codes, err := client.MFABackupGenerate(context.Background(), nil)
	if err != nil || len(codes) != 2 {
		t.Fatalf("MFABackupGenerate expected 2 codes, got codes=%v err=%v", codes, err)
	}

	consumed, err := client.MFABackupConsume(context.Background(), "c1")
	if err != nil || !consumed {
		t.Fatalf("MFABackupConsume expected consumed=true, got consumed=%v err=%v", consumed, err)
	}

	if _, err := client.MFATOTPStart(context.Background()); err != nil {
		t.Fatalf("MFATOTPStart error: %v", err)
	}
	if err := client.MFATOTPActivate(context.Background(), "123456"); err != nil {
		t.Fatalf("MFATOTPActivate error: %v", err)
	}
	if err := client.MFATOTPDisable(context.Background()); err != nil {
		t.Fatalf("MFATOTPDisable error: %v", err)
	}

	if _, err := client.MFAVerify(context.Background(), "challenge", guard.ControllerMfaVerifyReqMethod("totp"), "123456"); err != nil {
		t.Fatalf("MFAVerify error: %v", err)
	}
	if store.access != "mfa-access" || store.refresh != "mfa-refresh" {
		t.Fatalf("expected MFA verify token persistence, got access=%q refresh=%q", store.access, store.refresh)
	}

	sessions, err := client.Sessions(context.Background())
	if err != nil || len(sessions) != 1 {
		t.Fatalf("Sessions expected 1, got sessions=%v err=%v", sessions, err)
	}
}

func TestMFAAndSessions_ErrorBranches(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/auth/mfa/backup/count":
			_ = json.NewEncoder(w).Encode(map[string]any{}) // missing count
		case "/api/v1/auth/sessions":
			w.WriteHeader(http.StatusUnauthorized)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := guard.NewGuardClient(server.URL)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	if _, err := client.MFABackupCount(context.Background()); err == nil {
		t.Fatal("expected MFABackupCount error when count field missing")
	}
	if _, err := client.Sessions(context.Background()); err == nil {
		t.Fatal("expected Sessions error for unauthorized response")
	}
}

func TestSSOStart_AndTenantSettingsValidation(t *testing.T) {
	t.Run("sso start requires tenant id", func(t *testing.T) {
		client, err := guard.NewGuardClient("http://localhost:8080")
		if err != nil {
			t.Fatalf("new client: %v", err)
		}
		if _, err := client.SSOStart(context.Background(), "workos", nil); err == nil || !strings.Contains(err.Error(), "tenant ID not configured") {
			t.Fatalf("expected tenant-id error, got %v", err)
		}
	})

	t.Run("sso start appends use_query=true and reads redirect location", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/v1/auth/sso/workos/start" {
				t.Fatalf("unexpected path: %s", r.URL.Path)
			}
			if got := r.URL.Query().Get("tenant_id"); got != "tenant-1" {
				t.Fatalf("expected tenant_id tenant-1, got %q", got)
			}
			redirect := r.URL.Query().Get("redirect_url")
			if !strings.Contains(redirect, "use_query=true") {
				t.Fatalf("expected redirect_url to include use_query=true, got %q", redirect)
			}
			w.Header().Set("Location", "https://idp.example/authorize")
			w.WriteHeader(http.StatusFound)
		}))
		defer server.Close()

		httpClient := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}}
		client, err := guard.NewGuardClient(server.URL, guard.WithTenantID("tenant-1"), guard.WithHTTPDoer(httpClient))
		if err != nil {
			t.Fatalf("new client: %v", err)
		}
		redirect := "https://app.example/callback?x=1"
		loc, err := client.SSOStart(context.Background(), "workos", &guard.SSOStartOptions{RedirectURL: &redirect, UseQueryParams: true})
		if err != nil {
			t.Fatalf("SSOStart failed: %v", err)
		}
		if loc != "https://idp.example/authorize" {
			t.Fatalf("unexpected redirect location: %q", loc)
		}
	})

	t.Run("sso start propagates transport error", func(t *testing.T) {
		failing := roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("network down")
		})
		client, err := guard.NewGuardClient("https://guard.example", guard.WithTenantID("tenant-1"), guard.WithHTTPDoer(&http.Client{Transport: failing}))
		if err != nil {
			t.Fatalf("new client: %v", err)
		}
		if _, err := client.SSOStart(context.Background(), "workos", nil); err == nil {
			t.Fatal("expected transport error")
		}
	})

	t.Run("tenant settings requires tenant id", func(t *testing.T) {
		client, err := guard.NewGuardClient("http://localhost:8080")
		if err != nil {
			t.Fatalf("new client: %v", err)
		}
		if _, err := client.GetTenantSettings(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "tenant ID required") {
			t.Fatalf("expected tenant id required for GetTenantSettings, got %v", err)
		}
		if err := client.UpdateTenantSettings(context.Background(), "", guard.ControllerPutSettingsRequest{}); err == nil || !strings.Contains(err.Error(), "tenant ID required") {
			t.Fatalf("expected tenant id required for UpdateTenantSettings, got %v", err)
		}
	})
}
