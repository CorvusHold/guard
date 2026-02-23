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

func TestClient_Magic_Introspect_TenantSettings_ListTenants(t *testing.T) {
	store := &testTokenStore{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/auth/magic/send":
			w.WriteHeader(http.StatusNoContent)
		case "/api/v1/auth/magic/verify":
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "magic-access", "refresh_token": "magic-refresh"})
		case "/api/v1/auth/introspect":
			_ = json.NewEncoder(w).Encode(map[string]any{"active": true, "sub": "u1", "tenant_id": "t1"})
		case "/api/v1/tenants/tenant-1/settings":
			if r.Method == http.MethodGet {
				_ = json.NewEncoder(w).Encode(map[string]any{"sso_provider": "workos"})
				return
			}
			w.WriteHeader(http.StatusNoContent)
		case "/api/v1/tenants":
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]any{{"id": "tenant-1", "name": "Acme"}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := guard.NewGuardClient(server.URL, guard.WithTenantID("tenant-1"), guard.WithTokenStore(store))
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	if err := client.MagicSend(context.Background(), guard.ControllerMagicSendReq{Email: "u@example.com"}); err != nil {
		t.Fatalf("MagicSend: %v", err)
	}
	if _, err := client.MagicVerify(context.Background(), "token-1"); err != nil {
		t.Fatalf("MagicVerify: %v", err)
	}
	if store.access != "magic-access" || store.refresh != "magic-refresh" {
		t.Fatalf("expected magic tokens persisted, got access=%q refresh=%q", store.access, store.refresh)
	}

	in, err := client.Introspect(context.Background(), nil)
	if err != nil {
		t.Fatalf("Introspect: %v", err)
	}
	if in == nil {
		t.Fatal("expected introspection payload")
	}

	if _, err := client.GetTenantSettings(context.Background(), ""); err != nil {
		t.Fatalf("GetTenantSettings with default tenant: %v", err)
	}
	if err := client.UpdateTenantSettings(context.Background(), "", guard.ControllerPutSettingsRequest{}); err != nil {
		t.Fatalf("UpdateTenantSettings with default tenant: %v", err)
	}

	list, err := client.ListTenants(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTenants: %v", err)
	}
	if list == nil {
		t.Fatal("expected tenant list payload")
	}
}

func TestClient_LowBranchErrors_AndAPIKey(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/auth/me":
			if got := r.Header.Get("X-Guard-API-Key"); got != "api-key-1" {
				http.Error(w, "missing api key", http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "u1"})
		case "/api/v1/auth/magic/send":
			http.Error(w, "boom", http.StatusInternalServerError)
		case "/api/v1/auth/magic/verify":
			http.Error(w, "boom", http.StatusUnauthorized)
		case "/api/v1/auth/sso/workos/portal-link":
			if r.URL.Query().Get("tenant_id") != "tenant-1" {
				http.Error(w, "missing tenant", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"link": "https://portal.example"})
		case "/api/v1/auth/sso/workos/callback":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "cb-access", "refresh_token": "cb-refresh"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	store := &testTokenStore{}
	client, err := guard.NewGuardClient(server.URL, guard.WithTenantID("tenant-1"), guard.WithTokenStore(store), guard.WithAPIKey("api-key-1"))
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	if _, err := client.Me(context.Background()); err != nil {
		t.Fatalf("Me with api key: %v", err)
	}
	if err := client.MagicSend(context.Background(), guard.ControllerMagicSendReq{Email: "u@example.com"}); err != nil {
		t.Fatalf("MagicSend should only return transport errors, got %v", err)
	}
	if _, err := client.MagicVerify(context.Background(), "bad"); err == nil {
		t.Fatal("expected MagicVerify error for non-200")
	}

	intent := "user_management"
	link, err := client.SSOPortalLink(context.Background(), "workos", "org_1", &intent)
	if err != nil || !strings.Contains(link, "portal.example") {
		t.Fatalf("SSOPortalLink unexpected result link=%q err=%v", link, err)
	}

	cb, err := client.SSOCallback(context.Background(), "workos", "code-1", "state-1")
	if err != nil || cb == nil {
		t.Fatalf("SSOCallback unexpected result resp=%+v err=%v", cb, err)
	}
	if store.access != "cb-access" || store.refresh != "cb-refresh" {
		t.Fatalf("expected callback token persistence, got access=%q refresh=%q", store.access, store.refresh)
	}

	clientNoTenant, err := guard.NewGuardClient(server.URL)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	if _, err := clientNoTenant.SSOPortalLink(context.Background(), "workos", "org_1", nil); err == nil {
		t.Fatal("expected tenant id required error for SSOPortalLink")
	}
}
