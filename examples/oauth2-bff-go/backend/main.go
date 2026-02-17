package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	guard "github.com/corvusHold/guard/sdk/go"
)

const (
	sessionCookieName = "guard_oauth_bff_session"
	pendingTTL        = 10 * time.Minute
)

//go:embed static/*
var staticFS embed.FS

type config struct {
	Port             string
	GuardBaseURL     string
	OAuthClient      string
	RedirectURI      string
	Scope            string
	ExpectedTenantID string
	ForcePromptLogin bool
}

type pendingAuth struct {
	State        string
	Nonce        string
	CodeVerifier string
	CreatedAt    time.Time
}

type session struct {
	mu           sync.Mutex
	ID           string
	AccessToken  string
	RefreshToken string
	Pending      *pendingAuth
	UpdatedAt    time.Time
}

type sessionStore struct {
	mu       sync.Mutex
	sessions map[string]*session
}

func newSessionStore() *sessionStore {
	return &sessionStore{sessions: make(map[string]*session)}
}

func (s *sessionStore) getOrCreate(w http.ResponseWriter, r *http.Request) *session {
	s.mu.Lock()
	defer s.mu.Unlock()

	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		if existing, ok := s.sessions[cookie.Value]; ok {
			existing.mu.Lock()
			existing.UpdatedAt = time.Now()
			existing.mu.Unlock()
			return existing
		}
	}

	sid := mustRandomString(24)
	sess := &session{ID: sid, UpdatedAt: time.Now()}
	s.sessions[sid] = sess
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    sid,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	return sess
}

type sessionTokenStore struct {
	sess *session
}

func (s *sessionTokenStore) Get(_ context.Context) (string, string) {
	s.sess.mu.Lock()
	defer s.sess.mu.Unlock()
	return s.sess.AccessToken, s.sess.RefreshToken
}

func (s *sessionTokenStore) Set(_ context.Context, access, refresh string) error {
	s.sess.mu.Lock()
	defer s.sess.mu.Unlock()
	s.sess.AccessToken = access
	s.sess.RefreshToken = refresh
	s.sess.UpdatedAt = time.Now()
	return nil
}

func (s *sessionTokenStore) Clear(_ context.Context) error {
	s.sess.mu.Lock()
	defer s.sess.mu.Unlock()
	s.sess.AccessToken = ""
	s.sess.RefreshToken = ""
	s.sess.UpdatedAt = time.Now()
	return nil
}

type app struct {
	cfg      config
	sessions *sessionStore
}

func main() {
	cfg := loadConfig()
	app := &app{cfg: cfg, sessions: newSessionStore()}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/config", app.handleConfig)
	mux.HandleFunc("/oauth/login", app.handleLogin)
	mux.HandleFunc("/oauth/callback", app.handleCallback)
	mux.HandleFunc("/api/me", app.handleMe)
	mux.HandleFunc("/api/logout", app.handleLogout)
	mux.HandleFunc("/api/reset", app.handleReset)
	mux.Handle("/", app.staticHandler())

	addr := ":" + cfg.Port
	log.Printf("oauth2-bff-go example running on http://localhost%s", addr)
	log.Printf("Guard base URL: %s", cfg.GuardBaseURL)
	log.Printf("Redirect URI: %s", cfg.RedirectURI)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}

func (a *app) staticHandler() http.Handler {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic(err)
	}
	return http.FileServer(http.FS(sub))
}

func (a *app) handleConfig(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"guard_base_url":       a.cfg.GuardBaseURL,
		"redirect_uri":         a.cfg.RedirectURI,
		"scope":                a.cfg.Scope,
		"expected_tenant_id":   a.cfg.ExpectedTenantID,
		"force_prompt_login":   fmt.Sprintf("%t", a.cfg.ForcePromptLogin),
		"reset_hint":           "Use POST /api/reset then /oauth/login?fresh=1",
		"tenant_policy_notice": "Users authenticated in another tenant are blocked for this app",
	})
}

func (a *app) handleLogin(w http.ResponseWriter, r *http.Request) {
	sess := a.sessions.getOrCreate(w, r)
	if r.URL.Query().Get("fresh") == "1" {
		a.clearSession(sess)
	}
	state := mustRandomString(24)
	nonce := mustRandomString(24)
	verifier := mustRandomString(48)
	challenge := codeChallengeS256(verifier)

	sess.mu.Lock()
	sess.Pending = &pendingAuth{
		State:        state,
		Nonce:        nonce,
		CodeVerifier: verifier,
		CreatedAt:    time.Now(),
	}
	sess.mu.Unlock()

	client, err := a.newClient(sess)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	params := guard.OAuth2AuthorizeParams{
		ClientID:      a.cfg.OAuthClient,
		RedirectURI:   a.cfg.RedirectURI,
		Scope:         a.cfg.Scope,
		State:         state,
		Nonce:         nonce,
		CodeChallenge: challenge,
	}
	if a.cfg.ForcePromptLogin || r.URL.Query().Get("fresh") == "1" {
		prompt := "login"
		params.Prompt = &prompt
	}
	authorizeURL, err := client.BuildOAuth2AuthorizeURL(params)
	if err != nil {
		a.redirectUIError(w, r, "invalid_authorize_request", err.Error())
		return
	}
	http.Redirect(w, r, authorizeURL, http.StatusFound)
}

func (a *app) handleCallback(w http.ResponseWriter, r *http.Request) {
	sess := a.sessions.getOrCreate(w, r)
	if errParam := strings.TrimSpace(r.URL.Query().Get("error")); errParam != "" {
		desc := r.URL.Query().Get("error_description")
		a.clearSession(sess)
		a.redirectUIError(w, r, errParam, desc)
		return
	}

	code := strings.TrimSpace(r.URL.Query().Get("code"))
	state := strings.TrimSpace(r.URL.Query().Get("state"))
	if code == "" {
		a.redirectUIError(w, r, "missing_code", "oauth callback did not contain code")
		return
	}
	sess.mu.Lock()
	pending := sess.Pending
	sess.mu.Unlock()
	if pending == nil {
		a.redirectUIError(w, r, "missing_state", "missing pending oauth session; reset and retry")
		return
	}
	if time.Since(pending.CreatedAt) > pendingTTL {
		a.clearSession(sess)
		a.redirectUIError(w, r, "state_expired", "oauth state expired; start login again")
		return
	}
	if state != pending.State {
		a.clearSession(sess)
		a.redirectUIError(w, r, "state_mismatch", "oauth state mismatch; start login again")
		return
	}

	client, err := a.newClient(sess)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	_, err = client.ExchangeOAuth2Code(r.Context(), guard.OAuth2CodeExchangeRequest{
		Code:         code,
		CodeVerifier: pending.CodeVerifier,
		RedirectURI:  a.cfg.RedirectURI,
		ClientID:     strPtr(a.cfg.OAuthClient),
	})
	if err != nil {
		a.clearSession(sess)
		a.redirectUIError(w, r, "token_exchange_failed", err.Error())
		return
	}

	profile, err := client.Me(r.Context())
	if err != nil {
		a.clearSession(sess)
		a.redirectUIError(w, r, "post_exchange_profile_failed", err.Error())
		return
	}
	if mismatch, expected, actual := a.tenantMismatch(profile); mismatch {
		a.clearSession(sess)
		a.redirectUIError(
			w,
			r,
			"tenant_access_denied",
			fmt.Sprintf("authenticated tenant %s is not allowed for this app (expected %s)", actual, expected),
		)
		return
	}

	sess.mu.Lock()
	sess.Pending = nil
	sess.mu.Unlock()
	http.Redirect(w, r, "/?auth=ok", http.StatusFound)
}

func (a *app) handleMe(w http.ResponseWriter, r *http.Request) {
	sess := a.sessions.getOrCreate(w, r)
	sess.mu.Lock()
	accessToken := sess.AccessToken
	refreshToken := sess.RefreshToken
	sess.mu.Unlock()
	if accessToken == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not authenticated"})
		return
	}

	client, err := a.newClient(sess)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	profile, err := client.Me(r.Context())
	if err != nil {
		originalErr := err
		if refreshToken != "" && isAuthRelatedError(originalErr) {
			if _, rerr := client.OAuth2Refresh(r.Context(), guard.OAuth2RefreshRequest{ClientID: strPtr(a.cfg.OAuthClient)}); rerr == nil {
				profile, err = client.Me(r.Context())
			} else {
				err = fmt.Errorf("%w (refresh failed: %v)", originalErr, rerr)
			}
		} else {
			err = originalErr
		}
	}
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "failed to load profile: " + err.Error()})
		return
	}
	if mismatch, expected, actual := a.tenantMismatch(profile); mismatch {
		a.clearSession(sess)
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error":                "tenant_access_denied",
			"message":              fmt.Sprintf("authenticated tenant %s is not allowed for this app", actual),
			"expected_tenant_id":   expected,
			"action":               "POST /api/reset then login with allowed tenant",
			"fresh_login_endpoint": "/oauth/login?fresh=1",
		})
		return
	}

	writeJSON(w, http.StatusOK, profile)
}

func (a *app) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	sess := a.sessions.getOrCreate(w, r)
	client, err := a.newClient(sess)
	if err == nil {
		_ = client.Logout(r.Context())
	}
	a.clearSession(sess)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *app) handleReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	sess := a.sessions.getOrCreate(w, r)
	a.clearSession(sess)
	writeJSON(w, http.StatusOK, map[string]string{
		"status":               "reset",
		"next":                 "/oauth/login?fresh=1",
		"message":              "local BFF session reset; login again with an allowed tenant user",
		"expected_tenant_id":   a.cfg.ExpectedTenantID,
		"tenant_access_policy": "users from other tenants are blocked",
	})
}

func (a *app) newClient(sess *session) (*guard.GuardClient, error) {
	if sess == nil {
		return nil, errors.New("session required")
	}
	return guard.NewGuardClient(
		a.cfg.GuardBaseURL,
		guard.WithAuthMode(guard.AuthModeBearer),
		guard.WithTokenStore(&sessionTokenStore{sess: sess}),
	)
}

func (a *app) clearSession(sess *session) {
	if sess == nil {
		return
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()
	sess.Pending = nil
	sess.AccessToken = ""
	sess.RefreshToken = ""
	sess.UpdatedAt = time.Now()
}

func isAuthRelatedError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unauthorized") ||
		strings.Contains(msg, "401") ||
		strings.Contains(msg, "expired") ||
		strings.Contains(msg, "invalid token")
}

func (a *app) tenantMismatch(profile *guard.DomainUserProfile) (bool, string, string) {
	expected := strings.TrimSpace(a.cfg.ExpectedTenantID)
	if expected == "" {
		return false, "", ""
	}
	actual := ""
	if profile != nil && profile.TenantId != nil {
		actual = strings.TrimSpace(*profile.TenantId)
	}
	if actual == "" {
		return true, expected, "<none>"
	}
	if actual != expected {
		return true, expected, actual
	}
	return false, expected, actual
}

func (a *app) redirectUIError(w http.ResponseWriter, r *http.Request, code, message string) {
	q := url.Values{}
	q.Set("auth", "error")
	q.Set("error", code)
	if strings.TrimSpace(message) != "" {
		q.Set("message", message)
	}
	http.Redirect(w, r, "/?"+q.Encode(), http.StatusFound)
}

func loadConfig() config {
	cfg := config{
		Port:             envOr("PORT", "3004"),
		GuardBaseURL:     strings.TrimSpace(envOr("GUARD_BASE_URL", "http://localhost:8080")),
		OAuthClient:      strings.TrimSpace(os.Getenv("OAUTH_CLIENT_ID")),
		RedirectURI:      strings.TrimSpace(os.Getenv("OAUTH_REDIRECT_URI")),
		Scope:            strings.TrimSpace(envOr("OAUTH_SCOPE", "openid profile email offline_access")),
		ExpectedTenantID: strings.TrimSpace(os.Getenv("TENANT_ID")),
		ForcePromptLogin: parseBoolEnv("BFF_FORCE_PROMPT_LOGIN", true),
	}
	if cfg.OAuthClient == "" {
		log.Fatal("missing OAUTH_CLIENT_ID")
	}
	if cfg.RedirectURI == "" {
		cfg.RedirectURI = fmt.Sprintf("http://localhost:%s/oauth/callback", cfg.Port)
	}
	return cfg
}

func mustRandomString(byteLen int) string {
	b := make([]byte, byteLen)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func codeChallengeS256(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func strPtr(v string) *string {
	return &v
}

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func parseBoolEnv(key string, fallback bool) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	if v == "" {
		return fallback
	}
	switch v {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}
