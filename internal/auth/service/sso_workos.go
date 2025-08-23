package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/corvusHold/guard/internal/auth/domain"
	evdomain "github.com/corvusHold/guard/internal/events/domain"
	sdomain "github.com/corvusHold/guard/internal/settings/domain"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// startWorkOS builds the WorkOS authorization URL using tenant-scoped settings.
// It stores the state in Redis for CSRF protection and supports both connection_id and organization_id.
func (s *SSO) startWorkOS(ctx context.Context, in domain.SSOStartInput) (string, error) {
	clientID, err := s.settings.GetString(ctx, sdomain.KeyWorkOSClientID, &in.TenantID, "")
	if err != nil {
		return "", err
	}
	if clientID == "" {
		return "", errors.New("workos client_id missing")
	}

	baseURL, _ := s.settings.GetString(ctx, sdomain.KeyPublicBaseURL, &in.TenantID, s.cfg.PublicBaseURL)
	// redirect_uri: prefer explicit in.RedirectURL when provided and absolute; else fall back to our API callback
	var redirectURI string
	if ru := strings.TrimSpace(in.RedirectURL); ru != "" {
		if parsed, err := url.Parse(ru); err == nil && parsed.IsAbs() {
			redirectURI = parsed.String()
		}
	}
	if redirectURI == "" {
		cb, err := url.Parse(baseURL)
		if err != nil {
			return "", err
		}
		cb.Path = "/v1/auth/sso/" + in.Provider + "/callback"
		redirectURI = cb.String()
	}

	// Prepare state and store in Redis with short TTL
	state := in.State
	if state == "" {
		buf := make([]byte, 32)
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		state = base64.RawURLEncoding.EncodeToString(buf)
	}
	stateTTL, _ := s.settings.GetDuration(ctx, sdomain.KeySSOStateTTL, &in.TenantID, 10*time.Minute)
	// Store JSON with tenant_id and redirect_uri for callback use (backward compatible parsing)
	meta := map[string]string{"tenant_id": in.TenantID.String(), "redirect_uri": redirectURI}
	if b, err := json.Marshal(meta); err == nil {
		if err := s.redis.Set(ctx, "sso:state:"+state, string(b), stateTTL).Err(); err != nil {
			return "", err
		}
	} else {
		// Fallback: store tenant ID only
		if err := s.redis.Set(ctx, "sso:state:"+state, in.TenantID.String(), stateTTL).Err(); err != nil {
			return "", err
		}
	}

	// Resolve optional targeting parameters: prefer request input, else tenant-scoped defaults
	connID := strings.TrimSpace(in.ConnectionID)
	if connID == "" {
		if v, _ := s.settings.GetString(ctx, sdomain.KeyWorkOSDefaultConnectionID, &in.TenantID, ""); v != "" {
			connID = v
		}
	}
	orgID := strings.TrimSpace(in.OrganizationID)
	if orgID == "" {
		if v, _ := s.settings.GetString(ctx, sdomain.KeyWorkOSDefaultOrganizationID, &in.TenantID, ""); v != "" {
			orgID = v
		}
	}

	u, _ := url.Parse("https://api.workos.com/sso/authorize")
	q := u.Query()
	q.Set("client_id", clientID)
	// WorkOS requires response_type=code
	q.Set("response_type", "code")
	q.Set("redirect_uri", redirectURI)
	q.Set("state", state)
	// Map to WorkOS parameter names: connection / organization
	if connID != "" {
		q.Set("connection", connID)
	}
	if orgID != "" {
		q.Set("organization", orgID)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// callbackWorkOS validates state from Redis, and exchanges code via /sso/token using client_id and client_secret from settings,
// parses profile email, upserts user, and issues tokens.
func (s *SSO) callbackWorkOS(ctx context.Context, in domain.SSOCallbackInput) (domain.AccessTokens, error) {
	// Validate state
	stVals := in.Query["state"]
	if len(stVals) == 0 || stVals[0] == "" {
		// publish failure (no tenant identified)
		_ = s.pub.Publish(ctx, evdomain.Event{
			Type:     "auth.sso.login.failure",
			TenantID: uuid.Nil,
			Meta:     map[string]string{"provider": in.Provider, "reason": "missing_state", "ip": in.IP, "user_agent": in.UserAgent},
			Time:     time.Now(),
		})
		return domain.AccessTokens{}, errors.New("missing state")
	}
	state := stVals[0]
	// Atomically GET and DEL state to prevent race/replay
	key := "sso:state:" + state
	script := "local v = redis.call('GET', KEYS[1]); if v then redis.call('DEL', KEYS[1]) end; return v"
	res, err := s.redis.Eval(ctx, script, []string{key}).Result()
	if err != nil || res == nil {
		_ = s.pub.Publish(ctx, evdomain.Event{
			Type:     "auth.sso.login.failure",
			TenantID: uuid.Nil,
			Meta:     map[string]string{"provider": in.Provider, "reason": "invalid_state", "ip": in.IP, "user_agent": in.UserAgent},
			Time:     time.Now(),
		})
		return domain.AccessTokens{}, errors.New("invalid state")
	}
	tenStr, _ := res.(string)

	// Backward-compatible state payload: either plain tenant UUID string, or JSON {tenant_id, redirect_uri}
	var tenantID uuid.UUID
	var stateRedirectURI string
	type stateMeta struct {
		TenantID    string `json:"tenant_id"`
		RedirectURI string `json:"redirect_uri"`
	}
	var sm stateMeta
	if strings.HasPrefix(strings.TrimSpace(tenStr), "{") && json.Unmarshal([]byte(tenStr), &sm) == nil && sm.TenantID != "" {
		if tID, err := uuid.Parse(sm.TenantID); err == nil {
			tenantID = tID
			stateRedirectURI = strings.TrimSpace(sm.RedirectURI)
		} else {
			return domain.AccessTokens{}, errors.New("invalid tenant for state")
		}
	} else {
		// legacy format: just the tenant UUID
		tID, err := uuid.Parse(strings.TrimSpace(tenStr))
		if err != nil {
			return domain.AccessTokens{}, errors.New("invalid tenant for state")
		}
		tenantID = tID
	}

	// Extract authorization code
	cv := in.Query["code"]
	if len(cv) == 0 || strings.TrimSpace(cv[0]) == "" {
		_ = s.pub.Publish(ctx, evdomain.Event{
			Type:     "auth.sso.login.failure",
			TenantID: tenantID,
			Meta:     map[string]string{"provider": in.Provider, "reason": "code_required", "ip": in.IP, "user_agent": in.UserAgent},
			Time:     time.Now(),
		})
		return domain.AccessTokens{}, errors.New("code required")
	}
	code := strings.TrimSpace(cv[0])

	// Load WorkOS credentials
	clientID, err := s.settings.GetString(ctx, sdomain.KeyWorkOSClientID, &tenantID, "")
	if err != nil || clientID == "" {
		_ = s.pub.Publish(ctx, evdomain.Event{Type: "auth.sso.login.failure", TenantID: tenantID, Meta: map[string]string{"provider": in.Provider, "reason": "workos_client_id_missing"}, Time: time.Now()})
		return domain.AccessTokens{}, errors.New("workos client_id missing")
	}
	clientSecret, _ := s.settings.GetString(ctx, sdomain.KeyWorkOSClientSecret, &tenantID, "")
	if clientSecret == "" {
		// fallback to API key if client_secret not set
		clientSecret, _ = s.settings.GetString(ctx, sdomain.KeyWorkOSAPIKey, &tenantID, "")
	}
	if clientSecret == "" {
		_ = s.pub.Publish(ctx, evdomain.Event{Type: "auth.sso.login.failure", TenantID: tenantID, Meta: map[string]string{"provider": in.Provider, "reason": "workos_client_secret_missing"}, Time: time.Now()})
		return domain.AccessTokens{}, errors.New("workos client_secret missing")
	}

	// Reconstruct redirect_uri to match startWorkOS: prefer value stored in state, else fallback to API callback
	var redirectURI string
	if stateRedirectURI != "" {
		redirectURI = stateRedirectURI
	} else {
		baseURL, _ := s.settings.GetString(ctx, sdomain.KeyPublicBaseURL, &tenantID, s.cfg.PublicBaseURL)
		cb, err := url.Parse(baseURL)
		if err != nil {
			return domain.AccessTokens{}, err
		}
		cb.Path = "/v1/auth/sso/" + in.Provider + "/callback"
		redirectURI = cb.String()
	}

	// Exchange code for profile + token
	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.workos.com/sso/token", strings.NewReader(form.Encode()))
	if err != nil {
		_ = s.pub.Publish(ctx, evdomain.Event{Type: "auth.sso.login.failure", TenantID: tenantID, Meta: map[string]string{"provider": in.Provider, "reason": "http_request_build_error"}, Time: time.Now()})
		return domain.AccessTokens{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	httpClient := &http.Client{Timeout: 10 * time.Second}
	resp, err := httpClient.Do(req)
	if err != nil {
		_ = s.pub.Publish(ctx, evdomain.Event{Type: "auth.sso.login.failure", TenantID: tenantID, Meta: map[string]string{"provider": in.Provider, "reason": "token_exchange_transport_error"}, Time: time.Now()})
		return domain.AccessTokens{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_ = s.pub.Publish(ctx, evdomain.Event{Type: "auth.sso.login.failure", TenantID: tenantID, Meta: map[string]string{"provider": in.Provider, "reason": "token_exchange_failed", "status": resp.Status}, Time: time.Now()})
		return domain.AccessTokens{}, errors.New("workos token exchange failed")
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		Profile     struct {
			ID        string `json:"id"`
			Email     string `json:"email"`
			FirstName string `json:"first_name"`
			LastName  string `json:"last_name"`
		} `json:"profile"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		_ = s.pub.Publish(ctx, evdomain.Event{Type: "auth.sso.login.failure", TenantID: tenantID, Meta: map[string]string{"provider": in.Provider, "reason": "token_decode_error"}, Time: time.Now()})
		return domain.AccessTokens{}, err
	}
	email := strings.TrimSpace(tokenResp.Profile.Email)
	if email == "" {
		_ = s.pub.Publish(ctx, evdomain.Event{Type: "auth.sso.login.failure", TenantID: tenantID, Meta: map[string]string{"provider": in.Provider, "reason": "profile_missing_email"}, Time: time.Now()})
		return domain.AccessTokens{}, errors.New("workos profile missing email")
	}

	// Find or create identity
	var userID uuid.UUID
	if ai, err := s.repo.GetAuthIdentityByEmailTenant(ctx, tenantID, email); err == nil {
		userID = ai.UserID
		_ = s.repo.UpdateUserLoginAt(ctx, userID)
	} else {
		userID = uuid.New()
		if err := s.repo.CreateUser(ctx, userID, tokenResp.Profile.FirstName, tokenResp.Profile.LastName, []string{}); err != nil {
			return domain.AccessTokens{}, err
		}
		if err := s.repo.CreateAuthIdentity(ctx, uuid.New(), userID, tenantID, email, ""); err != nil {
			return domain.AccessTokens{}, err
		}
		if err := s.repo.AddUserToTenant(ctx, userID, tenantID); err != nil {
			return domain.AccessTokens{}, err
		}
	}

	// Issue tokens
	signingKey, _ := s.settings.GetString(ctx, sdomain.KeyJWTSigning, &tenantID, s.cfg.JWTSigningKey)
	accessTTL, _ := s.settings.GetDuration(ctx, sdomain.KeyAccessTTL, &tenantID, s.cfg.AccessTokenTTL)
	refreshTTL, _ := s.settings.GetDuration(ctx, sdomain.KeyRefreshTTL, &tenantID, s.cfg.RefreshTokenTTL)
	issuer, _ := s.settings.GetString(ctx, sdomain.KeyJWTIssuer, &tenantID, s.cfg.PublicBaseURL)
	audience, _ := s.settings.GetString(ctx, sdomain.KeyJWTAudience, &tenantID, s.cfg.PublicBaseURL)

	accClaims := jwt.MapClaims{
		"sub": userID.String(),
		"ten": tenantID.String(),
		"exp": time.Now().Add(accessTTL).Unix(),
		"iat": time.Now().Unix(),
		"iss": issuer,
		"aud": audience,
	}
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, accClaims)
	access, err := at.SignedString([]byte(signingKey))
	if err != nil {
		return domain.AccessTokens{}, err
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return domain.AccessTokens{}, err
	}
	rt := base64.RawURLEncoding.EncodeToString(raw)
	rh := sha256.Sum256([]byte(rt))
	hashB64 := base64.RawURLEncoding.EncodeToString(rh[:])
	expiresAt := time.Now().Add(refreshTTL)
	if err := s.repo.InsertRefreshToken(ctx, uuid.New(), userID, tenantID, hashB64, nil, in.UserAgent, in.IP, expiresAt); err != nil {
		return domain.AccessTokens{}, err
	}
	// Publish audit event
	_ = s.pub.Publish(ctx, evdomain.Event{
		Type:     "auth.sso.login.success",
		TenantID: tenantID,
		UserID:   userID,
		Meta:     map[string]string{"provider": in.Provider, "ip": in.IP, "user_agent": in.UserAgent, "email": email},
		Time:     time.Now(),
	})
	return domain.AccessTokens{AccessToken: access, RefreshToken: rt}, nil
}
