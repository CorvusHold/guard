package service

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
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

var compatibleWorkOSIntents = map[string]struct{}{"sso": {}, "dsync": {}, "audit_logs": {}, "log_streams": {}, "domain_verification": {}, "certificate_renewal": {}}

// httpDoWithRetry executes the request builder up to 3 attempts with a short
// exponential backoff on transient network errors or 5xx responses.
func httpDoWithRetry(ctx context.Context, client *http.Client, build func() (*http.Request, error)) (*http.Response, error) {
	const maxAttempts = 3
	backoffs := []time.Duration{200 * time.Millisecond, 500 * time.Millisecond}
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		req, err := build()
		if err != nil {
			return nil, err
		}
		resp, err := client.Do(req)
		if err != nil {
			// Retry network timeouts/temporary errors
			if ne, ok := err.(net.Error); ok && (ne.Timeout()) {
				if attempt < maxAttempts {
					if attempt-1 < len(backoffs) {
						time.Sleep(backoffs[attempt-1])
					} else {
						time.Sleep(1 * time.Second)
					}
					continue
				}
			}
			// Non-network error: try again if attempts remain
			if attempt < maxAttempts {
				if attempt-1 < len(backoffs) {
					time.Sleep(backoffs[attempt-1])
				} else {
					time.Sleep(1 * time.Second)
				}
				continue
			}
			return nil, err
		}
		// Retry on 5xx
		if resp.StatusCode >= 500 && resp.StatusCode <= 599 && attempt < maxAttempts {
			// drain and close before retry
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if attempt-1 < len(backoffs) {
				time.Sleep(backoffs[attempt-1])
			} else {
				time.Sleep(1 * time.Second)
			}
			continue
		}
		return resp, nil
	}
	return nil, errors.New("exhausted retries")
}

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

	// Build WorkOS authorize URL using tenant-scoped API base
	apiBase, _ := s.settings.GetString(ctx, sdomain.KeyWorkOSAPIBaseURL, &in.TenantID, "https://api.workos.com")
	u, _ := url.Parse(strings.TrimRight(apiBase, "/"))
	u.Path = "/sso/authorize"
	// u, _ := url.Parse("https://api.workos.com/sso/authorize")
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

	apiBase, _ := s.settings.GetString(ctx, sdomain.KeyWorkOSAPIBaseURL, &tenantID, "https://api.workos.com")
	tokenURL := strings.TrimRight(apiBase, "/") + "/sso/token"

	buildReq := func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return req, nil
	}

	httpClient := &http.Client{Timeout: 5 * time.Second}
	resp, err := httpDoWithRetry(ctx, httpClient, buildReq)
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
	if err := s.repo.InsertRefreshToken(ctx, uuid.New(), userID, tenantID, hashB64, nil, in.UserAgent, in.IP, expiresAt, "sso", nil); err != nil {
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

func (s *SSO) OrganizationPortalLinkGeneratorWorkOS(ctx context.Context, in domain.SSOOrganizationPortalLinkGeneratorInput) (plink domain.PortalLink, err error) {
	s.log.Info().
		Str("provider", in.Provider).
		Str("tenant_id", in.TenantID.String()).
		Str("organization_id", in.OrganizationID).
		Str("intent", strings.TrimSpace(in.Intent)).
		Msg("sso.portal_link:start")
	if in.Provider != "workos" {
		s.log.Error().Str("provider", in.Provider).Msg("sso.portal_link:error:provider_not_supported")
		return domain.PortalLink{}, errors.New("provider not supported")
	}
	orgID := in.OrganizationID
	if orgID == "" {
		s.log.Error().Str("tenant_id", in.TenantID.String()).Msg("sso.portal_link:error:organization_id_required")
		return domain.PortalLink{}, errors.New("organization ID not provided")
	}
	tenantID := in.TenantID.String()
	if tenantID == "" {
		s.log.Error().Msg("sso.portal_link:error:tenant_id_required")
		return domain.PortalLink{}, errors.New("tenant ID not provided")
	}
	// GET TENANT SSO CONFIG
	settingProvider, err := s.settings.GetString(ctx, sdomain.KeySSOProvider, &in.TenantID, "")
	if err != nil {
		s.log.Error().Str("tenant_id", in.TenantID.String()).Err(err).Msg("sso.portal_link:error:get_sso_provider")
		return domain.PortalLink{}, err
	}
	if settingProvider != "workos" {
		s.log.Error().Str("tenant_id", in.TenantID.String()).Str("sso_provider", settingProvider).Msg("sso.portal_link:error:tenant_provider_mismatch")
		return domain.PortalLink{}, errors.New("provider not workos")
	}
	apiKey, err := s.settings.GetString(ctx, sdomain.KeyWorkOSAPIKey, &in.TenantID, "")
	if err != nil {
		s.log.Error().Str("tenant_id", in.TenantID.String()).Err(err).Msg("sso.portal_link:error:get_api_key")
		return domain.PortalLink{}, err
	}
	if apiKey == "" {
		s.log.Error().Str("tenant_id", in.TenantID.String()).Msg("sso.portal_link:error:api_key_missing")
		return domain.PortalLink{}, errors.New("workos api key not configured")
	}
	// Map custom intents and default when empty
	intent := strings.TrimSpace(in.Intent)
	if intent == "" {
		intent = "sso"
	}
	if intent == "user_management" {
		intent = "sso"
	}
	if _, ok := compatibleWorkOSIntents[intent]; !ok {
		s.log.Error().Str("tenant_id", in.TenantID.String()).Str("intent", intent).Msg("sso.portal_link:error:intent_incompatible")
		return domain.PortalLink{}, errors.New("intent not compatible with workos")
	}
	s.log.Debug().
		Str("tenant_id", in.TenantID.String()).
		Str("organization_id", orgID).
		Str("intent", intent).
		Msg("sso.portal_link:build_payload")
	type payload struct {
		Organization string `json:"organization"`
		Intent       string `json:"intent"`
	}
	p := &payload{Organization: orgID, Intent: intent}
	b, err := json.Marshal(p)
	if err != nil {
		_ = s.pub.Publish(ctx, evdomain.Event{Type: "auth.sso.portal_link_generator.failure", TenantID: in.TenantID, Meta: map[string]string{"provider": in.Provider, "reason": "json_marshalling_error"}, Time: time.Now()})
		s.log.Error().Str("tenant_id", in.TenantID.String()).Err(err).Msg("sso.portal_link:error:json_marshal")
		return domain.PortalLink{}, err
	}
	apiBase, _ := s.settings.GetString(ctx, sdomain.KeyWorkOSAPIBaseURL, &in.TenantID, "https://api.workos.com")
	portalURL := strings.TrimRight(apiBase, "/") + "/portal/generate_link"
	s.log.Debug().Str("tenant_id", in.TenantID.String()).Str("portal_url", portalURL).Msg("sso.portal_link:http_request:build")
	buildReq := func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, portalURL, bytes.NewReader(b))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+apiKey)
		req.Header.Set("Content-Type", "application/json")
		return req, nil
	}

	httpClient := &http.Client{Timeout: 5 * time.Second}
	resp, err := httpDoWithRetry(ctx, httpClient, buildReq)
	if err != nil {
		_ = s.pub.Publish(ctx, evdomain.Event{Type: "auth.sso.portal_link_generator.failure", TenantID: in.TenantID, Meta: map[string]string{"provider": in.Provider, "reason": "http_request_transport_error", "intent": intent}, Time: time.Now()})
		s.log.Error().Str("tenant_id", in.TenantID.String()).Str("intent", intent).Err(err).Msg("sso.portal_link:error:http_transport")
		return domain.PortalLink{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		_ = s.pub.Publish(ctx, evdomain.Event{Type: "auth.sso.portal_link_generator.failure", TenantID: in.TenantID, Meta: map[string]string{"provider": in.Provider, "reason": "http_request_read_error", "intent": intent}, Time: time.Now()})
		s.log.Error().Str("tenant_id", in.TenantID.String()).Str("intent", intent).Err(err).Msg("sso.portal_link:error:http_read")
		return domain.PortalLink{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_ = s.pub.Publish(ctx, evdomain.Event{Type: "auth.sso.portal_link_generator.failure", TenantID: in.TenantID, Meta: map[string]string{"provider": in.Provider, "reason": "http_request_failed", "status": resp.Status, "intent": intent}, Time: time.Now()})
		s.log.Error().
			Str("tenant_id", in.TenantID.String()).
			Str("intent", intent).
			Int("status_code", resp.StatusCode).
			Msg("sso.portal_link:error:http_status")
		return domain.PortalLink{}, errors.New(string(body))
	}
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		_ = s.pub.Publish(ctx, evdomain.Event{Type: "auth.sso.portal_link_generator.failure", TenantID: in.TenantID, Meta: map[string]string{"provider": in.Provider, "reason": "http_request_unmarshal_error", "intent": intent}, Time: time.Now()})
		s.log.Error().Str("tenant_id", in.TenantID.String()).Str("intent", intent).Err(err).Msg("sso.portal_link:error:unmarshal")
		return domain.PortalLink{}, err
	}
	if link, ok := result["link"].(string); ok {
		_ = s.pub.Publish(ctx, evdomain.Event{Type: "auth.sso.portal_link_generator.success", TenantID: in.TenantID, Meta: map[string]string{"provider": in.Provider, "link": link, "intent": intent}, Time: time.Now()})
		// Avoid logging the full link; capture host only for observability
		if u, err := url.Parse(link); err == nil {
			s.log.Info().
				Str("tenant_id", in.TenantID.String()).
				Str("intent", intent).
				Str("organization_id", orgID).
				Str("link_host", u.Host).
				Msg("sso.portal_link:success")
		} else {
			s.log.Info().
				Str("tenant_id", in.TenantID.String()).
				Str("intent", intent).
				Str("organization_id", orgID).
				Msg("sso.portal_link:success")
		}
		return domain.PortalLink{Link: link}, nil
	}
	_ = s.pub.Publish(ctx, evdomain.Event{Type: "auth.sso.portal_link_generator.failure", TenantID: in.TenantID, Meta: map[string]string{"provider": in.Provider, "reason": "http_request_invalid_response", "response": string(body), "intent": intent}, Time: time.Now()})
	s.log.Error().Str("tenant_id", in.TenantID.String()).Str("intent", intent).Msg("sso.portal_link:error:invalid_response")
	return domain.PortalLink{}, errors.New("workos http request invalid response")
}
