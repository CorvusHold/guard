package guard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"sync"
)

// TokenStore abstracts access/refresh token persistence.
// Implementations may persist tokens in memory, files, keychain, etc.
type TokenStore interface {
	Get(ctx context.Context) (access, refresh string)
	Set(ctx context.Context, access, refresh string) error
	Clear(ctx context.Context) error
}

// MemoryTokenStore is an in-memory TokenStore implementation.
type MemoryTokenStore struct {
	mu      sync.RWMutex
	access  string
	refresh string
}

func (m *MemoryTokenStore) Get(_ context.Context) (string, string) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.access, m.refresh
}

func (m *MemoryTokenStore) Set(_ context.Context, access, refresh string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.access = access
	m.refresh = refresh
	return nil
}

func (m *MemoryTokenStore) Clear(_ context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.access = ""
	m.refresh = ""
	return nil
}

// AuthMode defines the authentication mode for the client.
type AuthMode string

const (
	// AuthModeBearer uses Bearer token authentication (tokens in Authorization header)
	AuthModeBearer AuthMode = "bearer"
	// AuthModeCookie uses cookie-based authentication (tokens in HTTP-only cookies)
	AuthModeCookie AuthMode = "cookie"
)

// GuardClient provides ergonomic, typed helpers over the generated client.
type GuardClient struct {
	baseURL  string
	tenantID string
	authMode AuthMode

	inner      *ClientWithResponses
	httpClient HttpRequestDoer
	tokens     TokenStore
}

// SSOPortalSession represents the minimal portal session context returned by the API.
type SSOPortalSession struct {
	TenantID      string `json:"tenant_id"`
	ProviderSlug  string `json:"provider_slug"`
	PortalTokenID string `json:"portal_token_id"`
}

// GuardOption customizes GuardClient construction.
type GuardOption func(*GuardClient) error

// WithTenantID sets a default tenant ID used when the request payload/params omit it.
func WithTenantID(tenantID string) GuardOption {
	return func(c *GuardClient) error {
		c.tenantID = tenantID
		return nil
	}
}

// WithHTTPDoer overrides the underlying HTTP client used by the SDK.
func WithHTTPDoer(h HttpRequestDoer) GuardOption {
	return func(c *GuardClient) error {
		c.httpClient = h
		return nil
	}
}

// WithTokenStore configures a custom token store implementation.
func WithTokenStore(ts TokenStore) GuardOption {
	return func(c *GuardClient) error {
		c.tokens = ts
		return nil
	}
}

// WithAuthMode sets the authentication mode (bearer or cookie).
func WithAuthMode(mode AuthMode) GuardOption {
	return func(c *GuardClient) error {
		c.authMode = mode
		return nil
	}
}

// WithCookieJar enables cookie storage for cookie mode authentication.
// This creates an HTTP client with a cookie jar if one isn't already configured.
func WithCookieJar() GuardOption {
	return func(c *GuardClient) error {
		jar, err := cookiejar.New(nil)
		if err != nil {
			return err
		}

		if c.httpClient == nil {
			c.httpClient = &http.Client{Jar: jar}
		} else if client, ok := c.httpClient.(*http.Client); ok {
			client.Jar = jar
		}

		return nil
	}
}

// NewGuardClient constructs a new ergonomic client on top of the generated client.
func NewGuardClient(baseURL string, opts ...GuardOption) (*GuardClient, error) {
	gc := &GuardClient{
		baseURL:  baseURL,
		tokens:   &MemoryTokenStore{},
		authMode: AuthModeBearer, // default to bearer mode
	}
	for _, o := range opts {
		if err := o(gc); err != nil {
			return nil, err
		}
	}

	clientOpts := []ClientOption{WithRequestEditorFn(gc.authEditor)}
	if gc.httpClient != nil {
		clientOpts = append(clientOpts, WithHTTPClient(gc.httpClient))
	}

	inner, err := NewClientWithResponses(baseURL, clientOpts...)
	if err != nil {
		return nil, err
	}
	gc.inner = inner
	return gc, nil
}

// authEditor injects Authorization header (bearer mode) or X-Auth-Mode header (cookie mode).
func (c *GuardClient) authEditor(_ context.Context, req *http.Request) error {
	if c.authMode == AuthModeCookie {
		// In cookie mode, set X-Auth-Mode header to signal backend
		req.Header.Set("X-Auth-Mode", "cookie")
	} else {
		// In bearer mode, attach Authorization header if token present
		access, _ := c.tokens.Get(context.Background())
		if access != "" {
			req.Header.Set("Authorization", "Bearer "+access)
		}
	}
	return nil
}

// persistTokens saves tokens to the token store if present (bearer mode only).
// In cookie mode, tokens are stored in HTTP-only cookies by the server.
func (c *GuardClient) persistTokens(ctx context.Context, t *ControllerAuthExchangeResp) error {
	if c.authMode == AuthModeCookie {
		// In cookie mode, tokens are in HTTP-only cookies; don't persist locally
		return nil
	}
	if t == nil {
		return nil
	}
	var access, refresh string
	if t.AccessToken != nil {
		access = *t.AccessToken
	}
	if t.RefreshToken != nil {
		refresh = *t.RefreshToken
	}
	if access == "" && refresh == "" {
		return nil
	}
	return c.tokens.Set(ctx, access, refresh)
}

// PasswordLogin performs email/password login. On 200 returns tokens; on 202 returns MFA challenge.
// It also persists tokens into the configured TokenStore.
func (c *GuardClient) PasswordLogin(ctx context.Context, req ControllerLoginReq) (*ControllerAuthExchangeResp, *ControllerMfaChallengeResp, error) {
	if req.TenantId == "" {
		req.TenantId = c.tenantID
	}
	resp, err := c.inner.PostApiV1AuthPasswordLoginWithResponse(ctx, nil, req)
	if err != nil {
		return nil, nil, err
	}
	if resp.JSON200 != nil {
		_ = c.persistTokens(ctx, resp.JSON200)
		return resp.JSON200, nil, nil
	}
	if resp.JSON202 != nil {
		return nil, resp.JSON202, nil
	}
	return nil, nil, errors.New(resp.Status())
}

// Refresh exchanges the stored refresh token for new tokens and persists them.
func (c *GuardClient) Refresh(ctx context.Context) (*ControllerAuthExchangeResp, error) {
	_, refresh := c.tokens.Get(ctx)
	if refresh == "" {
		return nil, errors.New("no refresh token available")
	}
	body := PostApiV1AuthRefreshJSONRequestBody{RefreshToken: &refresh}
	resp, err := c.inner.PostApiV1AuthRefreshWithResponse(ctx, nil, body)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, errors.New(resp.Status())
	}
	_ = c.persistTokens(ctx, resp.JSON200)
	return resp.JSON200, nil
}

// Logout revokes the current refresh token server-side and clears local tokens.
func (c *GuardClient) Logout(ctx context.Context) error {
	_, refresh := c.tokens.Get(ctx)
	if refresh == "" {
		// Nothing to revoke; clear any residual access token
		return c.tokens.Clear(ctx)
	}
	body := PostApiV1AuthLogoutJSONRequestBody{RefreshToken: &refresh}
	_, err := c.inner.PostApiV1AuthLogoutWithResponse(ctx, body)
	// Regardless of HTTP outcome, clear local tokens to avoid stale state
	_ = c.tokens.Clear(ctx)
	return err
}

// MagicSend sends a passwordless magic link to the given email.
func (c *GuardClient) MagicSend(ctx context.Context, req ControllerMagicSendReq) error {
	if req.TenantId == "" {
		req.TenantId = c.tenantID
	}
	_, err := c.inner.PostApiV1AuthMagicSendWithResponse(ctx, req)
	return err
}

// MagicVerify verifies a magic token and persists returned tokens.
func (c *GuardClient) MagicVerify(ctx context.Context, token string) (*ControllerAuthExchangeResp, error) {
	resp, err := c.inner.PostApiV1AuthMagicVerifyWithResponse(ctx, nil, ControllerMagicVerifyReq{Token: token})
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, errors.New(resp.Status())
	}
	_ = c.persistTokens(ctx, resp.JSON200)
	return resp.JSON200, nil
}

// SSOPortalLink returns an Admin Portal link for a given SSO provider and organization ID.
// Note: this endpoint requires an admin bearer token.
func (c *GuardClient) SSOPortalLink(ctx context.Context, provider, organizationID string, intent *string) (string, error) {
	tenID := c.tenantID
	if tenID == "" {
		return "", errors.New("tenant ID not configured; use WithTenantID or pass tenant_id via params")
	}
	params := &GetApiV1AuthSsoProviderPortalLinkParams{OrganizationId: organizationID, TenantId: tenID, Intent: intent}
	resp, err := c.inner.GetApiV1AuthSsoProviderPortalLinkWithResponse(ctx, provider, params)
	if err != nil {
		return "", err
	}
	if resp.HTTPResponse == nil || resp.HTTPResponse.StatusCode != http.StatusOK {
		return "", errors.New(resp.Status())
	}
	var pl DomainPortalLink
	if err := json.Unmarshal(resp.Body, &pl); err != nil {
		return "", err
	}
	if pl.Link == nil || *pl.Link == "" {
		return "", errors.New("missing link in response")
	}
	return *pl.Link, nil
}

// SSOPortalSession exchanges a raw portal token for a validated portal session context.
// This endpoint does not require a Guard user token; it is gated by the portal token itself.
func (c *GuardClient) SSOPortalSession(ctx context.Context, token string) (*SSOPortalSession, error) {
	if token == "" {
		return nil, errors.New("portal token required")
	}
	cli := c.httpClient
	if cli == nil {
		cli = http.DefaultClient
	}
	body, err := json.Marshal(map[string]string{"token": token})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/v1/sso/portal/session", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := cli.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New(resp.Status)
	}
	var ps SSOPortalSession
	if err := json.NewDecoder(resp.Body).Decode(&ps); err != nil {
		return nil, err
	}
	return &ps, nil
}

// SSOPortalProvider fetches the masked SSO provider configuration using a portal token.
// It returns the same SSOProvider shape as the admin SSO management helpers.
func (c *GuardClient) SSOPortalProvider(ctx context.Context, token string) (*SSOProvider, error) {
	if token == "" {
		return nil, errors.New("portal token required")
	}
	cli := c.httpClient
	if cli == nil {
		cli = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/v1/sso/portal/provider", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Portal-Token", token)
	resp, err := cli.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New(resp.Status)
	}
	var provider SSOProvider
	if err := json.NewDecoder(resp.Body).Decode(&provider); err != nil {
		return nil, err
	}
	return &provider, nil
}

// SSOStart initiates an SSO flow and returns the provider authorization URL to redirect the user to.
// It uses the client's tenant ID if params.TenantId is empty.
func (c *GuardClient) SSOStart(ctx context.Context, provider string, params *GetApiV1AuthSsoProviderStartParams) (string, error) {
	if params == nil {
		return "", errors.New("params required")
	}
	if params.TenantId == "" {
		params.TenantId = c.tenantID
	}
	if params.TenantId == "" {
		return "", errors.New("tenant ID not configured; set params.TenantId or use WithTenantID")
	}
	resp, err := c.inner.GetApiV1AuthSsoProviderStartWithResponse(ctx, provider, params)
	if err != nil {
		return "", err
	}
	if resp.HTTPResponse == nil || resp.HTTPResponse.StatusCode != http.StatusFound { // 302
		return "", errors.New(resp.Status())
	}
	loc := resp.HTTPResponse.Header.Get("Location")
	if loc == "" {
		return "", errors.New("missing redirect location")
	}
	return loc, nil
}

// SSOCallback completes the SSO flow by exchanging the authorization code for tokens.
// It appends the provided code and state as query parameters, persists tokens on success, and returns them.
func (c *GuardClient) SSOCallback(ctx context.Context, provider, code, state string) (*ControllerAuthExchangeResp, error) {
	editor := func(_ context.Context, req *http.Request) error {
		q := req.URL.Query()
		if code != "" {
			q.Set("code", code)
		}
		if state != "" {
			q.Set("state", state)
		}
		req.URL.RawQuery = q.Encode()
		return nil
	}
	resp, err := c.inner.GetApiV1AuthSsoProviderCallbackWithResponse(ctx, provider, nil, editor)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, errors.New(resp.Status())
	}
	_ = c.persistTokens(ctx, resp.JSON200)
	return resp.JSON200, nil
}

// GetTenantSettings fetches tenant settings by ID.
func (c *GuardClient) GetTenantSettings(ctx context.Context, tenantID string) (*ControllerSettingsResponse, error) {
	if tenantID == "" {
		tenantID = c.tenantID
	}
	if tenantID == "" {
		return nil, errors.New("tenant ID required")
	}
	resp, err := c.inner.GetApiV1TenantsIdSettingsWithResponse(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, errors.New(resp.Status())
	}
	return resp.JSON200, nil
}

// UpdateTenantSettings updates tenant settings by ID.
func (c *GuardClient) UpdateTenantSettings(ctx context.Context, tenantID string, body ControllerPutSettingsRequest) error {
	if tenantID == "" {
		tenantID = c.tenantID
	}
	if tenantID == "" {
		return errors.New("tenant ID required")
	}
	resp, err := c.inner.PutApiV1TenantsIdSettingsWithResponse(ctx, tenantID, body)
	if err != nil {
		return err
	}
	if resp.HTTPResponse == nil || (resp.StatusCode() != http.StatusOK && resp.StatusCode() != http.StatusNoContent) {
		return errors.New(resp.Status())
	}
	return nil
}

// Me fetches the current user's profile using the bearer token.
func (c *GuardClient) Me(ctx context.Context) (*DomainUserProfile, error) {
	resp, err := c.inner.GetApiV1AuthMeWithResponse(ctx, nil)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, errors.New(resp.Status())
	}
	return resp.JSON200, nil
}

// Introspect returns token claims and state. If token is nil, Authorization header is used.
func (c *GuardClient) Introspect(ctx context.Context, token *string) (*DomainIntrospection, error) {
	body := ControllerIntrospectReq{Token: token}
	resp, err := c.inner.PostApiV1AuthIntrospectWithResponse(ctx, body)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, errors.New(resp.Status())
	}
	return resp.JSON200, nil
}

// MFABackupCount returns how many backup codes remain.
func (c *GuardClient) MFABackupCount(ctx context.Context) (int, error) {
	resp, err := c.inner.GetApiV1AuthMfaBackupCountWithResponse(ctx)
	if err != nil {
		return 0, err
	}
	if resp.JSON200 == nil || resp.JSON200.Count == nil {
		return 0, errors.New(resp.Status())
	}
	return *resp.JSON200.Count, nil
}

// MFABackupGenerate generates backup codes (optionally specifying a count).
func (c *GuardClient) MFABackupGenerate(ctx context.Context, count *int) ([]string, error) {
	body := PostApiV1AuthMfaBackupGenerateJSONRequestBody{Count: count}
	resp, err := c.inner.PostApiV1AuthMfaBackupGenerateWithResponse(ctx, body)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil || resp.JSON200.Codes == nil {
		return nil, errors.New(resp.Status())
	}
	// Deref to return a concrete slice
	return append([]string(nil), (*resp.JSON200.Codes)...), nil
}

// MFABackupConsume consumes a backup code and returns whether it was consumed.
func (c *GuardClient) MFABackupConsume(ctx context.Context, code string) (bool, error) {
	body := PostApiV1AuthMfaBackupConsumeJSONRequestBody{Code: code}
	resp, err := c.inner.PostApiV1AuthMfaBackupConsumeWithResponse(ctx, body)
	if err != nil {
		return false, err
	}
	if resp.JSON200 == nil || resp.JSON200.Consumed == nil {
		return false, errors.New(resp.Status())
	}
	return *resp.JSON200.Consumed, nil
}

// MFATOTPStart begins TOTP enrollment and returns secret and otpauth URL.
func (c *GuardClient) MFATOTPStart(ctx context.Context) (*ControllerMfaTOTPStartResp, error) {
	resp, err := c.inner.PostApiV1AuthMfaTotpStartWithResponse(ctx)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, errors.New(resp.Status())
	}
	return resp.JSON200, nil
}

// MFATOTPActivate verifies the TOTP code to complete enrollment.
func (c *GuardClient) MFATOTPActivate(ctx context.Context, code string) error {
	body := PostApiV1AuthMfaTotpActivateJSONRequestBody{Code: code}
	resp, err := c.inner.PostApiV1AuthMfaTotpActivateWithResponse(ctx, body)
	if err != nil {
		return err
	}
	if resp.HTTPResponse == nil || (resp.StatusCode() != http.StatusOK && resp.StatusCode() != http.StatusNoContent) {
		return errors.New(resp.Status())
	}
	return nil
}

// MFATOTPDisable disables TOTP for the current user.
func (c *GuardClient) MFATOTPDisable(ctx context.Context) error {
	resp, err := c.inner.PostApiV1AuthMfaTotpDisableWithResponse(ctx)
	if err != nil {
		return err
	}
	if resp.HTTPResponse == nil || (resp.StatusCode() != http.StatusOK && resp.StatusCode() != http.StatusNoContent) {
		return errors.New(resp.Status())
	}
	return nil
}

// MFAVerify submits an MFA challenge response and persists the returned tokens.
func (c *GuardClient) MFAVerify(ctx context.Context, challengeToken string, method ControllerMfaVerifyReqMethod, code string) (*ControllerAuthExchangeResp, error) {
	req := ControllerMfaVerifyReq{ChallengeToken: challengeToken, Method: method, Code: code}
	resp, err := c.inner.PostApiV1AuthMfaVerifyWithResponse(ctx, nil, req)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, errors.New(resp.Status())
	}
	_ = c.persistTokens(ctx, resp.JSON200)
	return resp.JSON200, nil
}

// Sessions lists active sessions for the current user.
func (c *GuardClient) Sessions(ctx context.Context) ([]ControllerSessionItem, error) {
	resp, err := c.inner.GetApiV1AuthSessionsWithResponse(ctx)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil || resp.JSON200.Sessions == nil {
		return nil, errors.New(resp.Status())
	}
	return append([]ControllerSessionItem(nil), (*resp.JSON200.Sessions)...), nil
}

// RevokeSession revokes a specific session by ID.
func (c *GuardClient) RevokeSession(ctx context.Context, id string) error {
	resp, err := c.inner.PostApiV1AuthSessionsIdRevokeWithResponse(ctx, id)
	if err != nil {
		return err
	}
	if resp.HTTPResponse == nil || (resp.StatusCode() != http.StatusOK && resp.StatusCode() != http.StatusNoContent) {
		return errors.New(resp.Status())
	}
	return nil
}

// ListTenants returns tenants with optional query, page and page size.
func (c *GuardClient) ListTenants(ctx context.Context, params *GetApiV1TenantsParams) (*ControllerListResponse, error) {
	resp, err := c.inner.GetApiV1TenantsWithResponse(ctx, params)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, errors.New(resp.Status())
	}
	return resp.JSON200, nil
}
