# ADR-0006: SSO Technical Debt Remediation

**Status**: Proposed
**Date**: 2025-12-07
**Authors**: Guard Team
**Deciders**: Engineering Team

---

## Context and Problem Statement

During a recent code review (CodeRabbit), several technical debt items were identified in the SSO implementation that require architectural decisions and implementation work. These items fall into four categories:

1. **SSO Logout Session Revocation**: The logout handler acknowledges logout but doesn't actually revoke sessions
2. **Shared Callback Logic Extraction**: Duplicate code between V2 and legacy callback handlers
3. **SDK Token Requirement Relaxation**: The SDK requires both access and refresh tokens, but refresh tokens may be optional
4. **Repository Metadata Field Population**: Refresh tokens store empty `{}` metadata instead of useful context

These issues were flagged as TODOs or nitpicks but represent real gaps in the implementation that could affect security, maintainability, and developer experience.

---

## Decision Drivers

### Security Drivers
- **Session Revocation**: Logout without session revocation leaves tokens valid, enabling session hijacking
- **Token Leakage**: Proper metadata tracking aids forensic analysis of compromised sessions

### Maintainability Drivers
- **Code Duplication**: Shared callback logic reduces bug surface and simplifies updates
- **Consistency**: Unified patterns across handlers improve code comprehension

### Developer Experience Drivers
- **SDK Flexibility**: Relaxed token requirements support more authentication flows
- **Debugging**: Rich metadata aids troubleshooting authentication issues

---

## Decision Outcome

We will address these four items in priority order, with security-critical items first.

---

## Item 1: SSO Logout Session Revocation

### Current State

The SSO logout handler in `internal/auth/sso/controller/http.go` (lines 310-348) has multiple TODOs:

```go
// handleSSOLogout handles SSO logout requests
func (h *SSOController) handleSSOLogout(c echo.Context) error {
    // ...
    if samlRequest != "" {
        h.log.Info().Str("tenant_id", tenantIDStr).Str("slug", slug).Msg("processing IdP-initiated logout")
        // TODO: Implement IdP-initiated SLO
        return c.JSON(http.StatusOK, map[string]string{"status": "logged_out"})
    }
    // ...
    if config.IdPSLOUrl != "" {
        // TODO: Generate proper SAML LogoutRequest
        return c.Redirect(http.StatusFound, config.IdPSLOUrl)
    }
    // No SLO configured, just acknowledge logout
    return c.JSON(http.StatusOK, map[string]string{"status": "logged_out"})
}
```

**Problem**: The handler returns "logged_out" without actually revoking the user's sessions/refresh tokens.

### Proposed Solution

#### Phase 1: Local Session Revocation (Priority: High)

1. Accept session identifier (access token or session ID) in logout request
2. Revoke all refresh tokens for the user/session in the database
3. Invalidate any cached session data
4. Return success only after revocation completes

```go
func (h *SSOController) handleSSOLogout(c echo.Context) error {
    // ... existing tenant/slug parsing ...
    
    // Extract session context from request
    sessionID := c.Request().Header.Get("X-Session-ID")
    accessToken := extractBearerToken(c)
    
    // Revoke sessions before acknowledging logout
    if err := h.authService.RevokeUserSessions(c.Request().Context(), RevokeSessionsInput{
        TenantID:    tenantID,
        SessionID:   sessionID,
        AccessToken: accessToken,
        RevokeAll:   false, // Only current session by default
    }); err != nil {
        h.log.Error().Err(err).Msg("failed to revoke sessions during logout")
        // Continue with logout flow even if revocation fails
    }
    
    // ... rest of logout logic ...
}
```

#### Phase 2: SAML Single Logout (SLO) Support (Priority: Medium)

1. Implement `SAMLLogoutRequest` generation per SAML 2.0 spec
2. Handle `SAMLLogoutResponse` validation
3. Support both SP-initiated and IdP-initiated SLO flows
4. Add SLO URL configuration to provider settings

#### Phase 3: OIDC Back-Channel Logout (Priority: Low)

1. Implement OIDC back-channel logout endpoint
2. Support logout tokens per RFC 7009
3. Register back-channel logout URI with IdPs

### Work Estimate

| Phase | Effort | Priority |
|-------|--------|----------|
| Phase 1: Local Session Revocation | 2-3 days | High |
| Phase 2: SAML SLO | 1 week | Medium |
| Phase 3: OIDC Back-Channel | 3-4 days | Low |

### Files to Modify

- `internal/auth/sso/controller/http.go` - Logout handler
- `internal/auth/service/service.go` - Add `RevokeUserSessions` method
- `internal/auth/repository/sqlc.go` - Add session revocation queries
- `internal/db/queries/sessions.sql` - New SQL queries
- `internal/auth/sso/domain/types.go` - SLO-related types

---

## Item 2: Extract Shared Callback Logic

### Current State

The SSO controller has duplicate callback handling logic between:
- `handleSSOCallbackV2` (lines ~200-260) - New tenant-scoped format
- `handleSSOCallbackLegacy` (lines 414-450) - Legacy format with inline handling

Both handlers perform the same sequence:
1. Parse SAML response and relay state
2. Call `h.ssoService.HandleCallback()`
3. Call `h.authService.IssueTokensForSSO()`
4. Return tokens to client

### Proposed Solution

Extract shared logic into a private helper method:

```go
// callbackResult holds the result of SSO callback processing
type callbackResult struct {
    Tokens      *authdomain.AccessTokens
    RedirectURL string
    Error       error
}

// processCallback handles the common SSO callback logic
func (h *SSOController) processCallback(ctx context.Context, req callbackRequest) callbackResult {
    resp, err := h.ssoService.HandleCallback(ctx, service.CallbackRequest{
        TenantID:     req.TenantID,
        ProviderSlug: req.Slug,
        SAMLResponse: req.SAMLResponse,
        RelayState:   req.RelayState,
        IPAddress:    req.IPAddress,
        UserAgent:    req.UserAgent,
    })
    if err != nil {
        h.log.Error().Err(err).Str("slug", req.Slug).Msg("SSO callback failed")
        return callbackResult{Error: err}
    }

    tokens, err := h.authService.IssueTokensForSSO(ctx, authdomain.SSOTokenInput{
        UserID:    resp.User.ID,
        TenantID:  req.TenantID,
        UserAgent: req.UserAgent,
        IP:        req.IPAddress,
    })
    if err != nil {
        return callbackResult{Error: fmt.Errorf("failed to create session: %w", err)}
    }

    return callbackResult{
        Tokens:      tokens,
        RedirectURL: resp.RedirectURL,
    }
}

// handleSSOCallbackV2 uses the shared helper
func (h *SSOController) handleSSOCallbackV2(c echo.Context) error {
    // ... parse request ...
    result := h.processCallback(c.Request().Context(), callbackRequest{...})
    if result.Error != nil {
        return c.JSON(http.StatusBadRequest, map[string]string{"error": result.Error.Error()})
    }
    // ... handle redirect with tokens ...
}

// handleSSOCallbackLegacy uses the same shared helper
func (h *SSOController) handleSSOCallbackLegacy(c echo.Context) error {
    // ... parse request ...
    if c.Request().Method == http.MethodPost {
        result := h.processCallback(c.Request().Context(), callbackRequest{...})
        // ... return JSON response ...
    }
    // ... redirect for GET ...
}
```

### Benefits

- **Single source of truth** for callback logic
- **Easier testing** - test helper once, handlers just parse/format
- **Consistent error handling** across all callback paths
- **Simpler auditing** - security-critical logic in one place

### Work Estimate

| Task | Effort |
|------|--------|
| Extract helper method | 2-3 hours |
| Update V2 handler | 1 hour |
| Update legacy handler | 1 hour |
| Add unit tests for helper | 2-3 hours |
| **Total** | **1 day** |

### Files to Modify

- `internal/auth/sso/controller/http.go` - Extract helper, update handlers
- `internal/auth/sso/controller/http_test.go` - Add helper tests

---

## Item 3: SDK Token Requirement Relaxation

### Current State

The TypeScript SDK's `extractTokensFromUrl` method (lines 819-827) requires both tokens:

```typescript
if (accessToken && refreshToken) {
    const tokens: TokensResp = {
        access_token: accessToken,
        refresh_token: refreshToken,
    };
    this.persistTokensFrom(tokens);
    return tokens;
}
return null;
```

**Problem**: Some authentication flows may only provide an access token (e.g., implicit flow, short-lived sessions). The SDK silently fails in these cases.

### Proposed Solution

Make refresh token optional with clear documentation:

```typescript
/**
 * Extract tokens from URL (query params or fragment).
 * 
 * @param url - URL containing tokens
 * @returns Tokens if access_token found, null otherwise
 * 
 * @remarks
 * - access_token is required
 * - refresh_token is optional (some flows don't provide it)
 * - When refresh_token is missing, token refresh will not be available
 */
extractTokensFromUrl(url: string): TokensResp | null {
    try {
        const searchParams = this.parseUrlParams(url);
        const accessToken = searchParams.get('access_token');
        const refreshToken = searchParams.get('refresh_token');
        
        if (!accessToken) {
            return null;
        }
        
        const tokens: TokensResp = {
            access_token: accessToken,
            refresh_token: refreshToken ?? undefined,
        };
        
        this.persistTokensFrom(tokens);
        
        // Warn if refresh token missing (affects token refresh capability)
        if (!refreshToken && this.options.debug) {
            console.warn('[Guard SDK] No refresh_token in URL - token refresh will not be available');
        }
        
        return tokens;
    } catch {
        return null;
    }
}
```

### Considerations

1. **Token Refresh**: Without refresh token, `refreshTokens()` will fail - document this clearly
2. **Session Duration**: Access-only sessions expire when access token expires
3. **Backward Compatibility**: Existing code expecting both tokens continues to work
4. **Type Safety**: Update `TokensResp` type to make `refresh_token` optional

### Type Update

```typescript
interface TokensResp {
    access_token: string;
    refresh_token?: string;  // Optional - not all flows provide refresh tokens
}
```

### Work Estimate

| Task | Effort |
|------|--------|
| Update type definitions | 30 min |
| Modify extractTokensFromUrl | 1 hour |
| Update persistTokensFrom | 1 hour |
| Add warning for missing refresh | 30 min |
| Update documentation | 1 hour |
| Add tests | 2 hours |
| **Total** | **0.5-1 day** |

### Files to Modify

- `sdk/ts/src/client.ts` - Token extraction and persistence
- `sdk/ts/src/types.ts` - Type definitions
- `sdk/ts/README.md` - Documentation update

---

## Item 4: Repository Metadata Field Population

### Current State

The `CreateRefreshToken` method in `internal/auth/repository/sqlc.go` (line 368) hardcodes empty metadata:

```go
func (r *SQLCRepository) CreateRefreshToken(...) error {
    return r.q.CreateRefreshToken(ctx, sqlc.CreateRefreshTokenParams{
        // ... other fields ...
        Metadata: []byte("{}"),  // Always empty
    })
}
```

**Problem**: The metadata field exists but is never populated, missing an opportunity to store useful session context.

### Proposed Solution

#### Phase 1: Define Metadata Schema

```go
// RefreshTokenMetadata contains contextual information about a refresh token
type RefreshTokenMetadata struct {
    // Authentication context
    AuthMethod    string    `json:"auth_method,omitempty"`     // "password", "sso", "mfa"
    SSOProvider   string    `json:"sso_provider,omitempty"`    // Provider slug if SSO
    MFAVerified   bool      `json:"mfa_verified,omitempty"`    // Whether MFA was completed
    
    // Session context
    DeviceID      string    `json:"device_id,omitempty"`       // Client device identifier
    DeviceType    string    `json:"device_type,omitempty"`     // "mobile", "desktop", "tablet"
    Location      string    `json:"location,omitempty"`        // Geo-location if available
    
    // Security context
    RiskScore     int       `json:"risk_score,omitempty"`      // 0-100 risk assessment
    TrustLevel    string    `json:"trust_level,omitempty"`     // "high", "medium", "low"
    
    // Audit context
    CreatedVia    string    `json:"created_via,omitempty"`     // "api", "web", "sdk"
    ClientVersion string    `json:"client_version,omitempty"`  // SDK/client version
}
```

#### Phase 2: Update Repository Method

```go
func (r *SQLCRepository) CreateRefreshToken(
    ctx context.Context,
    userID, tenantID uuid.UUID,
    tokenHash string,
    parentID *uuid.UUID,
    userAgent, ip string,
    expiresAt time.Time,
    authMethod string,
    ssoProviderID *uuid.UUID,
    metadata *domain.RefreshTokenMetadata,  // New parameter
) error {
    metadataJSON := []byte("{}")
    if metadata != nil {
        var err error
        metadataJSON, err = json.Marshal(metadata)
        if err != nil {
            return fmt.Errorf("failed to marshal metadata: %w", err)
        }
    }
    
    return r.q.CreateRefreshToken(ctx, sqlc.CreateRefreshTokenParams{
        // ... other fields ...
        Metadata: metadataJSON,
    })
}
```

#### Phase 3: Populate Metadata at Token Creation

Update callers to provide metadata:

```go
// In auth service during login
metadata := &domain.RefreshTokenMetadata{
    AuthMethod:    "password",
    MFAVerified:   mfaCompleted,
    CreatedVia:    "api",
    ClientVersion: clientVersion,
}

err := r.repo.CreateRefreshToken(ctx, userID, tenantID, tokenHash, nil, 
    userAgent, ip, expiresAt, "password", nil, metadata)
```

```go
// In SSO service during callback
metadata := &domain.RefreshTokenMetadata{
    AuthMethod:  "sso",
    SSOProvider: providerSlug,
    CreatedVia:  "sso_callback",
}

err := r.repo.CreateRefreshToken(ctx, userID, tenantID, tokenHash, nil,
    userAgent, ip, expiresAt, "sso", &providerID, metadata)
```

### Benefits

- **Forensics**: Understand how sessions were created during security incidents
- **Analytics**: Track authentication patterns across methods
- **Risk Assessment**: Use metadata for adaptive authentication decisions
- **Debugging**: Easier troubleshooting of session issues

### Work Estimate

| Phase | Effort |
|-------|--------|
| Define metadata schema | 1 hour |
| Update repository method | 2 hours |
| Update service callers | 3-4 hours |
| Add migration (if schema change needed) | 1 hour |
| Add tests | 2 hours |
| **Total** | **1-1.5 days** |

### Files to Modify

- `internal/auth/domain/types.go` - Add `RefreshTokenMetadata` type
- `internal/auth/repository/sqlc.go` - Update `CreateRefreshToken`
- `internal/auth/service/service.go` - Populate metadata during login
- `internal/auth/sso/service/service.go` - Populate metadata during SSO
- `internal/auth/service/service_test.go` - Update tests

---

## Implementation Priority

| Item | Priority | Effort | Security Impact |
|------|----------|--------|-----------------|
| 1. SSO Logout Session Revocation (Phase 1) | **High** | 2-3 days | **Critical** |
| 2. Extract Shared Callback Logic | Medium | 1 day | Low |
| 3. SDK Token Requirement Relaxation | Medium | 0.5-1 day | Low |
| 4. Repository Metadata Population | Low | 1-1.5 days | Medium |
| 1. SSO Logout (Phases 2-3) | Low | 1.5 weeks | Medium |

**Recommended Order**: 1 (Phase 1) → 2 → 3 → 4 → 1 (Phases 2-3)

---

## Success Criteria

### Item 1: Session Revocation
- [ ] Logout endpoint revokes refresh tokens before returning success
- [ ] Revoked tokens cannot be used for refresh
- [ ] Audit log captures logout events with session details

### Item 2: Shared Callback Logic
- [ ] Single helper method handles callback processing
- [ ] Both V2 and legacy handlers use the helper
- [ ] Unit tests cover helper method edge cases

### Item 3: SDK Token Relaxation
- [ ] SDK accepts access-only token responses
- [ ] Clear warning when refresh token missing
- [ ] Documentation updated with flow compatibility matrix

### Item 4: Metadata Population
- [ ] Metadata schema defined and documented
- [ ] All token creation paths populate metadata
- [ ] Metadata queryable for analytics/forensics

---

## References

- [SAML 2.0 Single Logout](http://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf) - Section 4.4
- [OIDC Back-Channel Logout](https://openid.net/specs/openid-connect-backchannel-1_0.html)
- [RFC 7009 - OAuth 2.0 Token Revocation](https://tools.ietf.org/html/rfc7009)
- CodeRabbit Review - PR #XXX (December 2025)
