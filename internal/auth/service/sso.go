package service

import (
    "context"
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "errors"
    "net/url"
    "time"

    "github.com/corvusHold/guard/internal/auth/domain"
    "github.com/corvusHold/guard/internal/config"
    sdomain "github.com/corvusHold/guard/internal/settings/domain"
    evdomain "github.com/corvusHold/guard/internal/events/domain"
    evsvc "github.com/corvusHold/guard/internal/events/service"
    "github.com/golang-jwt/jwt/v5"
    "github.com/google/uuid"
    "strings"
    "github.com/redis/go-redis/v9"
)

// SSO implements domain.SSOService with a dev adapter (local/testing).
type SSO struct{
    repo     domain.Repository
    cfg      config.Config
    settings sdomain.Service
    redis    *redis.Client
    pub      evdomain.Publisher
}

func NewSSO(repo domain.Repository, cfg config.Config, settings sdomain.Service) *SSO {
    rc := redis.NewClient(&redis.Options{Addr: cfg.RedisAddr, DB: cfg.RedisDB})
    return &SSO{repo: repo, cfg: cfg, settings: settings, redis: rc, pub: evsvc.NewLogger()}
}

// SetPublisher allows tests or callers to override the event publisher.
func (s *SSO) SetPublisher(p evdomain.Publisher) { s.pub = p }

// Start builds a local callback URL with a signed one-time code.
func (s *SSO) Start(ctx context.Context, in domain.SSOStartInput) (string, error) {
    if in.Provider == "" { return "", errors.New("provider required") }
    // Choose adapter by settings; default to dev
    mode, _ := s.settings.GetString(ctx, sdomain.KeySSOProvider, &in.TenantID, "")
    if strings.EqualFold(mode, "workos") {
        return s.startWorkOS(ctx, in)
    }
    // DEV adapter flow
    baseURL, _ := s.settings.GetString(ctx, sdomain.KeyPublicBaseURL, &in.TenantID, s.cfg.PublicBaseURL)
    signingKey, _ := s.settings.GetString(ctx, sdomain.KeyJWTSigning, &in.TenantID, s.cfg.JWTSigningKey)

    // Issue short-lived code JWT containing provider, tenant and redirect
    claims := jwt.MapClaims{
        "ten": in.TenantID.String(),
        "prov": in.Provider,
        "redir": in.RedirectURL,
        "state": in.State,
        "exp": time.Now().Add(5 * time.Minute).Unix(),
        "iat": time.Now().Unix(),
    }
    t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    code, err := t.SignedString([]byte(signingKey))
    if err != nil { return "", err }

    // Build callback URL: {base}/v1/auth/sso/{provider}/callback?code=...&state=...
    u, err := url.Parse(baseURL)
    if err != nil { return "", err }
    u.Path = "/v1/auth/sso/" + in.Provider + "/callback"
    q := u.Query()
    q.Set("code", code)
    if in.State != "" { q.Set("state", in.State) }
    u.RawQuery = q.Encode()
    return u.String(), nil
}

// Callback verifies the code, finds/creates a user, and issues tokens.
func (s *SSO) Callback(ctx context.Context, in domain.SSOCallbackInput) (domain.AccessTokens, error) {
    // Prefer tenant-scoped adapter selection using state->tenant mapping (WorkOS flow)
    if stVals := in.Query["state"]; len(stVals) > 0 && stVals[0] != "" {
        if tenStr, err := s.redis.Get(ctx, "sso:state:"+stVals[0]).Result(); err == nil && tenStr != "" {
            if tenID, err := uuid.Parse(tenStr); err == nil {
                mode, _ := s.settings.GetString(ctx, sdomain.KeySSOProvider, &tenID, "")
                if strings.EqualFold(mode, "workos") {
                    return s.callbackWorkOS(ctx, in)
                }
            }
        }
    }
    vals := in.Query["code"]
    if len(vals) == 0 || vals[0] == "" {
        return domain.AccessTokens{}, errors.New("code required")
    }
    code := vals[0]

    // Extract provider and tenant from code (JWT)
    var claims jwt.MapClaims
    token, _ := jwt.ParseWithClaims(code, jwt.MapClaims{}, func(t *jwt.Token) (interface{}, error) {
        // We need tenant to fetch correct signing key; decode claims without verify first
        return []byte(""), nil
    }, jwt.WithoutClaimsValidation())
    if token == nil {
        return domain.AccessTokens{}, errors.New("invalid code")
    }
    if mc, ok := token.Claims.(jwt.MapClaims); ok {
        claims = mc
    } else {
        return domain.AccessTokens{}, errors.New("invalid code claims")
    }

    tenStr, _ := claims["ten"].(string)
    prov, _ := claims["prov"].(string)
    if prov == "" || prov != in.Provider { return domain.AccessTokens{}, errors.New("invalid provider") }
    tenantID, err := uuid.Parse(tenStr)
    if err != nil { return domain.AccessTokens{}, errors.New("invalid tenant in code") }

    // Verify signature with tenant's signing key
    signingKey, _ := s.settings.GetString(ctx, sdomain.KeyJWTSigning, &tenantID, s.cfg.JWTSigningKey)
    _, err = jwt.ParseWithClaims(code, jwt.MapClaims{}, func(t *jwt.Token) (interface{}, error) {
        return []byte(signingKey), nil
    })
    if err != nil { return domain.AccessTokens{}, errors.New("invalid code signature") }

    // Determine dev email: allow optional ?email= in callback, else synthesize
    email := ""
    if ev := in.Query["email"]; len(ev) > 0 && ev[0] != "" {
        email = ev[0]
    } else {
        email = "sso.dev." + prov + "." + tenantID.String() + "@example.test"
    }

    // Find or create identity
    var userID uuid.UUID
    if ai, err := s.repo.GetAuthIdentityByEmailTenant(ctx, tenantID, email); err == nil {
        userID = ai.UserID
    } else {
        userID = uuid.New()
        if err := s.repo.CreateUser(ctx, userID, "", "", []string{}); err != nil { return domain.AccessTokens{}, err }
        if err := s.repo.CreateAuthIdentity(ctx, uuid.New(), userID, tenantID, email, ""); err != nil { return domain.AccessTokens{}, err }
        if err := s.repo.AddUserToTenant(ctx, userID, tenantID); err != nil { return domain.AccessTokens{}, err }
    }

    // Issue tokens (mirror Service.issueTokens)
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
    if err != nil { return domain.AccessTokens{}, err }

    raw := make([]byte, 32)
    if _, err := rand.Read(raw); err != nil { return domain.AccessTokens{}, err }
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
