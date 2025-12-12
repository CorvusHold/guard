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
	edomain "github.com/corvusHold/guard/internal/email/domain"
	evdomain "github.com/corvusHold/guard/internal/events/domain"
	evsvc "github.com/corvusHold/guard/internal/events/service"
	"github.com/corvusHold/guard/internal/metrics"
	sdomain "github.com/corvusHold/guard/internal/settings/domain"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Magic implements domain.MagicLinkService.
type Magic struct {
	repo     domain.Repository
	cfg      config.Config
	settings sdomain.Service
	email    edomain.Sender
	pub      evdomain.Publisher
}

func NewMagic(repo domain.Repository, cfg config.Config, settings sdomain.Service, email edomain.Sender) *Magic {
	return &Magic{repo: repo, cfg: cfg, settings: settings, email: email, pub: evsvc.NewLogger()}
}

// SetPublisher allows tests or callers to override the event publisher.
func (m *Magic) SetPublisher(p evdomain.Publisher) { m.pub = p }

func (m *Magic) Send(ctx context.Context, in domain.MagicSendInput) error {
	if in.Email == "" {
		return errors.New("email is required")
	}
	// Resolve TTL and public base URL
	ttl, _ := m.settings.GetDuration(ctx, sdomain.KeyMagicLinkTTL, &in.TenantID, m.cfg.MagicLinkTTL)
	baseURL, _ := m.settings.GetString(ctx, sdomain.KeyPublicBaseURL, &in.TenantID, m.cfg.PublicBaseURL)

	// Optional: set userID if identity exists
	var userID *uuid.UUID
	if ai, err := m.repo.GetAuthIdentityByEmailTenant(ctx, in.TenantID, in.Email); err == nil {
		uid := ai.UserID
		userID = &uid
	}

	// Generate token and store hashed
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	h := sha256.Sum256([]byte(token))
	tokenHash := base64.RawURLEncoding.EncodeToString(h[:])
	exp := time.Now().Add(ttl)
	if err := m.repo.CreateMagicLink(ctx, uuid.New(), userID, in.TenantID, in.Email, tokenHash, in.RedirectURL, exp); err != nil {
		return err
	}

	// Build verification link
	u, err := url.Parse(baseURL)
	if err != nil {
		return err
	}
	u.Path = "/api/v1/auth/magic/verify"
	q := u.Query()
	q.Set("token", token)
	u.RawQuery = q.Encode()
	link := u.String()

	// Send via pluggable email provider
	subject := "Sign in to Guard"
	body := "Click to sign in: " + link + "\nThis link expires in " + ttl.String() + "."
	return m.email.Send(ctx, in.TenantID, in.Email, subject, body)
}

// CreateForTest creates and stores a magic link token (without sending email) and returns the raw token.
// This is intended for CI/test environments to automate magic-link verification flows.
func (m *Magic) CreateForTest(ctx context.Context, in domain.MagicSendInput) (string, error) {
	if in.Email == "" {
		return "", errors.New("email is required")
	}
	// Resolve TTL so expiry matches production logic
	ttl, _ := m.settings.GetDuration(ctx, sdomain.KeyMagicLinkTTL, &in.TenantID, m.cfg.MagicLinkTTL)

	// Optional: set userID if identity exists
	var userID *uuid.UUID
	if ai, err := m.repo.GetAuthIdentityByEmailTenant(ctx, in.TenantID, in.Email); err == nil {
		uid := ai.UserID
		userID = &uid
	}

	// Generate token and store hashed (same format as Send)
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	h := sha256.Sum256([]byte(token))
	tokenHash := base64.RawURLEncoding.EncodeToString(h[:])
	exp := time.Now().Add(ttl)
	if err := m.repo.CreateMagicLink(ctx, uuid.New(), userID, in.TenantID, in.Email, tokenHash, in.RedirectURL, exp); err != nil {
		return "", err
	}
	return token, nil
}

func (m *Magic) Verify(ctx context.Context, in domain.MagicVerifyInput) (toks domain.AccessTokens, err error) {
	defer func() {
		if err == nil {
			metrics.IncAuthOutcome("magic", "success")
		} else {
			metrics.IncAuthOutcome("magic", "failure")
		}
	}()
	if in.Token == "" {
		return domain.AccessTokens{}, errors.New("token required")
	}
	h := sha256.Sum256([]byte(in.Token))
	tokenHash := base64.RawURLEncoding.EncodeToString(h[:])
	ml, err := m.repo.GetMagicLinkByHash(ctx, tokenHash)
	if err != nil {
		return domain.AccessTokens{}, err
	}
	if ml.ConsumedAt != nil || time.Now().After(ml.ExpiresAt) {
		return domain.AccessTokens{}, errors.New("token expired or already used")
	}
	if err := m.repo.ConsumeMagicLink(ctx, tokenHash); err != nil {
		return domain.AccessTokens{}, err
	}

	tenantID := ml.TenantID
	var userID uuid.UUID
	if ml.UserID != nil {
		userID = *ml.UserID
	} else if ai, err := m.repo.GetAuthIdentityByEmailTenant(ctx, tenantID, ml.Email); err == nil {
		userID = ai.UserID
	} else {
		userID = uuid.New()
		if err := m.repo.CreateUser(ctx, userID, "", "", []string{}); err != nil {
			return domain.AccessTokens{}, err
		}
		if err := m.repo.CreateAuthIdentity(ctx, uuid.New(), userID, tenantID, ml.Email, ""); err != nil {
			return domain.AccessTokens{}, err
		}
		if err := m.repo.AddUserToTenant(ctx, userID, tenantID); err != nil {
			return domain.AccessTokens{}, err
		}
	}

	// Resolve settings for token issuance
	accessTTL, _ := m.settings.GetDuration(ctx, sdomain.KeyAccessTTL, &tenantID, m.cfg.AccessTokenTTL)
	refreshTTL, _ := m.settings.GetDuration(ctx, sdomain.KeyRefreshTTL, &tenantID, m.cfg.RefreshTokenTTL)
	signingKey, _ := m.settings.GetString(ctx, sdomain.KeyJWTSigning, &tenantID, m.cfg.JWTSigningKey)
	issuer, _ := m.settings.GetString(ctx, sdomain.KeyJWTIssuer, &tenantID, m.cfg.PublicBaseURL)
	audience, _ := m.settings.GetString(ctx, sdomain.KeyJWTAudience, &tenantID, m.cfg.PublicBaseURL)

	claims := jwt.MapClaims{
		"sub": userID.String(),
		"ten": tenantID.String(),
		"exp": time.Now().Add(accessTTL).Unix(),
		"iat": time.Now().Unix(),
		"iss": issuer,
		"aud": audience,
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	access, err := t.SignedString([]byte(signingKey))
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
	metadata := &domain.RefreshTokenMetadata{
		AuthMethod: "magic_link",
		CreatedVia: "login",
	}
	if err := m.repo.InsertRefreshToken(ctx, uuid.New(), userID, tenantID, hashB64, nil, in.UserAgent, in.IP, expiresAt, "magic_link", nil, metadata); err != nil {
		return domain.AccessTokens{}, err
	}
	// Publish audit event for successful magic login
	_ = m.pub.Publish(ctx, evdomain.Event{
		Type:     "auth.magic.login.success",
		TenantID: tenantID,
		UserID:   userID,
		Meta:     map[string]string{"provider": "magic", "ip": in.IP, "user_agent": in.UserAgent, "email": ml.Email},
		Time:     time.Now(),
	})

	return domain.AccessTokens{AccessToken: access, RefreshToken: rt}, nil
}
