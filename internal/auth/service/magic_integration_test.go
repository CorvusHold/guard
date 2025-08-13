package service

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/corvusHold/guard/internal/config"
	"github.com/corvusHold/guard/internal/auth/domain"
	authrepo "github.com/corvusHold/guard/internal/auth/repository"
	evdomain "github.com/corvusHold/guard/internal/events/domain"
	srepo "github.com/corvusHold/guard/internal/settings/repository"
	ssvc "github.com/corvusHold/guard/internal/settings/service"
	trepo "github.com/corvusHold/guard/internal/tenants/repository"
	edomain "github.com/corvusHold/guard/internal/email/domain"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type fakeEmail struct{ lastBody string }

// publisherFunc helps implement evdomain.Publisher in tests via a func.
type publisherFunc func(ctx context.Context, e evdomain.Event) error

func (f publisherFunc) Publish(ctx context.Context, e evdomain.Event) error { return f(ctx, e) }

func (f *fakeEmail) Send(ctx context.Context, tenantID uuid.UUID, to, subject, body string) error {
	f.lastBody = body
	return nil
}

var _ edomain.Sender = (*fakeEmail)(nil)

func TestMagic_Flow_Integration(t *testing.T) {
	if os.Getenv("DATABASE_URL") == "" {
		t.Skip("skipping integration test: DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil { t.Fatalf("db connect: %v", err) }
	defer pool.Close()

	// Create tenant
	tr := trepo.New(pool)
	tenantID := uuid.New()
	name := "magic-itest-" + tenantID.String()
	if err := tr.Create(ctx, tenantID, name); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	// small delay for consistency in CI
	time.Sleep(25 * time.Millisecond)

	// Build services
	repo := authrepo.New(pool)
	sr := srepo.New(pool)
	settings := ssvc.New(sr)
	cfg, _ := config.Load()
	fe := &fakeEmail{}
	magic := NewMagic(repo, cfg, settings, fe)
	// capture audit events
	events := make([]evdomain.Event, 0, 1)
	magic.SetPublisher(publisherFunc(func(ctx context.Context, e evdomain.Event) error {
		events = append(events, e)
		return nil
	}))

	email := "user.magic.itest@example.com"
	if err := magic.Send(ctx, domain.MagicSendInput{TenantID: tenantID, Email: email}); err != nil {
		t.Fatalf("magic send failed: %v", err)
	}
	if fe.lastBody == "" { t.Fatalf("expected email body captured") }

	// Extract token from body
	re := regexp.MustCompile(`token=([A-Za-z0-9_-]+)`) // raw URL-safe base64 token
	m := re.FindStringSubmatch(fe.lastBody)
	if len(m) < 2 { t.Fatalf("token not found in body: %q", fe.lastBody) }
	token := m[1]

	// Verify
	tokens, err := magic.Verify(ctx, domain.MagicVerifyInput{Token: token, UserAgent: "itest", IP: "127.0.0.1"})
	if err != nil { t.Fatalf("magic verify failed: %v", err) }
	if tokens.AccessToken == "" || tokens.RefreshToken == "" {
		t.Fatalf("expected non-empty tokens: %+v", tokens)
	}

	// Assert JWT iss/aud claims on access token
	parts := strings.Split(tokens.AccessToken, ".")
	if len(parts) < 2 { t.Fatalf("invalid jwt format") }
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil { t.Fatalf("decode jwt payload: %v", err) }
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil { t.Fatalf("unmarshal claims: %v", err) }
	if iss, _ := claims["iss"].(string); iss != os.Getenv("PUBLIC_BASE_URL") { t.Fatalf("iss mismatch: %v", claims["iss"]) }
	if aud, _ := claims["aud"].(string); aud != os.Getenv("PUBLIC_BASE_URL") { t.Fatalf("aud mismatch: %v", claims["aud"]) }

	// Audit event published
	if len(events) == 0 { t.Fatalf("expected an audit event") }
	found := false
	for _, e := range events {
		if e.Type == "auth.magic.login.success" {
			if e.Meta["provider"] != "magic" { t.Fatalf("provider mismatch: %v", e.Meta["provider"]) }
			if e.Meta["email"] != email { t.Fatalf("email mismatch: %v", e.Meta["email"]) }
			found = true
		}
	}
	if !found { t.Fatalf("expected auth.magic.login.success event") }

	// Ensure consumed
	h := sha256.Sum256([]byte(token))
	b64 := base64.RawURLEncoding.EncodeToString(h[:])
	ml, err := repo.GetMagicLinkByHash(ctx, b64)
	if err != nil { t.Fatalf("get magic link: %v", err) }
	if ml.ConsumedAt == nil { t.Fatalf("expected consumed_at to be set") }
}
