package service

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/corvusHold/guard/internal/webhooks/domain"
	"github.com/google/uuid"
)

func TestSignPayload(t *testing.T) {
	secret := "my-webhook-secret"
	payload := []byte(`{"event":"user.created","user_id":"123"}`)

	sig := SignPayload(secret, payload)
	if sig == "" {
		t.Fatal("expected non-empty signature")
	}

	// Verify manually
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	expected := hex.EncodeToString(mac.Sum(nil))
	if sig != expected {
		t.Errorf("signature mismatch: got %s, want %s", sig, expected)
	}
}

func TestSignPayload_DifferentSecrets(t *testing.T) {
	payload := []byte(`{"event":"user.created"}`)
	sig1 := SignPayload("secret-a", payload)
	sig2 := SignPayload("secret-b", payload)
	if sig1 == sig2 {
		t.Error("different secrets should produce different signatures")
	}
}

func TestSignPayload_DifferentPayloads(t *testing.T) {
	secret := "shared-secret"
	sig1 := SignPayload(secret, []byte(`{"a":1}`))
	sig2 := SignPayload(secret, []byte(`{"a":2}`))
	if sig1 == sig2 {
		t.Error("different payloads should produce different signatures")
	}
}

func TestSignPayload_Deterministic(t *testing.T) {
	secret := "deterministic"
	payload := []byte("hello")
	sig1 := SignPayload(secret, payload)
	sig2 := SignPayload(secret, payload)
	if sig1 != sig2 {
		t.Error("same inputs should produce same signature")
	}
}

func TestHashSecret(t *testing.T) {
	h := HashSecret("my-secret")
	if h == "" {
		t.Fatal("expected non-empty hash")
	}
	if len(h) != 64 { // SHA-256 hex
		t.Errorf("expected 64 char hex, got %d", len(h))
	}
	// Deterministic
	h2 := HashSecret("my-secret")
	if h != h2 {
		t.Error("HashSecret should be deterministic")
	}
	// Different input
	h3 := HashSecret("other-secret")
	if h == h3 {
		t.Error("different secrets should produce different hashes")
	}
}

type fakeRepo struct {
	createdWebhook    domain.Webhook
	createErr         error
	getWebhook        domain.Webhook
	getErr            error
	listWebhooks      []domain.Webhook
	listErr           error
	updateWebhook     domain.Webhook
	updateErr         error
	deleteErr         error
	webhooksByEvent   []domain.Webhook
	listByEventErr    error
	createDeliveryErr map[uuid.UUID]error
	createdDeliveries []domain.Delivery
}

func (f *fakeRepo) CreateWebhook(_ context.Context, wh domain.Webhook) (domain.Webhook, error) {
	if f.createErr != nil {
		return domain.Webhook{}, f.createErr
	}
	f.createdWebhook = wh
	return wh, nil
}

func (f *fakeRepo) GetWebhook(_ context.Context, _, _ uuid.UUID) (domain.Webhook, error) {
	return f.getWebhook, f.getErr
}

func (f *fakeRepo) GetWebhookByID(_ context.Context, _ uuid.UUID) (domain.Webhook, error) {
	return domain.Webhook{}, nil
}

func (f *fakeRepo) ListWebhooks(_ context.Context, _ uuid.UUID) ([]domain.Webhook, error) {
	return f.listWebhooks, f.listErr
}

func (f *fakeRepo) UpdateWebhook(_ context.Context, _, _ uuid.UUID, _ *string, _ []string, _ *bool) (domain.Webhook, error) {
	return f.updateWebhook, f.updateErr
}

func (f *fakeRepo) DeleteWebhook(_ context.Context, _, _ uuid.UUID) error { return f.deleteErr }

func (f *fakeRepo) CreateDelivery(_ context.Context, d domain.Delivery) error {
	f.createdDeliveries = append(f.createdDeliveries, d)
	if f.createDeliveryErr == nil {
		return nil
	}
	if err, ok := f.createDeliveryErr[d.WebhookID]; ok {
		return err
	}
	return nil
}

func (f *fakeRepo) ListPendingDeliveries(_ context.Context, _ int) ([]domain.Delivery, error) {
	return nil, nil
}

func (f *fakeRepo) UpdateDeliveryStatus(_ context.Context, _ uuid.UUID, _, _ string, _ *time.Time, _ *time.Time) error {
	return nil
}

func (f *fakeRepo) ListWebhooksByTenantAndEvent(_ context.Context, _ uuid.UUID, _ string) ([]domain.Webhook, error) {
	if f.listByEventErr != nil {
		return nil, f.listByEventErr
	}
	return f.webhooksByEvent, nil
}

func TestServiceCreate_HashesSecretAndSetsDefaults(t *testing.T) {
	repo := &fakeRepo{}
	svc := New(repo)
	tenantID := uuid.New()

	wh, err := svc.Create(context.Background(), domain.CreateWebhookInput{
		TenantID: tenantID,
		URL:      "https://example.com/webhook",
		Secret:   "super-secret",
		Events:   []string{"user.created"},
	})
	if err != nil {
		t.Fatalf("Create returned error: %v", err)
	}

	if wh.TenantID != tenantID {
		t.Fatalf("expected tenant id %s, got %s", tenantID, wh.TenantID)
	}
	if wh.SecretHash == "" || wh.SecretHash == "super-secret" {
		t.Fatalf("expected hashed secret, got %q", wh.SecretHash)
	}
	if !wh.IsActive {
		t.Fatal("expected newly created webhook to be active")
	}
}

func TestServiceEnqueueEvent_CollectsFirstDeliveryError(t *testing.T) {
	tenantID := uuid.New()
	wh1 := domain.Webhook{ID: uuid.New(), TenantID: tenantID}
	wh2 := domain.Webhook{ID: uuid.New(), TenantID: tenantID}
	repo := &fakeRepo{
		webhooksByEvent: []domain.Webhook{wh1, wh2},
		createDeliveryErr: map[uuid.UUID]error{
			wh1.ID: errors.New("delivery failed"),
		},
	}
	svc := New(repo)

	err := svc.EnqueueEvent(context.Background(), tenantID, "user.created", map[string]string{"id": "123"})
	if err == nil {
		t.Fatal("expected first delivery error to be returned")
	}

	if len(repo.createdDeliveries) != 2 {
		t.Fatalf("expected deliveries for both webhooks, got %d", len(repo.createdDeliveries))
	}
	if repo.createdDeliveries[0].Status != "pending" {
		t.Fatalf("expected pending delivery status, got %q", repo.createdDeliveries[0].Status)
	}
	if repo.createdDeliveries[0].EventType != "user.created" {
		t.Fatalf("expected event type user.created, got %q", repo.createdDeliveries[0].EventType)
	}
}

func TestServiceEnqueueEvent_PropagatesListError(t *testing.T) {
	repo := &fakeRepo{listByEventErr: errors.New("list failed")}
	svc := New(repo)

	err := svc.EnqueueEvent(context.Background(), uuid.New(), "user.created", map[string]string{"id": "123"})
	if err == nil || err.Error() != "list failed" {
		t.Fatalf("expected list error, got %v", err)
	}
}

func TestServiceCRUD_PassThroughs(t *testing.T) {
	tenantID := uuid.New()
	webhookID := uuid.New()
	repo := &fakeRepo{
		getWebhook:    domain.Webhook{ID: webhookID, TenantID: tenantID},
		listWebhooks:  []domain.Webhook{{ID: webhookID, TenantID: tenantID}},
		updateWebhook: domain.Webhook{ID: webhookID, TenantID: tenantID, URL: "https://new.example.com"},
	}
	svc := New(repo)

	got, err := svc.Get(context.Background(), webhookID, tenantID)
	if err != nil {
		t.Fatalf("Get returned error: %v", err)
	}
	if got.ID != webhookID {
		t.Fatalf("expected webhook id %s, got %s", webhookID, got.ID)
	}

	list, err := svc.List(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("List returned error: %v", err)
	}
	if len(list) != 1 || list[0].ID != webhookID {
		t.Fatalf("unexpected list result: %+v", list)
	}

	newURL := "https://new.example.com"
	isActive := true
	updated, err := svc.Update(context.Background(), webhookID, tenantID, &newURL, []string{"user.updated"}, &isActive)
	if err != nil {
		t.Fatalf("Update returned error: %v", err)
	}
	if updated.URL != newURL {
		t.Fatalf("expected updated URL %s, got %s", newURL, updated.URL)
	}

	if err := svc.Delete(context.Background(), webhookID, tenantID); err != nil {
		t.Fatalf("Delete returned error: %v", err)
	}
}

func TestServiceDelete_PropagatesError(t *testing.T) {
	repo := &fakeRepo{deleteErr: errors.New("delete failed")}
	svc := New(repo)
	if err := svc.Delete(context.Background(), uuid.New(), uuid.New()); err == nil || err.Error() != "delete failed" {
		t.Fatalf("expected delete error, got %v", err)
	}
}

func TestServiceEnqueueEvent_MarshalError(t *testing.T) {
	tenantID := uuid.New()
	repo := &fakeRepo{webhooksByEvent: []domain.Webhook{{ID: uuid.New(), TenantID: tenantID}}}
	svc := New(repo)

	// channels cannot be marshaled to JSON
	err := svc.EnqueueEvent(context.Background(), tenantID, "bad.payload", map[string]interface{}{"ch": make(chan int)})
	if err == nil {
		t.Fatal("expected marshal error")
	}
}
