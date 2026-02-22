package service

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/corvusHold/guard/internal/webhooks/domain"
	"github.com/google/uuid"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

type workerRepo struct {
	webhook         domain.Webhook
	getWebhookErr   error
	listPending     []domain.Delivery
	listPendingErr  error
	statusCalls     []statusCall
	updateStatusErr error
}

type statusCall struct {
	id        uuid.UUID
	status    string
	lastError string
	nextRetry *time.Time
	completed *time.Time
}

func (r *workerRepo) CreateWebhook(context.Context, domain.Webhook) (domain.Webhook, error) {
	return domain.Webhook{}, nil
}
func (r *workerRepo) GetWebhook(context.Context, uuid.UUID, uuid.UUID) (domain.Webhook, error) {
	return domain.Webhook{}, nil
}
func (r *workerRepo) GetWebhookByID(context.Context, uuid.UUID) (domain.Webhook, error) {
	if r.getWebhookErr != nil {
		return domain.Webhook{}, r.getWebhookErr
	}
	return r.webhook, nil
}
func (r *workerRepo) ListWebhooks(context.Context, uuid.UUID) ([]domain.Webhook, error) {
	return nil, nil
}
func (r *workerRepo) UpdateWebhook(context.Context, uuid.UUID, uuid.UUID, *string, []string, *bool) (domain.Webhook, error) {
	return domain.Webhook{}, nil
}
func (r *workerRepo) DeleteWebhook(context.Context, uuid.UUID, uuid.UUID) error { return nil }
func (r *workerRepo) CreateDelivery(context.Context, domain.Delivery) error     { return nil }
func (r *workerRepo) ListPendingDeliveries(context.Context, int) ([]domain.Delivery, error) {
	if r.listPendingErr != nil {
		return nil, r.listPendingErr
	}
	return r.listPending, nil
}
func (r *workerRepo) UpdateDeliveryStatus(_ context.Context, id uuid.UUID, status string, lastError string, nextRetryAt *time.Time, completedAt *time.Time) error {
	r.statusCalls = append(r.statusCalls, statusCall{id: id, status: status, lastError: lastError, nextRetry: nextRetryAt, completed: completedAt})
	return r.updateStatusErr
}
func (r *workerRepo) ListWebhooksByTenantAndEvent(context.Context, uuid.UUID, string) ([]domain.Webhook, error) {
	return nil, nil
}

func baseDelivery() domain.Delivery {
	return domain.Delivery{
		ID:          uuid.New(),
		WebhookID:   uuid.New(),
		EventType:   "user.created",
		Payload:     []byte(`{"id":"u1"}`),
		Status:      "pending",
		Attempts:    0,
		MaxAttempts: 5,
	}
}

func TestIsBlockedIP(t *testing.T) {
	cases := []struct {
		ip      string
		blocked bool
	}{
		{"127.0.0.1", true},
		{"10.1.2.3", true},
		{"169.254.169.254", true},
		{"8.8.8.8", false},
	}
	for _, tc := range cases {
		if got := isBlockedIP(netParseIP(t, tc.ip)); got != tc.blocked {
			t.Fatalf("ip %s expected blocked=%v, got %v", tc.ip, tc.blocked, got)
		}
	}
}

func netParseIP(t *testing.T, raw string) []byte {
	t.Helper()
	ip := netParse(raw)
	if ip == nil {
		t.Fatalf("failed to parse ip %s", raw)
	}
	return ip
}

func netParse(raw string) []byte {
	return net.ParseIP(raw)
}

func TestWorkerDeliver_SuccessAndRetryAndFailures(t *testing.T) {
	ctx := context.Background()
	d := baseDelivery()

	t.Run("webhook lookup failure marks failed", func(t *testing.T) {
		repo := &workerRepo{getWebhookErr: errors.New("missing")}
		w := &Worker{repo: repo, client: &http.Client{}, requireHTTPS: false}
		w.deliver(ctx, d)
		if len(repo.statusCalls) != 1 || repo.statusCalls[0].status != "failed" {
			t.Fatalf("expected failed status update, got %+v", repo.statusCalls)
		}
	})

	t.Run("invalid URL marks failed", func(t *testing.T) {
		repo := &workerRepo{webhook: domain.Webhook{ID: d.WebhookID, URL: "://bad", SecretHash: "s"}}
		w := &Worker{repo: repo, client: &http.Client{}, requireHTTPS: false}
		w.deliver(ctx, d)
		if len(repo.statusCalls) != 1 || repo.statusCalls[0].status != "failed" {
			t.Fatalf("expected failed status update, got %+v", repo.statusCalls)
		}
	})

	t.Run("require HTTPS rejects http url", func(t *testing.T) {
		repo := &workerRepo{webhook: domain.Webhook{ID: d.WebhookID, URL: "http://example.com/hook", SecretHash: "s"}}
		w := &Worker{repo: repo, client: &http.Client{}, requireHTTPS: true}
		w.deliver(ctx, d)
		if len(repo.statusCalls) != 1 || repo.statusCalls[0].status != "failed" {
			t.Fatalf("expected failed status update, got %+v", repo.statusCalls)
		}
	})

	t.Run("http client error schedules retry", func(t *testing.T) {
		repo := &workerRepo{webhook: domain.Webhook{ID: d.WebhookID, URL: "https://example.com/hook", SecretHash: "s"}}
		client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("dial error")
		})}
		w := &Worker{repo: repo, client: client, requireHTTPS: false}
		w.deliver(ctx, d)
		if len(repo.statusCalls) != 1 || repo.statusCalls[0].status != "retrying" {
			t.Fatalf("expected retrying status update, got %+v", repo.statusCalls)
		}
	})

	t.Run("2xx response marks delivered", func(t *testing.T) {
		repo := &workerRepo{webhook: domain.Webhook{ID: d.WebhookID, URL: "https://example.com/hook", SecretHash: "s"}}
		client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.Header.Get("X-Guard-Signature") == "" {
				t.Fatal("expected signature header")
			}
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("ok"))}, nil
		})}
		w := &Worker{repo: repo, client: client, requireHTTPS: false}
		w.deliver(ctx, d)
		if len(repo.statusCalls) != 1 || repo.statusCalls[0].status != "delivered" || repo.statusCalls[0].completed == nil {
			t.Fatalf("expected delivered status update with completed time, got %+v", repo.statusCalls)
		}
	})

	t.Run("non-2xx response schedules retry", func(t *testing.T) {
		repo := &workerRepo{webhook: domain.Webhook{ID: d.WebhookID, URL: "https://example.com/hook", SecretHash: "s"}}
		client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 500, Body: io.NopCloser(strings.NewReader("fail"))}, nil
		})}
		w := &Worker{repo: repo, client: client, requireHTTPS: false}
		w.deliver(ctx, d)
		if len(repo.statusCalls) != 1 || repo.statusCalls[0].status != "retrying" {
			t.Fatalf("expected retrying status update, got %+v", repo.statusCalls)
		}
	})
}

func TestNewWorker_DefaultsAndRequireHTTPSEnv(t *testing.T) {
	repo := &workerRepo{}
	old := os.Getenv("WEBHOOK_REQUIRE_HTTPS")
	defer func() { _ = os.Setenv("WEBHOOK_REQUIRE_HTTPS", old) }()

	_ = os.Setenv("WEBHOOK_REQUIRE_HTTPS", "true")
	w := NewWorker(repo)
	if w == nil || w.client == nil {
		t.Fatal("expected NewWorker to initialize client")
	}
	if !w.requireHTTPS {
		t.Fatal("expected requireHTTPS=true from env")
	}
	if w.interval != 5*time.Second || w.batchSize != 50 || w.concurrency != 10 {
		t.Fatalf("unexpected defaults: interval=%s batch=%d conc=%d", w.interval, w.batchSize, w.concurrency)
	}
}

func TestWorkerRun_CancelAndTickPaths(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	repo := &workerRepo{listPending: []domain.Delivery{baseDelivery()}, webhook: domain.Webhook{URL: "https://example.com/hook", SecretHash: "s"}}
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("ok"))}, nil
	})}
	w := &Worker{repo: repo, client: client, interval: 10 * time.Millisecond, batchSize: 5, concurrency: 1}

	go w.Run(ctx)
	time.Sleep(25 * time.Millisecond)
	cancel()
	time.Sleep(10 * time.Millisecond)

	if len(repo.statusCalls) == 0 {
		t.Fatal("expected worker run loop to process at least one delivery before cancellation")
	}

	// immediate cancellation path
	ctx2, cancel2 := context.WithCancel(context.Background())
	cancel2()
	w.Run(ctx2)
}

func TestMarkFailed_DoesNotPanicWhenUpdateFails(t *testing.T) {
	repo := &workerRepo{updateStatusErr: errors.New("write failed")}
	w := &Worker{repo: repo}
	w.markFailed(context.Background(), baseDelivery(), "boom")
	if len(repo.statusCalls) != 1 || repo.statusCalls[0].status != "failed" {
		t.Fatalf("expected failed status call despite update error, got %+v", repo.statusCalls)
	}
}

func TestWorkerRetryAndBatchHelpers(t *testing.T) {
	ctx := context.Background()
	d := baseDelivery()

	t.Run("scheduleRetry caps backoff and eventually fails", func(t *testing.T) {
		repo := &workerRepo{}
		w := &Worker{repo: repo}

		d.Attempts = 10
		d.MaxAttempts = 20
		w.scheduleRetry(ctx, d, "transient")
		if len(repo.statusCalls) != 1 || repo.statusCalls[0].status != "retrying" {
			t.Fatalf("expected retrying status, got %+v", repo.statusCalls)
		}
		if repo.statusCalls[0].nextRetry == nil {
			t.Fatal("expected next retry timestamp")
		}
		until := time.Until(*repo.statusCalls[0].nextRetry)
		if until < 9*time.Minute {
			t.Fatalf("expected retry backoff to be applied (>=9m), got %s", until)
		}
		if until > 11*time.Minute {
			t.Fatalf("expected capped retry backoff around 10m, got %s", until)
		}

		repo.statusCalls = nil
		d.Attempts = d.MaxAttempts
		w.scheduleRetry(ctx, d, "fatal")
		if len(repo.statusCalls) != 1 || repo.statusCalls[0].status != "failed" {
			t.Fatalf("expected failed status when attempts exhausted, got %+v", repo.statusCalls)
		}
	})

	t.Run("processBatch handles list errors and dispatches pending deliveries", func(t *testing.T) {
		repoErr := &workerRepo{listPendingErr: errors.New("db down")}
		wErr := &Worker{repo: repoErr, batchSize: 10, concurrency: 2}
		wErr.processBatch(ctx)
		if len(repoErr.statusCalls) != 0 {
			t.Fatalf("expected no status updates when list fails, got %+v", repoErr.statusCalls)
		}

		repo := &workerRepo{
			listPending: []domain.Delivery{baseDelivery()},
			webhook:     domain.Webhook{URL: "https://example.com/hook", SecretHash: "s"},
		}
		client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("ok"))}, nil
		})}
		w := &Worker{repo: repo, client: client, batchSize: 10, concurrency: 2}
		w.processBatch(ctx)
		if len(repo.statusCalls) == 0 {
			t.Fatal("expected status updates for processed delivery")
		}
	})
}
