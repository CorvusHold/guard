package service

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/corvusHold/guard/internal/webhooks/domain"
	"github.com/rs/zerolog/log"
)

// Worker processes pending webhook deliveries in the background.
type Worker struct {
	repo      domain.Repository
	client    *http.Client
	interval  time.Duration
	batchSize int
}

// NewWorker creates a new webhook delivery worker.
func NewWorker(repo domain.Repository) *Worker {
	return &Worker{
		repo:      repo,
		client:    &http.Client{Timeout: 10 * time.Second},
		interval:  5 * time.Second,
		batchSize: 50,
	}
}

// Run starts the worker loop. It blocks until the context is cancelled.
func (w *Worker) Run(ctx context.Context) {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.processBatch(ctx)
		}
	}
}

func (w *Worker) processBatch(ctx context.Context) {
	deliveries, err := w.repo.ListPendingDeliveries(ctx, w.batchSize)
	if err != nil {
		log.Error().Err(err).Msg("webhook worker: failed to list pending deliveries")
		return
	}

	for _, d := range deliveries {
		w.deliver(ctx, d)
	}
}

func (w *Worker) deliver(ctx context.Context, d domain.Delivery) {
	wh, err := w.repo.GetWebhookByID(ctx, d.WebhookID)
	if err != nil {
		log.Error().Err(err).Str("delivery_id", d.ID.String()).Msg("webhook worker: failed to get webhook")
		return
	}

	// Build request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, wh.URL, bytes.NewReader(d.Payload))
	if err != nil {
		w.markFailed(ctx, d, err.Error())
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Guard-Event", d.EventType)
	req.Header.Set("X-Guard-Delivery", d.ID.String())

	// Sign payload with webhook secret hash
	signature := SignPayload(wh.SecretHash, d.Payload)
	req.Header.Set("X-Guard-Signature", signature)

	resp, err := w.client.Do(req)
	if err != nil {
		w.scheduleRetry(ctx, d, err.Error())
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		now := time.Now()
		if err := w.repo.UpdateDeliveryStatus(ctx, d.ID, "delivered", "", nil, &now); err != nil {
			log.Error().Err(err).Str("delivery_id", d.ID.String()).Msg("webhook worker: failed to mark delivery as delivered")
		}
	} else {
		w.scheduleRetry(ctx, d, fmt.Sprintf("HTTP %d", resp.StatusCode))
	}
}

func (w *Worker) scheduleRetry(ctx context.Context, d domain.Delivery, lastError string) {
	if d.Attempts+1 >= d.MaxAttempts {
		w.markFailed(ctx, d, lastError)
		return
	}
	// Exponential backoff: 10s, 30s, 90s, 270s, ...
	backoff := time.Duration(10*(1<<uint(d.Attempts))) * time.Second
	nextRetry := time.Now().Add(backoff)
	if err := w.repo.UpdateDeliveryStatus(ctx, d.ID, "retrying", lastError, &nextRetry, nil); err != nil {
		log.Error().Err(err).Str("delivery_id", d.ID.String()).Msg("webhook worker: failed to schedule retry")
	}
}

func (w *Worker) markFailed(ctx context.Context, d domain.Delivery, lastError string) {
	now := time.Now()
	if err := w.repo.UpdateDeliveryStatus(ctx, d.ID, "failed", lastError, nil, &now); err != nil {
		log.Error().Err(err).Str("delivery_id", d.ID.String()).Msg("webhook worker: failed to mark delivery as failed")
	}
}
