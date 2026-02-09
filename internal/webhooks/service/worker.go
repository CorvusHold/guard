package service

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/corvusHold/guard/internal/webhooks/domain"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/errgroup"
)

// Worker processes pending webhook deliveries in the background.
type Worker struct {
	repo         domain.Repository
	client       *http.Client
	interval     time.Duration
	batchSize    int
	concurrency  int
	requireHTTPS bool
}

// NewWorker creates a new webhook delivery worker.
func NewWorker(repo domain.Repository) *Worker {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("invalid address: %s", addr)
			}
			ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, err
			}
			for _, ip := range ips {
				if isBlockedIP(ip.IP) {
					return nil, fmt.Errorf("webhook target resolves to blocked IP: %s", ip.IP)
				}
			}
			// Dial the validated IP directly to prevent DNS rebinding (TOCTOU).
			if len(ips) == 0 {
				return nil, fmt.Errorf("no IPs resolved for host: %s", host)
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
		},
		// Preserve TLS server name verification when dialing by IP.
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}

	requireHTTPS := os.Getenv("WEBHOOK_REQUIRE_HTTPS") == "true"

	return &Worker{
		repo:         repo,
		client:       &http.Client{Timeout: 10 * time.Second, Transport: transport},
		interval:     5 * time.Second,
		batchSize:    50,
		concurrency:  10,
		requireHTTPS: requireHTTPS,
	}
}

// isBlockedIP returns true if the IP is private, loopback, link-local, or a cloud metadata address.
func isBlockedIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	// Block cloud metadata endpoint 169.254.169.254
	if ip.Equal(net.ParseIP("169.254.169.254")) {
		return true
	}
	return false
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

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(w.concurrency)
	for _, d := range deliveries {
		d := d // capture loop variable
		g.Go(func() error {
			w.deliver(gctx, d)
			return nil
		})
	}
	_ = g.Wait()
}

func (w *Worker) deliver(ctx context.Context, d domain.Delivery) {
	wh, err := w.repo.GetWebhookByID(ctx, d.WebhookID)
	if err != nil {
		log.Error().Err(err).Str("delivery_id", d.ID.String()).Msg("webhook worker: failed to get webhook")
		w.markFailed(ctx, d, fmt.Sprintf("webhook not found: %s", err.Error()))
		return
	}

	// Validate URL before making request (SSRF protection)
	parsedURL, err := url.Parse(wh.URL)
	if err != nil || (parsedURL.Scheme != "https" && parsedURL.Scheme != "http") {
		w.markFailed(ctx, d, fmt.Sprintf("invalid or disallowed webhook URL: %s", wh.URL))
		return
	}
	if w.requireHTTPS && parsedURL.Scheme != "https" {
		w.markFailed(ctx, d, fmt.Sprintf("webhook URL must use HTTPS: %s", wh.URL))
		return
	}
	if parsedURL.Host == "" {
		w.markFailed(ctx, d, "webhook URL has no host")
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
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()

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
	// Exponential backoff: 10s, 20s, 40s, 80s, ... capped at 10 minutes
	backoff := time.Duration(10*(1<<uint(d.Attempts))) * time.Second
	if backoff > 10*time.Minute {
		backoff = 10 * time.Minute
	}
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
