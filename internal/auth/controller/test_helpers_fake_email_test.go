package controller

import (
	"context"

	edomain "github.com/corvusHold/guard/internal/email/domain"
	evdomain "github.com/corvusHold/guard/internal/events/domain"
	"github.com/google/uuid"
)

// tokensResponse matches the shape of auth token payloads returned by HTTP endpoints.
type tokensResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// fakeEmail implements edomain.Sender for testing
type fakeEmail struct {
	lastBody string
}

func (f *fakeEmail) Send(ctx context.Context, tenantID uuid.UUID, to, subject, body string) error {
	f.lastBody = body
	return nil
}

var _ edomain.Sender = (*fakeEmail)(nil)

// publisherFunc helps implement evdomain.Publisher in tests via a func.
type publisherFunc func(ctx context.Context, e evdomain.Event) error

func (f publisherFunc) Publish(ctx context.Context, e evdomain.Event) error {
	return f(ctx, e)
}
