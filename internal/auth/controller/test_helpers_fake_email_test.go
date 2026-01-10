//go:build integration

package controller

import (
	"context"

	edomain "github.com/corvusHold/guard/internal/auth/email/domain"
	"github.com/google/uuid"
)

// fakeEmail implements edomain.Sender for testing
type fakeEmail struct {
	lastBody string
}

func (f *fakeEmail) Send(ctx context.Context, tenantID uuid.UUID, to, subject, body string) error {
	f.lastBody = body
	return nil
}

var _ edomain.Sender = (*fakeEmail)(nil)
