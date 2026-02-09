package service

import (
	"context"

	"github.com/corvusHold/guard/internal/events/domain"
)

// Multi fans out events to multiple publishers.
// Errors from individual publishers are logged but do not block others.
type Multi struct {
	publishers []domain.Publisher
}

// NewMulti creates a fan-out publisher.
func NewMulti(pubs ...domain.Publisher) *Multi {
	return &Multi{publishers: pubs}
}

func (m *Multi) Publish(ctx context.Context, e domain.Event) error {
	var firstErr error
	for _, p := range m.publishers {
		if err := p.Publish(ctx, e); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// Add appends a publisher to the fan-out chain.
func (m *Multi) Add(p domain.Publisher) {
	m.publishers = append(m.publishers, p)
}
