package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/corvusHold/guard/internal/events/domain"
	"github.com/google/uuid"
)

type fakePub struct {
	events []domain.Event
	err    error
}

func (f *fakePub) Publish(_ context.Context, e domain.Event) error {
	f.events = append(f.events, e)
	return f.err
}

func TestMulti_FansOut(t *testing.T) {
	p1 := &fakePub{}
	p2 := &fakePub{}
	m := NewMulti(p1, p2)

	evt := domain.Event{
		Type:     "test.event",
		TenantID: uuid.New(),
		UserID:   uuid.New(),
		Meta:     map[string]string{"key": "val"},
		Time:     time.Now(),
	}
	err := m.Publish(context.Background(), evt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(p1.events) != 1 {
		t.Errorf("expected 1 event in p1, got %d", len(p1.events))
	}
	if len(p2.events) != 1 {
		t.Errorf("expected 1 event in p2, got %d", len(p2.events))
	}
	if p1.events[0].Type != "test.event" {
		t.Errorf("expected event type 'test.event', got %q", p1.events[0].Type)
	}
}

func TestMulti_ReturnsFirstError(t *testing.T) {
	p1 := &fakePub{err: errors.New("p1 failed")}
	p2 := &fakePub{}
	m := NewMulti(p1, p2)

	evt := domain.Event{Type: "err.test"}
	err := m.Publish(context.Background(), evt)
	if err == nil {
		t.Fatal("expected error from first publisher")
	}
	if err.Error() != "p1 failed" {
		t.Errorf("expected 'p1 failed', got %q", err.Error())
	}
	// p2 should still receive the event
	if len(p2.events) != 1 {
		t.Error("p2 should still receive event even if p1 fails")
	}
}

func TestMulti_AllFail_ReturnsFirst(t *testing.T) {
	p1 := &fakePub{err: errors.New("first")}
	p2 := &fakePub{err: errors.New("second")}
	m := NewMulti(p1, p2)

	err := m.Publish(context.Background(), domain.Event{Type: "x"})
	if err == nil || err.Error() != "first" {
		t.Errorf("expected first error, got %v", err)
	}
}

func TestMulti_NoPubs(t *testing.T) {
	m := NewMulti()
	err := m.Publish(context.Background(), domain.Event{Type: "x"})
	if err != nil {
		t.Fatalf("expected no error with no publishers, got %v", err)
	}
}

func TestMulti_Add(t *testing.T) {
	m := NewMulti()
	p := &fakePub{}
	m.Add(p)

	_ = m.Publish(context.Background(), domain.Event{Type: "added"})
	if len(p.events) != 1 {
		t.Error("expected event after Add")
	}
}
