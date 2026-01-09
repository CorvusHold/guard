package service

import (
	"context"
	"testing"

	db "github.com/corvusHold/guard/internal/db/sqlc"
	"github.com/corvusHold/guard/internal/tenants/domain"
	"github.com/google/uuid"
)

type mockRepo struct {
	items []db.Tenant
	total int64
}

func (m *mockRepo) Create(ctx context.Context, id uuid.UUID, name string, parentTenantID *uuid.UUID) error {
	return nil
}
func (m *mockRepo) GetByID(ctx context.Context, id uuid.UUID) (db.Tenant, error) {
	return db.Tenant{}, nil
}
func (m *mockRepo) GetByName(ctx context.Context, name string) (db.Tenant, error) {
	return db.Tenant{}, nil
}
func (m *mockRepo) Deactivate(ctx context.Context, id uuid.UUID) error { return nil }
func (m *mockRepo) List(ctx context.Context, query string, active int, limit, offset int32) ([]db.Tenant, int64, error) {
	return m.items, m.total, nil
}
func (m *mockRepo) ListChildTenants(ctx context.Context, parentID uuid.UUID) ([]db.Tenant, error) {
	return nil, nil
}
func (m *mockRepo) GetTenantAncestors(ctx context.Context, tenantID uuid.UUID) ([]db.Tenant, error) {
	return nil, nil
}
func (m *mockRepo) UpdateParent(ctx context.Context, id uuid.UUID, parentID *uuid.UUID) error {
	return nil
}

func TestServiceList_DefaultsAndPagination(t *testing.T) {
	m := &mockRepo{
		items: []db.Tenant{
			{Name: "a"}, {Name: "b"},
		},
		total: 42,
	}
	s := New(m)

	res, err := s.List(context.Background(), domain.ListOptions{})
	if err != nil {
		t.Fatalf("List returned error: %v", err)
	}
	if res.Page != 1 {
		t.Errorf("expected Page=1 got %d", res.Page)
	}
	if res.PageSize != 20 {
		t.Errorf("expected PageSize=20 got %d", res.PageSize)
	}
	if res.Total != 42 {
		t.Errorf("expected Total=42 got %d", res.Total)
	}
	if res.TotalPages != 3 {
		t.Errorf("expected TotalPages=3 got %d", res.TotalPages)
	}
	if len(res.Items) != 2 {
		t.Errorf("expected Items len=2 got %d", len(res.Items))
	}
}

func TestServiceList_NormalizesActive(t *testing.T) {
	m := &mockRepo{}
	s := New(m)
	_, err := s.List(context.Background(), domain.ListOptions{Active: 99, Page: 0, PageSize: 0})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
