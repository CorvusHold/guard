package repository

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestRepository_List_Integration(t *testing.T) {
	if os.Getenv("DATABASE_URL") == "" {
		t.Skip("skipping integration test: DATABASE_URL not set")
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		t.Fatalf("failed to connect to db: %v", err)
	}
	defer pool.Close()

	repo := New(pool)

	// Create a uniquely identifiable tenant
	suffix := uuid.New().String()
	name := "itest-" + suffix
	id := uuid.New()
	if err := repo.Create(ctx, id, name); err != nil {
		t.Fatalf("Create tenant failed: %v", err)
	}
	// Give DB a brief moment in case of transaction lag in CI
	time.Sleep(50 * time.Millisecond)

	// Verify GetByID
	got, err := repo.GetByID(ctx, id)
	if err != nil {
		t.Fatalf("GetByID failed: %v", err)
	}
	if got.Name != name {
		t.Fatalf("expected name %s got %s", name, got.Name)
	}

	// List with name query should return exactly this tenant
	items, total, err := repo.List(ctx, suffix, -1, 10, 0)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if total < 1 {
		t.Fatalf("expected total >= 1 got %d", total)
	}
	found := false
	for _, it := range items {
		if it.Name == name {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("created tenant not found in list results")
	}

	// Active filter: default create is active; ensure active=1 returns it
	_, total2, err := repo.List(ctx, suffix, 1, 10, 0)
	if err != nil {
		t.Fatalf("List with active filter failed: %v", err)
	}
	if total2 < 1 {
		t.Fatalf("expected total2 >= 1 got %d", total2)
	}

	// Pagination limit=1
	items3, _, err := repo.List(ctx, suffix, -1, 1, 0)
	if err != nil {
		t.Fatalf("List with limit failed: %v", err)
	}
	if len(items3) > 1 {
		t.Fatalf("expected <=1 item got %d", len(items3))
	}
}
