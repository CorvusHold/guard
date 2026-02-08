package service

import (
	"context"
	"errors"
	"testing"

	"github.com/corvusHold/guard/internal/applications/domain"
	"github.com/google/uuid"
)

type fakeRepo struct {
	created   domain.Application
	createErr error
	getApp    domain.Application
	getErr    error
	listApps  []domain.Application
	listTotal int
	listErr   error
	updated   domain.Application
	updateErr error
	deleteErr error
}

func (f *fakeRepo) Create(_ context.Context, app domain.Application) (domain.Application, error) {
	if f.createErr != nil {
		return domain.Application{}, f.createErr
	}
	f.created = app
	return app, nil
}
func (f *fakeRepo) GetByID(_ context.Context, _ uuid.UUID) (domain.Application, error) {
	return f.getApp, f.getErr
}
func (f *fakeRepo) List(_ context.Context, _ uuid.UUID, _ domain.ListOptions) ([]domain.Application, int, error) {
	return f.listApps, f.listTotal, f.listErr
}
func (f *fakeRepo) Update(_ context.Context, _ uuid.UUID, _ domain.UpdateInput) (domain.Application, error) {
	return f.updated, f.updateErr
}
func (f *fakeRepo) Delete(_ context.Context, _ uuid.UUID) error {
	return f.deleteErr
}

func TestCreate_Success(t *testing.T) {
	repo := &fakeRepo{}
	svc := New(repo)

	input := domain.CreateInput{
		TenantID:    uuid.New(),
		Name:        "My App",
		Description: "A test application",
		CreatedBy:   uuid.New(),
	}
	app, err := svc.Create(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if app.Name != "My App" {
		t.Errorf("expected name 'My App', got %q", app.Name)
	}
	if app.Description != "A test application" {
		t.Errorf("expected description, got %q", app.Description)
	}
	if !app.IsActive {
		t.Error("expected new app to be active")
	}
	if app.ID == uuid.Nil {
		t.Error("expected non-nil UUID")
	}
}

func TestCreate_EmptyName(t *testing.T) {
	repo := &fakeRepo{}
	svc := New(repo)

	input := domain.CreateInput{
		TenantID: uuid.New(),
		Name:     "   ",
	}
	_, err := svc.Create(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for empty name")
	}
}

func TestCreate_TrimsWhitespace(t *testing.T) {
	repo := &fakeRepo{}
	svc := New(repo)

	input := domain.CreateInput{
		TenantID:    uuid.New(),
		Name:        "  Trimmed App  ",
		Description: "  desc  ",
		LogoURI:     "  https://logo.png  ",
		HomepageURL: "  https://home.com  ",
		CreatedBy:   uuid.New(),
	}
	app, err := svc.Create(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if app.Name != "Trimmed App" {
		t.Errorf("expected trimmed name, got %q", app.Name)
	}
	if app.Description != "desc" {
		t.Errorf("expected trimmed description, got %q", app.Description)
	}
	if app.LogoURI != "https://logo.png" {
		t.Errorf("expected trimmed logo URI, got %q", app.LogoURI)
	}
	if app.HomepageURL != "https://home.com" {
		t.Errorf("expected trimmed homepage URL, got %q", app.HomepageURL)
	}
}

func TestCreate_RepoError(t *testing.T) {
	repo := &fakeRepo{createErr: errors.New("db error")}
	svc := New(repo)

	input := domain.CreateInput{
		TenantID: uuid.New(),
		Name:     "App",
	}
	_, err := svc.Create(context.Background(), input)
	if err == nil {
		t.Fatal("expected error from repo")
	}
}

func TestGetByID_Delegates(t *testing.T) {
	id := uuid.New()
	expected := domain.Application{ID: id, Name: "Found"}
	repo := &fakeRepo{getApp: expected}
	svc := New(repo)

	app, err := svc.GetByID(context.Background(), id)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if app.Name != "Found" {
		t.Errorf("expected 'Found', got %q", app.Name)
	}
}

func TestDelete_Delegates(t *testing.T) {
	repo := &fakeRepo{}
	svc := New(repo)

	err := svc.Delete(context.Background(), uuid.New())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDelete_Error(t *testing.T) {
	repo := &fakeRepo{deleteErr: errors.New("not found")}
	svc := New(repo)

	err := svc.Delete(context.Background(), uuid.New())
	if err == nil {
		t.Fatal("expected error")
	}
}
