package service

import (
	"context"
	"strconv"
	"strings"
	"time"

	sdomain "github.com/corvusHold/guard/internal/settings/domain"
	"github.com/google/uuid"
)

type Service struct{ repo sdomain.Repository }

func New(repo sdomain.Repository) *Service { return &Service{repo: repo} }

func (s *Service) GetString(ctx context.Context, key string, tenantID *uuid.UUID, def string) (string, error) {
	v, ok, err := s.repo.Get(ctx, key, tenantID)
	if err != nil { return def, err }
	if !ok { return def, nil }
	v = strings.TrimSpace(v)
	if v == "" { return def, nil }
	return v, nil
}

func (s *Service) GetDuration(ctx context.Context, key string, tenantID *uuid.UUID, def time.Duration) (time.Duration, error) {
	v, ok, err := s.repo.Get(ctx, key, tenantID)
	if err != nil { return def, err }
	if !ok { return def, nil }
	v = strings.TrimSpace(v)
	if v == "" { return def, nil }
	d, err := time.ParseDuration(v)
	if err != nil { return def, nil }
	return d, nil
}

func (s *Service) GetInt(ctx context.Context, key string, tenantID *uuid.UUID, def int) (int, error) {
	v, ok, err := s.repo.Get(ctx, key, tenantID)
	if err != nil { return def, err }
	if !ok { return def, nil }
	v = strings.TrimSpace(v)
	if v == "" { return def, nil }
	n, err := strconv.Atoi(v)
	if err != nil { return def, nil }
	return n, nil
}
