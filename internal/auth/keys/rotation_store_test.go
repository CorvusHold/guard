package keys

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type fakeRow struct {
	id        uuid.UUID
	tenantID  *uuid.UUID
	algorithm string
	keyPEM    string
	kid       string
	active    bool
	createdAt time.Time
	retiredAt *time.Time
	scanErr   error
}

type fakeRows struct {
	rows []fakeRow
	idx  int
	err  error
}

func (r *fakeRows) Close()                                       {}
func (r *fakeRows) Err() error                                   { return r.err }
func (r *fakeRows) CommandTag() pgconn.CommandTag                { return pgconn.NewCommandTag("SELECT 0") }
func (r *fakeRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (r *fakeRows) RawValues() [][]byte                          { return nil }
func (r *fakeRows) Values() ([]interface{}, error)               { return nil, nil }
func (r *fakeRows) Conn() *pgx.Conn                              { return nil }
func (r *fakeRows) Next() bool {
	if r.idx >= len(r.rows) {
		return false
	}
	r.idx++
	return true
}
func (r *fakeRows) Scan(dest ...interface{}) error {
	row := r.rows[r.idx-1]
	if row.scanErr != nil {
		return row.scanErr
	}
	*(dest[0].(*uuid.UUID)) = row.id
	*(dest[1].(**uuid.UUID)) = row.tenantID
	*(dest[2].(*string)) = row.algorithm
	*(dest[3].(*string)) = row.keyPEM
	*(dest[4].(*string)) = row.kid
	*(dest[5].(*bool)) = row.active
	*(dest[6].(*time.Time)) = row.createdAt
	*(dest[7].(**time.Time)) = row.retiredAt
	return nil
}

type storeStub struct {
	queryErr  error
	queryRows pgx.Rows
	querySQL  string
	queryArgs []interface{}
	execErr   error
	execSQL   string
	execArgs  []interface{}
}

func (s *storeStub) Query(_ context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
	s.querySQL = sql
	s.queryArgs = args
	if s.queryErr != nil {
		return nil, s.queryErr
	}
	if s.queryRows != nil {
		return s.queryRows, nil
	}
	return &fakeRows{}, nil
}

func (s *storeStub) Exec(_ context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
	s.execSQL = sql
	s.execArgs = args
	if s.execErr != nil {
		return pgconn.NewCommandTag(""), s.execErr
	}
	return pgconn.NewCommandTag("UPDATE 1"), nil
}

func TestRotatingManager_LoadKeys_QueryError(t *testing.T) {
	rm := NewRotatingManager(&storeStub{queryErr: errors.New("query failed")}, nil)
	if err := rm.LoadKeys(context.Background(), nil); err == nil || err.Error() != "query failed" {
		t.Fatalf("expected query error, got %v", err)
	}
}

func TestRotatingManager_LoadKeys_SetsActiveAndSkipsInvalid(t *testing.T) {
	validPEM := generateTestPEM(t)
	tenantID := uuid.New()
	store := &storeStub{queryRows: &fakeRows{rows: []fakeRow{
		{
			id:        uuid.New(),
			tenantID:  &tenantID,
			algorithm: "ES256",
			keyPEM:    "not-a-pem",
			kid:       "bad-key",
			active:    true,
			createdAt: time.Now(),
		},
		{
			id:        uuid.New(),
			tenantID:  &tenantID,
			algorithm: "ES256",
			keyPEM:    validPEM,
			kid:       "good-key",
			active:    true,
			createdAt: time.Now().Add(-time.Minute),
		},
	}}}

	rm := NewRotatingManager(store, nil)
	if err := rm.LoadKeys(context.Background(), &tenantID); err != nil {
		t.Fatalf("LoadKeys returned error: %v", err)
	}
	if rm.activeKID != "good-key" {
		t.Fatalf("expected active key to be first valid key, got %q", rm.activeKID)
	}
	if len(rm.managers) != 1 {
		t.Fatalf("expected only valid key to load, got %d entries", len(rm.managers))
	}
	if !strings.Contains(store.querySQL, "tenant_id = $1") || len(store.queryArgs) != 1 {
		t.Fatalf("expected tenant-scoped query and args, sql=%q args=%d", store.querySQL, len(store.queryArgs))
	}
}

func TestRotatingManager_LoadKeys_ScanError(t *testing.T) {
	store := &storeStub{queryRows: &fakeRows{rows: []fakeRow{{scanErr: errors.New("scan failed")}}}}
	rm := NewRotatingManager(store, nil)
	if err := rm.LoadKeys(context.Background(), nil); err == nil || err.Error() != "scan failed" {
		t.Fatalf("expected scan error, got %v", err)
	}
}

func TestRotatingManager_GenerateAndStore(t *testing.T) {
	store := &storeStub{}
	rm := NewRotatingManager(store, nil)

	rec, err := rm.GenerateAndStore(context.Background(), nil)
	if err != nil {
		t.Fatalf("GenerateAndStore returned error: %v", err)
	}
	if rec == nil || rec.KID == "" {
		t.Fatalf("expected generated key record with kid, got %+v", rec)
	}
	if rec.Algorithm != "ES256" {
		t.Fatalf("expected ES256 algorithm, got %q", rec.Algorithm)
	}
	if store.execSQL == "" || len(store.execArgs) == 0 {
		t.Fatal("expected INSERT exec to be called")
	}
	if rm.activeKID != rec.KID {
		t.Fatalf("expected active KID to be generated kid %q, got %q", rec.KID, rm.activeKID)
	}
	if _, ok := rm.managers[rec.KID]; !ok {
		t.Fatalf("expected manager to be registered for kid %q", rec.KID)
	}
}

func TestRotatingManager_GenerateAndStore_ExecError(t *testing.T) {
	store := &storeStub{execErr: errors.New("insert failed")}
	rm := NewRotatingManager(store, nil)

	rec, err := rm.GenerateAndStore(context.Background(), nil)
	if err == nil || err.Error() != "insert failed" {
		t.Fatalf("expected insert error, got rec=%+v err=%v", rec, err)
	}
}

func TestRotatingManager_RetireKey_ReassignsNewestActive(t *testing.T) {
	store := &storeStub{}
	rm := NewRotatingManager(store, nil)

	m1, err := NewManager("ES256", "", "")
	if err != nil {
		t.Fatalf("create manager1: %v", err)
	}
	m2, err := NewManager("ES256", "", "")
	if err != nil {
		t.Fatalf("create manager2: %v", err)
	}

	k1, k2 := m1.KeyID(), m2.KeyID()
	rm.managers[k1] = m1
	rm.managers[k2] = m2
	rm.keyCreatedAt[k1] = time.Now().Add(-2 * time.Hour)
	rm.keyCreatedAt[k2] = time.Now().Add(-1 * time.Hour)
	rm.activeKID = k1

	if err := rm.RetireKey(context.Background(), k1); err != nil {
		t.Fatalf("RetireKey returned error: %v", err)
	}
	if rm.activeKID != k2 {
		t.Fatalf("expected active kid to move to newest remaining %q, got %q", k2, rm.activeKID)
	}
	if _, ok := rm.managers[k1]; ok {
		t.Fatalf("expected retired key %q removed from managers", k1)
	}
}

func TestRotatingManager_RetireKey_ExecError(t *testing.T) {
	store := &storeStub{execErr: errors.New("update failed")}
	rm := NewRotatingManager(store, nil)
	kid := uuid.NewString()
	if err := rm.RetireKey(context.Background(), kid); err == nil || err.Error() != "update failed" {
		t.Fatalf("expected update error, got %v", err)
	}
}

func TestRotatingManager_RetireKey_LastKeyClearsActive(t *testing.T) {
	store := &storeStub{}
	rm := NewRotatingManager(store, nil)
	m, err := NewManager("ES256", "", "")
	if err != nil {
		t.Fatalf("create manager: %v", err)
	}
	k := m.KeyID()
	rm.managers[k] = m
	rm.keyCreatedAt[k] = time.Now()
	rm.activeKID = k

	if err := rm.RetireKey(context.Background(), k); err != nil {
		t.Fatalf("RetireKey returned error: %v", err)
	}
	if rm.activeKID != "" {
		t.Fatalf("expected active key cleared when last key retired, got %q", rm.activeKID)
	}
}
