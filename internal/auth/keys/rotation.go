package keys

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SigningKeyRecord represents a row in the signing_keys table.
type SigningKeyRecord struct {
	ID        uuid.UUID
	TenantID  *uuid.UUID
	Algorithm string
	KeyPEM    string
	KID       string
	Active    bool
	CreatedAt time.Time
	RetiredAt *time.Time
}

// RotatingManager manages multiple signing keys for rotation.
// It signs with the newest active key and can verify with any active key.
type RotatingManager struct {
	pg           *pgxpool.Pool
	mu           sync.RWMutex
	managers     map[string]*Manager  // kid -> Manager
	keyCreatedAt map[string]time.Time // kid -> created_at (for deterministic newest-key selection)
	activeKID    string
	fallback     *Manager // fallback for HS256 or single-key mode
}

// NewRotatingManager creates a RotatingManager backed by the signing_keys table.
func NewRotatingManager(pg *pgxpool.Pool, fallback *Manager) *RotatingManager {
	rm := &RotatingManager{
		pg:           pg,
		managers:     make(map[string]*Manager),
		keyCreatedAt: make(map[string]time.Time),
		fallback:     fallback,
	}
	return rm
}

// LoadKeys loads all active signing keys from the database.
func (rm *RotatingManager) LoadKeys(ctx context.Context, tenantID *uuid.UUID) error {
	query := `SELECT id, tenant_id, algorithm, key_pem, kid, active, created_at, retired_at
	          FROM signing_keys WHERE active = TRUE`
	args := []interface{}{}
	if tenantID != nil {
		query += ` AND (tenant_id = $1 OR tenant_id IS NULL)`
		args = append(args, *tenantID)
	} else {
		query += ` AND tenant_id IS NULL`
	}
	query += ` ORDER BY created_at DESC`

	rows, err := rm.pg.Query(ctx, query, args...)
	if err != nil {
		return err
	}
	defer rows.Close()

	rm.mu.Lock()
	defer rm.mu.Unlock()

	first := true
	for rows.Next() {
		var rec SigningKeyRecord
		var tid *uuid.UUID
		var retiredAt *time.Time
		if err := rows.Scan(&rec.ID, &tid, &rec.Algorithm, &rec.KeyPEM, &rec.KID, &rec.Active, &rec.CreatedAt, &retiredAt); err != nil {
			return err
		}
		rec.TenantID = tid
		rec.RetiredAt = retiredAt

		mgr, err := NewManagerFromPEM(rec.Algorithm, rec.KeyPEM, rec.KID)
		if err != nil {
			continue // skip invalid keys
		}
		rm.managers[rec.KID] = mgr
		rm.keyCreatedAt[rec.KID] = rec.CreatedAt
		if first {
			rm.activeKID = rec.KID
			first = false
		}
	}
	return rows.Err()
}

// ActiveManager returns the manager for the active (newest) signing key.
// Falls back to the fallback manager if no DB keys are loaded.
func (rm *RotatingManager) ActiveManager() *Manager {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	if m, ok := rm.managers[rm.activeKID]; ok {
		return m
	}
	return rm.fallback
}

// ManagerByKID returns the manager for a specific key ID (for verification).
func (rm *RotatingManager) ManagerByKID(kid string) *Manager {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	if m, ok := rm.managers[kid]; ok {
		return m
	}
	return rm.fallback
}

// JWKSBytes returns a combined JWKS containing all active keys.
func (rm *RotatingManager) JWKSBytes() ([]byte, error) {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	allKeys := make([]json.RawMessage, 0, len(rm.managers))
	for _, m := range rm.managers {
		if m.IsAsymmetric() {
			data, err := m.JWKSBytes()
			if err != nil {
				continue
			}
			var jwks struct {
				Keys []json.RawMessage `json:"keys"`
			}
			if err := json.Unmarshal(data, &jwks); err != nil {
				continue
			}
			allKeys = append(allKeys, jwks.Keys...)
		}
	}
	// Include fallback if asymmetric and not already loaded from DB
	if rm.fallback != nil && rm.fallback.IsAsymmetric() {
		if _, alreadyLoaded := rm.managers[rm.fallback.KeyID()]; !alreadyLoaded {
			data, err := rm.fallback.JWKSBytes()
			if err == nil {
				var jwks struct {
					Keys []json.RawMessage `json:"keys"`
				}
				if err := json.Unmarshal(data, &jwks); err == nil {
					allKeys = append(allKeys, jwks.Keys...)
				}
			}
		}
	}

	return json.Marshal(map[string]interface{}{"keys": allKeys})
}

// GenerateAndStore creates a new ES256 key, stores it in the DB, and adds it to the manager.
func (rm *RotatingManager) GenerateAndStore(ctx context.Context, tenantID *uuid.UUID) (*SigningKeyRecord, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	derBytes, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return nil, err
	}
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: derBytes}))

	mgr, err := NewManagerFromPEM("ES256", keyPEM, "")
	if err != nil {
		return nil, err
	}

	rec := &SigningKeyRecord{
		ID:        uuid.New(),
		TenantID:  tenantID,
		Algorithm: "ES256",
		KeyPEM:    keyPEM,
		KID:       mgr.KeyID(),
		Active:    true,
		CreatedAt: time.Now(),
	}

	_, err = rm.pg.Exec(ctx,
		`INSERT INTO signing_keys (id, tenant_id, algorithm, key_pem, kid, active, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		rec.ID, rec.TenantID, rec.Algorithm, rec.KeyPEM, rec.KID, rec.Active, rec.CreatedAt,
	)
	if err != nil {
		return nil, err
	}

	rm.mu.Lock()
	rm.managers[rec.KID] = mgr
	rm.keyCreatedAt[rec.KID] = rec.CreatedAt
	rm.activeKID = rec.KID
	rm.mu.Unlock()

	return rec, nil
}

// RetireKey marks a key as retired in the DB and removes it from the active set.
func (rm *RotatingManager) RetireKey(ctx context.Context, kid string) error {
	now := time.Now()
	_, err := rm.pg.Exec(ctx,
		`UPDATE signing_keys SET active = FALSE, retired_at = $1 WHERE kid = $2`,
		now, kid,
	)
	if err != nil {
		return err
	}

	rm.mu.Lock()
	delete(rm.managers, kid)
	delete(rm.keyCreatedAt, kid)
	if rm.activeKID == kid {
		rm.activeKID = ""
		// Find the newest remaining key by creation time
		var newestTime time.Time
		for k, t := range rm.keyCreatedAt {
			if t.After(newestTime) {
				newestTime = t
				rm.activeKID = k
			}
		}
	}
	rm.mu.Unlock()
	return nil
}

// NewManagerFromPEM creates a Manager from a PEM-encoded private key.
func NewManagerFromPEM(algorithm, keyPEM, kid string) (*Manager, error) {
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in key data")
	}
	privKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	m := &Manager{
		algorithm:  algorithm,
		privateKey: privKey,
		publicKey:  &privKey.PublicKey,
	}
	if kid != "" {
		m.kid = kid
	} else {
		m.kid = thumbprint(&privKey.PublicKey)
	}
	return m, nil
}
