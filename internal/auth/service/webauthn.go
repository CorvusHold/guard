package service

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// WebAuthnCredential represents a stored passkey credential.
type WebAuthnCredential struct {
	ID              uuid.UUID
	UserID          uuid.UUID
	TenantID        uuid.UUID
	CredentialID    []byte
	PublicKey       []byte
	AttestationType string
	AAGUID          []byte
	SignCount       uint32
	Transports      []string
	FriendlyName    string
	CreatedAt       time.Time
	LastUsedAt      *time.Time
}

// WebAuthnService handles passkey registration and authentication.
type WebAuthnService struct {
	pg *pgxpool.Pool
}

// NewWebAuthnService creates a new WebAuthn service.
func NewWebAuthnService(pg *pgxpool.Pool) *WebAuthnService {
	return &WebAuthnService{pg: pg}
}

// StoreCredential persists a new WebAuthn credential.
func (w *WebAuthnService) StoreCredential(ctx context.Context, cred WebAuthnCredential) error {
	_, err := w.pg.Exec(ctx,
		`INSERT INTO webauthn_credentials (id, user_id, tenant_id, credential_id, public_key, attestation_type, aaguid, sign_count, transports, friendly_name, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		cred.ID, cred.UserID, cred.TenantID, cred.CredentialID, cred.PublicKey,
		cred.AttestationType, cred.AAGUID, cred.SignCount, cred.Transports, cred.FriendlyName, cred.CreatedAt,
	)
	return err
}

// ListCredentials returns all WebAuthn credentials for a user in a tenant.
func (w *WebAuthnService) ListCredentials(ctx context.Context, userID, tenantID uuid.UUID) ([]WebAuthnCredential, error) {
	rows, err := w.pg.Query(ctx,
		`SELECT id, user_id, tenant_id, credential_id, public_key, attestation_type, aaguid, sign_count, transports, friendly_name, created_at, last_used_at
		 FROM webauthn_credentials WHERE user_id = $1 AND tenant_id = $2 ORDER BY created_at DESC`,
		userID, tenantID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var creds []WebAuthnCredential
	for rows.Next() {
		var c WebAuthnCredential
		if err := rows.Scan(&c.ID, &c.UserID, &c.TenantID, &c.CredentialID, &c.PublicKey,
			&c.AttestationType, &c.AAGUID, &c.SignCount, &c.Transports, &c.FriendlyName, &c.CreatedAt, &c.LastUsedAt); err != nil {
			return nil, err
		}
		creds = append(creds, c)
	}
	return creds, rows.Err()
}

// GetCredentialByID retrieves a credential by its credential_id bytes.
func (w *WebAuthnService) GetCredentialByID(ctx context.Context, credentialID []byte) (WebAuthnCredential, error) {
	var c WebAuthnCredential
	err := w.pg.QueryRow(ctx,
		`SELECT id, user_id, tenant_id, credential_id, public_key, attestation_type, aaguid, sign_count, transports, friendly_name, created_at, last_used_at
		 FROM webauthn_credentials WHERE credential_id = $1`,
		credentialID,
	).Scan(&c.ID, &c.UserID, &c.TenantID, &c.CredentialID, &c.PublicKey,
		&c.AttestationType, &c.AAGUID, &c.SignCount, &c.Transports, &c.FriendlyName, &c.CreatedAt, &c.LastUsedAt)
	return c, err
}

// UpdateSignCount updates the sign count and last used timestamp after authentication.
func (w *WebAuthnService) UpdateSignCount(ctx context.Context, credentialID []byte, signCount uint32) error {
	_, err := w.pg.Exec(ctx,
		`UPDATE webauthn_credentials SET sign_count = $1, last_used_at = now() WHERE credential_id = $2`,
		signCount, credentialID,
	)
	return err
}

// DeleteCredential removes a WebAuthn credential.
func (w *WebAuthnService) DeleteCredential(ctx context.Context, id uuid.UUID, userID uuid.UUID) error {
	_, err := w.pg.Exec(ctx,
		`DELETE FROM webauthn_credentials WHERE id = $1 AND user_id = $2`,
		id, userID,
	)
	return err
}
