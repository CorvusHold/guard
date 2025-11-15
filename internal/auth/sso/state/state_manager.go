package state

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

// State represents the SSO state stored during authentication flow.
// It contains all the necessary information to validate and complete
// the SSO callback.
type State struct {
	// Token is the unique state token (used as CSRF protection).
	Token string `json:"token"`

	// ProviderID is the ID of the SSO provider being used.
	ProviderID uuid.UUID `json:"provider_id"`

	// TenantID is the tenant this auth flow belongs to.
	TenantID uuid.UUID `json:"tenant_id"`

	// Nonce is the OIDC nonce for replay protection (OIDC only).
	Nonce string `json:"nonce,omitempty"`

	// PKCEVerifier is the PKCE code verifier (OIDC only).
	PKCEVerifier string `json:"pkce_verifier,omitempty"`

	// RedirectURL is the URL to redirect to after successful authentication.
	RedirectURL string `json:"redirect_url"`

	// RelayState is the SAML relay state (SAML only).
	RelayState string `json:"relay_state,omitempty"`

	// CreatedAt is when this state was created.
	CreatedAt time.Time `json:"created_at"`

	// ExpiresAt is when this state expires.
	ExpiresAt time.Time `json:"expires_at"`

	// IPAddress is the client's IP address when initiating the flow.
	IPAddress string `json:"ip_address,omitempty"`

	// UserAgent is the client's user agent when initiating the flow.
	UserAgent string `json:"user_agent,omitempty"`
}

// StateManager manages SSO state tokens for CSRF protection and flow continuation.
type StateManager interface {
	// CreateState creates and stores a new state token.
	CreateState(ctx context.Context, state *State) error

	// GetState retrieves a state by its token.
	GetState(ctx context.Context, stateToken string) (*State, error)

	// DeleteState deletes a state token (should be called after successful callback).
	DeleteState(ctx context.Context, stateToken string) error

	// GetAndDelete atomically retrieves and deletes a state token.
	// This is the preferred method for callback handling to prevent replay attacks.
	GetAndDelete(ctx context.Context, stateToken string) (*State, error)
}

// GenerateStateToken generates a cryptographically secure random state token.
func GenerateStateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random state: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// RedisStateManager implements StateManager using Redis for storage.
type RedisStateManager struct {
	client     *redis.Client
	keyPrefix  string
	expiration time.Duration
}

// NewRedisStateManager creates a new Redis-backed state manager.
func NewRedisStateManager(client *redis.Client, keyPrefix string, expiration time.Duration) *RedisStateManager {
	if keyPrefix == "" {
		keyPrefix = "sso:state:"
	}
	if expiration == 0 {
		expiration = 10 * time.Minute
	}
	return &RedisStateManager{
		client:     client,
		keyPrefix:  keyPrefix,
		expiration: expiration,
	}
}

// CreateState creates and stores a new state token in Redis.
func (r *RedisStateManager) CreateState(ctx context.Context, state *State) error {
	if state.Token == "" {
		return fmt.Errorf("state token is required")
	}
	if state.ProviderID == uuid.Nil {
		return fmt.Errorf("provider ID is required")
	}
	if state.TenantID == uuid.Nil {
		return fmt.Errorf("tenant ID is required")
	}

	// Set timestamps
	now := time.Now()
	state.CreatedAt = now
	state.ExpiresAt = now.Add(r.expiration)

	// Serialize state to JSON
	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("failed to marshal state: %w", err)
	}

	// Store in Redis with expiration
	key := r.keyPrefix + state.Token
	if err := r.client.Set(ctx, key, data, r.expiration).Err(); err != nil {
		return fmt.Errorf("failed to store state in redis: %w", err)
	}

	return nil
}

// GetState retrieves a state by its token from Redis.
func (r *RedisStateManager) GetState(ctx context.Context, stateToken string) (*State, error) {
	if stateToken == "" {
		return nil, fmt.Errorf("state token is required")
	}

	key := r.keyPrefix + stateToken
	data, err := r.client.Get(ctx, key).Bytes()
	if err == redis.Nil {
		return nil, fmt.Errorf("state not found or expired")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get state from redis: %w", err)
	}

	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("failed to unmarshal state: %w", err)
	}

	// Check if expired (Redis should auto-delete, but double-check)
	if time.Now().After(state.ExpiresAt) {
		_ = r.DeleteState(ctx, stateToken)
		return nil, fmt.Errorf("state has expired")
	}

	return &state, nil
}

// DeleteState deletes a state token from Redis.
func (r *RedisStateManager) DeleteState(ctx context.Context, stateToken string) error {
	if stateToken == "" {
		return fmt.Errorf("state token is required")
	}

	key := r.keyPrefix + stateToken
	if err := r.client.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("failed to delete state from redis: %w", err)
	}

	return nil
}

// GetAndDelete atomically retrieves and deletes a state token.
// This prevents replay attacks by ensuring a state can only be used once.
func (r *RedisStateManager) GetAndDelete(ctx context.Context, stateToken string) (*State, error) {
	if stateToken == "" {
		return nil, fmt.Errorf("state token is required")
	}

	key := r.keyPrefix + stateToken

	// Use a Lua script to atomically get and delete
	script := redis.NewScript(`
		local value = redis.call("GET", KEYS[1])
		if value then
			redis.call("DEL", KEYS[1])
			return value
		else
			return nil
		end
	`)

	result, err := script.Run(ctx, r.client, []string{key}).Result()
	if err == redis.Nil || result == nil {
		return nil, fmt.Errorf("state not found or expired")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get and delete state: %w", err)
	}

	// Convert result to string
	data, ok := result.(string)
	if !ok {
		return nil, fmt.Errorf("invalid state data type")
	}

	var state State
	if err := json.Unmarshal([]byte(data), &state); err != nil {
		return nil, fmt.Errorf("failed to unmarshal state: %w", err)
	}

	// Check if expired
	if time.Now().After(state.ExpiresAt) {
		return nil, fmt.Errorf("state has expired")
	}

	return &state, nil
}
