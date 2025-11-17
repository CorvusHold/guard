package state

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupRedis(t *testing.T) *redis.Client {
	client := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
		DB:   15, // Use a separate DB for testing
	})

	// Test connection
	ctx := context.Background()
	if err := client.Ping(ctx).Err(); err != nil {
		t.Skipf("Redis not available: %v", err)
	}

	// Clean up test data
	t.Cleanup(func() {
		if err := client.FlushDB(ctx).Err(); err != nil {
			t.Logf("failed to flush redis test DB: %v", err)
		}
		if err := client.Close(); err != nil {
			t.Logf("failed to close redis client: %v", err)
		}
	})

	return client
}

func TestGenerateStateToken(t *testing.T) {
	t.Run("generates unique tokens", func(t *testing.T) {
		token1, err := GenerateStateToken()
		require.NoError(t, err)
		require.NotEmpty(t, token1)

		token2, err := GenerateStateToken()
		require.NoError(t, err)
		require.NotEmpty(t, token2)

		assert.NotEqual(t, token1, token2)
	})

	t.Run("generates tokens of expected length", func(t *testing.T) {
		token, err := GenerateStateToken()
		require.NoError(t, err)
		// base64 encoding of 32 bytes should be 43 characters (without padding)
		assert.Len(t, token, 43)
	})
}

func TestRedisStateManager_CreateState(t *testing.T) {
	client := setupRedis(t)
	ctx := context.Background()

	tests := []struct {
		name      string
		state     *State
		expectErr bool
		errMsg    string
	}{
		{
			name: "creates valid state",
			state: &State{
				Token:       "test-token-123",
				ProviderID:  uuid.New(),
				TenantID:    uuid.New(),
				RedirectURL: "https://example.com/callback",
				Nonce:       "test-nonce",
			},
			expectErr: false,
		},
		{
			name: "fails with empty token",
			state: &State{
				ProviderID:  uuid.New(),
				TenantID:    uuid.New(),
				RedirectURL: "https://example.com/callback",
			},
			expectErr: true,
			errMsg:    "state token is required",
		},
		{
			name: "fails with nil provider ID",
			state: &State{
				Token:       "test-token-456",
				TenantID:    uuid.New(),
				RedirectURL: "https://example.com/callback",
			},
			expectErr: true,
			errMsg:    "provider ID is required",
		},
		{
			name: "fails with nil tenant ID",
			state: &State{
				Token:       "test-token-789",
				ProviderID:  uuid.New(),
				RedirectURL: "https://example.com/callback",
			},
			expectErr: true,
			errMsg:    "tenant ID is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager := NewRedisStateManager(client, "test:sso:state:", 5*time.Minute)
			err := manager.CreateState(ctx, tt.state)

			if tt.expectErr {
				require.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				require.NoError(t, err)
				assert.False(t, tt.state.CreatedAt.IsZero())
				assert.False(t, tt.state.ExpiresAt.IsZero())
			}
		})
	}
}

func TestRedisStateManager_GetState(t *testing.T) {
	client := setupRedis(t)
	ctx := context.Background()
	manager := NewRedisStateManager(client, "test:sso:state:", 5*time.Minute)

	providerID := uuid.New()
	tenantID := uuid.New()

	t.Run("retrieves existing state", func(t *testing.T) {
		state := &State{
			Token:       "get-test-token",
			ProviderID:  providerID,
			TenantID:    tenantID,
			RedirectURL: "https://example.com/callback",
			Nonce:       "test-nonce",
		}

		err := manager.CreateState(ctx, state)
		require.NoError(t, err)

		retrieved, err := manager.GetState(ctx, "get-test-token")
		require.NoError(t, err)
		assert.Equal(t, state.Token, retrieved.Token)
		assert.Equal(t, state.ProviderID, retrieved.ProviderID)
		assert.Equal(t, state.TenantID, retrieved.TenantID)
		assert.Equal(t, state.RedirectURL, retrieved.RedirectURL)
		assert.Equal(t, state.Nonce, retrieved.Nonce)
	})

	t.Run("returns error for non-existent state", func(t *testing.T) {
		_, err := manager.GetState(ctx, "non-existent-token")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "state not found or expired")
	})

	t.Run("returns error for empty token", func(t *testing.T) {
		_, err := manager.GetState(ctx, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "state token is required")
	})
}

func TestRedisStateManager_DeleteState(t *testing.T) {
	client := setupRedis(t)
	ctx := context.Background()
	manager := NewRedisStateManager(client, "test:sso:state:", 5*time.Minute)

	t.Run("deletes existing state", func(t *testing.T) {
		state := &State{
			Token:       "delete-test-token",
			ProviderID:  uuid.New(),
			TenantID:    uuid.New(),
			RedirectURL: "https://example.com/callback",
		}

		err := manager.CreateState(ctx, state)
		require.NoError(t, err)

		err = manager.DeleteState(ctx, "delete-test-token")
		require.NoError(t, err)

		// Verify it's deleted
		_, err = manager.GetState(ctx, "delete-test-token")
		require.Error(t, err)
	})

	t.Run("succeeds even if state doesn't exist", func(t *testing.T) {
		err := manager.DeleteState(ctx, "non-existent-token")
		require.NoError(t, err)
	})

	t.Run("returns error for empty token", func(t *testing.T) {
		err := manager.DeleteState(ctx, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "state token is required")
	})
}

func TestRedisStateManager_GetAndDelete(t *testing.T) {
	client := setupRedis(t)
	ctx := context.Background()
	manager := NewRedisStateManager(client, "test:sso:state:", 5*time.Minute)

	providerID := uuid.New()
	tenantID := uuid.New()

	t.Run("atomically retrieves and deletes state", func(t *testing.T) {
		state := &State{
			Token:        "atomic-test-token",
			ProviderID:   providerID,
			TenantID:     tenantID,
			RedirectURL:  "https://example.com/callback",
			Nonce:        "test-nonce",
			PKCEVerifier: "test-verifier",
		}

		err := manager.CreateState(ctx, state)
		require.NoError(t, err)

		// First GetAndDelete should succeed
		retrieved, err := manager.GetAndDelete(ctx, "atomic-test-token")
		require.NoError(t, err)
		assert.Equal(t, state.Token, retrieved.Token)
		assert.Equal(t, state.ProviderID, retrieved.ProviderID)
		assert.Equal(t, state.Nonce, retrieved.Nonce)
		assert.Equal(t, state.PKCEVerifier, retrieved.PKCEVerifier)

		// Second GetAndDelete should fail (state was deleted)
		_, err = manager.GetAndDelete(ctx, "atomic-test-token")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "state not found or expired")
	})

	t.Run("returns error for non-existent state", func(t *testing.T) {
		_, err := manager.GetAndDelete(ctx, "non-existent-token")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "state not found or expired")
	})

	t.Run("returns error for empty token", func(t *testing.T) {
		_, err := manager.GetAndDelete(ctx, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "state token is required")
	})
}

func TestRedisStateManager_Expiration(t *testing.T) {
	client := setupRedis(t)
	ctx := context.Background()
	// Use very short expiration for testing
	manager := NewRedisStateManager(client, "test:sso:state:", 1*time.Second)

	t.Run("state expires after TTL", func(t *testing.T) {
		state := &State{
			Token:       "expiry-test-token",
			ProviderID:  uuid.New(),
			TenantID:    uuid.New(),
			RedirectURL: "https://example.com/callback",
		}

		err := manager.CreateState(ctx, state)
		require.NoError(t, err)

		// Should exist immediately
		_, err = manager.GetState(ctx, "expiry-test-token")
		require.NoError(t, err)

		// Wait for expiration
		time.Sleep(2 * time.Second)

		// Should be expired
		_, err = manager.GetState(ctx, "expiry-test-token")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "state not found or expired")
	})
}

func TestRedisStateManager_DefaultValues(t *testing.T) {
	client := setupRedis(t)

	t.Run("uses default key prefix", func(t *testing.T) {
		manager := NewRedisStateManager(client, "", 5*time.Minute)
		assert.Equal(t, "sso:state:", manager.keyPrefix)
	})

	t.Run("uses default expiration", func(t *testing.T) {
		manager := NewRedisStateManager(client, "test:", 0)
		assert.Equal(t, 10*time.Minute, manager.expiration)
	})
}
