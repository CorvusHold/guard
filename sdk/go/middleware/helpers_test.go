package middleware

import (
	"context"

	guard "github.com/corvusHold/guard/sdk/go"
)

// mockGuardClient implements the Client interface for testing
type mockGuardClient struct {
	introspectFn         func(ctx context.Context, token *string) (*guard.DomainIntrospection, error)
	resolvePermissionsFn func(ctx context.Context, userID, tenantID string) ([]guard.Permission, error)
}

func (m *mockGuardClient) Introspect(ctx context.Context, token *string) (*guard.DomainIntrospection, error) {
	if m.introspectFn == nil {
		return nil, nil
	}
	return m.introspectFn(ctx, token)
}

func (m *mockGuardClient) ResolveUserPermissions(ctx context.Context, userID, tenantID string) ([]guard.Permission, error) {
	if m.resolvePermissionsFn == nil {
		return nil, nil
	}
	return m.resolvePermissionsFn(ctx, userID, tenantID)
}

// Helper functions for test data
func boolPtr(b bool) *bool {
	return &b
}

func stringPtr(s string) *string {
	return &s
}

func stringsPtr(s ...string) *[]string {
	return &s
}
