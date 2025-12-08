-- +goose Up
-- Composite indexes for refresh_tokens query optimization

-- Index for RevokeRefreshTokensByUserAndTenant and ListUserSessions queries
-- Supports WHERE user_id = $1 AND tenant_id = $2
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_refresh_tokens_user_tenant 
ON refresh_tokens (user_id, tenant_id);

-- Index for RevokeRefreshTokenByHash query optimization
-- Supports WHERE token_hash = $1 AND revoked = FALSE
-- Even though token_hash is unique, the additional revoked column helps the WHERE predicate
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_refresh_tokens_tokenhash_revoked 
ON refresh_tokens (token_hash, revoked);

-- +goose Down
DROP INDEX CONCURRENTLY IF EXISTS idx_refresh_tokens_user_tenant;
DROP INDEX CONCURRENTLY IF EXISTS idx_refresh_tokens_tokenhash_revoked;
