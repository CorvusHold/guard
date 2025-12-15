# SSO Deployment Guide

## Prerequisites

- **PostgreSQL 14+** for SSO provider storage
- **Redis 6+** for state token storage
- **HTTPS endpoint** (required for production)
- **Admin access** to identity providers (Google, Okta, etc.)
- **Go 1.21+** for building from source

## Environment Variables

```bash
# Required
DATABASE_URL=postgres://user:pass@localhost:5432/guard
REDIS_ADDR=localhost:6379

# Optional - Override defaults
PUBLIC_BASE_URL=https://auth.example.com
JWT_SIGNING_KEY=<secret-key>
ACCESS_TOKEN_TTL=15m
REFRESH_TOKEN_TTL=7d
LOG_LEVEL=info
```

## Database Migration

Run the SSO migration:

```bash
# Check current migration version
psql $DATABASE_URL -c "SELECT version FROM schema_migrations ORDER BY version DESC LIMIT 1;"

# Apply SSO migration (should be 000006_sso_providers.sql)
make migrate-up

# Or manually
psql $DATABASE_URL < migrations/000006_sso_providers.sql
```

Verify tables created:
```sql
\dt sso_*
-- Should show: sso_providers, sso_auth_attempts, sso_sessions
```

## Redis Configuration

SSO requires Redis for state token storage:

```bash
# Test Redis connection
redis-cli -h localhost -p 6379 ping
# Expected: PONG

# Check memory usage
redis-cli info memory
```

Configure Redis persistence (optional but recommended):
```conf
# redis.conf
save 900 1        # Save if 1 key changed in 15 minutes
save 300 10       # Save if 10 keys changed in 5 minutes
save 60 10000     # Save if 10000 keys changed in 1 minute
```

## Initial Setup

### 1. Build and Start Guard

```bash
# Build
go build -o guard ./cmd/api

# Run
./guard
```

### 2. Create Tenant

```bash
# Create a tenant (if not exists)
curl -X POST http://localhost:8080/api/v1/tenants \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My Organization",
    "slug": "my-org"
  }'

# Response includes tenant_id
```

### 3. Create Admin User

```bash
# Sign up admin user
curl -X POST http://localhost:8080/api/v1/auth/password/signup \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "<tenant_id>",
    "email": "admin@example.com",
    "password": "SecurePassword123!",
    "first_name": "Admin",
    "last_name": "User"
  }'

# Get access token
curl -X POST http://localhost:8080/api/v1/auth/password/login \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "<tenant_id>",
    "email": "admin@example.com",
    "password": "SecurePassword123!"
  }'

# Save the access_token from response
```

### 4. Configure SSO Provider

See [SSO_API.md](../api/SSO_API.md) for full API documentation.

#### Example: Google OIDC

```bash
# 1. Create OAuth 2.0 Client in Google Cloud Console
# https://console.cloud.google.com/apis/credentials
# - Application type: Web application
# - Authorized redirect URIs: https://auth.example.com/auth/sso/google/callback

# 2. Create provider in Guard
curl -X POST http://localhost:8080/api/v1/sso/providers \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "<tenant_id>",
    "name": "Google SSO",
    "slug": "google",
    "provider_type": "oidc",
    "enabled": true,
    "allow_signup": true,
    "trust_email_verified": true,
    "domains": ["example.com"],
    "issuer": "https://accounts.google.com",
    "client_id": "<google_client_id>",
    "client_secret": "<google_client_secret>",
    "scopes": ["openid", "profile", "email"]
  }'
```

#### Example: Okta SAML

```bash
# 1. Create SAML app in Okta Admin Console
# - Single sign on URL: https://auth.example.com/auth/sso/okta/callback
# - Audience URI (SP Entity ID): https://auth.example.com/auth/sso/okta/metadata
# - Attribute Statements:
#   - email -> user.email
#   - firstName -> user.firstName
#   - lastName -> user.lastName

# 2. Get IdP metadata URL from Okta app settings

# 3. Create provider in Guard
curl -X POST http://localhost:8080/api/v1/sso/providers \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "<tenant_id>",
    "name": "Okta SAML",
    "slug": "okta",
    "provider_type": "saml",
    "enabled": true,
    "allow_signup": true,
    "trust_email_verified": true,
    "entity_id": "https://auth.example.com/saml",
    "acs_url": "https://auth.example.com/auth/sso/okta/callback",
    "idp_metadata_url": "https://<okta_domain>/app/<app_id>/sso/saml/metadata",
    "want_assertions_signed": true,
    "want_response_signed": false
  }'
```

## Testing

### Manual Test

1. **Initiate SSO:**
   ```bash
   # In browser or with curl -L
   open "http://localhost:8080/auth/sso/google/login?tenant_id=<tenant_id>"
   ```

2. **Verify redirect to IdP** - Should redirect to Google/Okta login page

3. **Complete authentication at IdP**

4. **Verify callback returns tokens:**
   ```json
   {
     "access_token": "eyJ...",
     "refresh_token": "..."
   }
   ```

5. **Test token:**
   ```bash
   curl http://localhost:8080/api/v1/auth/me \
     -H "Authorization: Bearer <access_token>"
   ```

### Automated Test

```bash
# Run integration tests
go test -tags=integration ./internal/auth/sso/... -v

# Run specific test
go test -tags=integration ./internal/auth/sso/... -run TestOIDCFlow -v
```

## Monitoring

### Health Check

```bash
curl http://localhost:8080/health
```

Expected response:
```json
{
  "status": "healthy",
  "services": {
    "database": "up",
    "redis": "up"
  }
}
```

### Metrics

```bash
# View all SSO metrics
curl http://localhost:8080/metrics | grep guard_sso
```

Key metrics:
- `guard_sso_initiate_total` - SSO initiation count
- `guard_sso_callback_total` - Callback success/failure
- `guard_sso_auth_duration_seconds` - Auth flow duration

### Logs

```bash
# Follow logs
tail -f /var/log/guard/app.log | grep sso

# Search for errors
grep "sso.*error\|sso.*failed" /var/log/guard/app.log

# Check specific provider
grep "provider_slug.*google" /var/log/guard/app.log
```

## Production Checklist

- [ ] **HTTPS enabled** - All endpoints use TLS
- [ ] **DATABASE_URL configured with SSL** - `?sslmode=require`
- [ ] **Redis password protected** - Set requirepass in redis.conf
- [ ] **JWT_SIGNING_KEY** is strong and secret (32+ bytes)
- [ ] **Rate limiting enabled** - Configured in application
- [ ] **Monitoring/alerting configured** - Prometheus + Alertmanager
- [ ] **Backup strategy for PostgreSQL** - Daily backups configured
- [ ] **Redis persistence enabled** - RDB or AOF enabled
- [ ] **Log aggregation configured** - Centralized logging (ELK, Loki, etc.)
- [ ] **All provider secrets rotated** from defaults
- [ ] **Domain restrictions configured** - Email domain filtering enabled
- [ ] **Audit logging enabled** - Events published and stored
- [ ] **Load testing completed** - Tested under expected load
- [ ] **Disaster recovery plan** documented
- [ ] **Security review completed** - Penetration testing done

## Production Deployment

### Docker Deployment

```dockerfile
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o guard ./cmd/api

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/guard .
COPY --from=builder /app/migrations ./migrations
EXPOSE 8080
CMD ["./guard"]
```

```bash
# Build image
docker build -t guard:latest .

# Run with docker-compose
docker-compose up -d
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: guard
spec:
  replicas: 3
  selector:
    matchLabels:
      app: guard
  template:
    metadata:
      labels:
        app: guard
    spec:
      containers:
      - name: guard
        image: guard:latest
        ports:
        - containerPort: 8080
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: guard-secrets
              key: database-url
        - name: REDIS_ADDR
          value: redis:6379
        - name: PUBLIC_BASE_URL
          value: https://auth.example.com
```

## Backup & Recovery

### Database Backup

```bash
# Backup SSO providers
pg_dump -t sso_providers -t sso_auth_attempts -t sso_sessions \
  $DATABASE_URL > sso_backup.sql

# Backup with compression
pg_dump -t sso_providers -t sso_auth_attempts -t sso_sessions \
  $DATABASE_URL | gzip > sso_backup_$(date +%Y%m%d).sql.gz

# Restore
gunzip < sso_backup_20250114.sql.gz | psql $DATABASE_URL
```

### Redis Backup

```bash
# Trigger save
redis-cli SAVE

# Backup RDB file
cp /var/lib/redis/dump.rdb /backup/redis-$(date +%Y%m%d).rdb

# Restore (stop Redis first)
sudo systemctl stop redis
cp /backup/redis-20250114.rdb /var/lib/redis/dump.rdb
sudo systemctl start redis
```

## Rollback Plan

If issues occur after deployment:

1. **Disable affected provider:**
   ```bash
   curl -X PUT http://localhost:8080/api/v1/sso/providers/<id> \
     -H "Authorization: Bearer <token>" \
     -H "Content-Type: application/json" \
     -d '{"enabled": false}'
   ```

2. **Check logs for errors**
   ```bash
   tail -n 1000 /var/log/guard/app.log | grep -i error
   ```

3. **Restore from backup if needed**
   ```bash
   psql $DATABASE_URL < sso_backup.sql
   ```

4. **Users can still use password auth** - SSO is additive, doesn't replace existing auth

5. **Rollback application version**
   ```bash
   # Docker
   docker pull guard:previous-version
   docker-compose up -d

   # Kubernetes
   kubectl rollout undo deployment/guard
   ```

## Upgrading

When upgrading Guard:

1. **Review release notes** for SSO-related changes
2. **Test in staging** environment first
3. **Backup database and Redis**
4. **Run new migrations** if any
5. **Deploy new version** with zero-downtime strategy
6. **Monitor metrics** for 24 hours
7. **Validate SSO flows** with test accounts

## Scaling Considerations

### Horizontal Scaling

- Guard API is stateless (state in Redis)
- Can run multiple instances behind load balancer
- Ensure Redis is configured for high availability
- Use Redis Cluster or Sentinel for failover

### High Availability

```bash
# PostgreSQL - Use replication
# Primary-Replica setup with automatic failover

# Redis - Use Sentinel
redis-sentinel /etc/redis/sentinel.conf

# Load Balancer - Use health checks
# Configure /health endpoint monitoring
```

## Support

For issues:
- Check [TROUBLESHOOTING.md](TROUBLESHOOTING.md) first
- Review logs and metrics
- Check [SSO_API.md](../api/SSO_API.md) for API details
- Open issue with full details if problem persists
