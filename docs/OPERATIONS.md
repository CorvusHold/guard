# Corvus Guard Operations Guide

This guide covers operational aspects of running Corvus Guard in production, including monitoring, backup, performance optimization, and troubleshooting.

## Table of Contents

- [Monitoring](#monitoring)
- [Backup and Recovery](#backup-and-recovery)
- [Performance Optimization](#performance-optimization)
- [Security Operations](#security-operations)
- [Troubleshooting](#troubleshooting)
- [Maintenance](#maintenance)
- [Disaster Recovery](#disaster-recovery)

## Monitoring

### Application Metrics

Corvus Guard exposes Prometheus metrics for comprehensive monitoring:

```bash
# Check metrics endpoint
curl http://localhost:8080/metrics

# Key metrics to monitor:
# - guard_http_requests_total
# - guard_http_request_duration_seconds
# - guard_auth_attempts_total
# - guard_auth_failures_total
# - guard_mfa_verifications_total
# - guard_rate_limit_hits_total
# - guard_database_connections
# - guard_email_sends_total
```

### Prometheus Configuration

```yaml
# prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'guard-api'
    static_configs:
      - targets: ['guard-api:8080']
    metrics_path: /metrics
    scrape_interval: 10s

  - job_name: 'guard-ui'
    static_configs:
      - targets: ['guard-ui:3000']
    metrics_path: /api/metrics
    scrape_interval: 30s
```

### Grafana Dashboards

Key dashboards to create:

1. **API Performance Dashboard**
   - Request rate and latency
   - Error rates by endpoint
   - Response time percentiles
   - Active connections

2. **Authentication Dashboard**
   - Login success/failure rates
   - MFA verification rates
   - Rate limiting hits
   - Session duration

3. **Infrastructure Dashboard**
   - Database connection pool usage
   - Memory and CPU utilization
   - Network I/O
   - Disk usage

### Alert Rules

```yaml
# alerts.yml
groups:
  - name: guard-alerts
    rules:
      - alert: HighErrorRate
        expr: rate(guard_http_requests_total{status=~"5.."}[5m]) > 0.1
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "High error rate detected"
          description: "Error rate is {{ $value }} errors per second"

      - alert: HighLatency
        expr: histogram_quantile(0.95, rate(guard_http_request_duration_seconds_bucket[5m])) > 1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High API latency"
          description: "95th percentile latency is {{ $value }}s"

      - alert: AuthenticationFailures
        expr: rate(guard_auth_failures_total[5m]) > 5
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "High authentication failure rate"
          description: "{{ $value }} auth failures per second"

      - alert: DatabaseConnectionsHigh
        expr: guard_database_connections > 80
        for: 1m
        labels:
          severity: warning
        annotations:
          summary: "High database connection usage"
          description: "{{ $value }} active connections"

      - alert: RateLimitHits
        expr: rate(guard_rate_limit_hits_total[5m]) > 10
        for: 1m
        labels:
          severity: info
        annotations:
          summary: "High rate limit activity"
          description: "{{ $value }} rate limit hits per second"
```

### Health Checks

```bash
# Application health check
curl -f http://localhost:8080/health || exit 1

# Database connectivity check
curl -f http://localhost:8080/health/db || exit 1

# Detailed health status
curl http://localhost:8080/health/detailed
```

### Log Monitoring

Configure structured logging with appropriate log levels:

```bash
# Environment variables for logging
export LOG_LEVEL=info
export LOG_FORMAT=json
export LOG_OUTPUT=stdout

# Log aggregation with ELK stack or similar
# Key log patterns to monitor:
# - Authentication failures
# - Rate limit violations
# - Database connection errors
# - Email delivery failures
# - SSO integration errors
```

## Backup and Recovery

### Database Backup

#### PostgreSQL Backup Strategy

```bash
#!/bin/bash
# backup-database.sh

DB_NAME="guard"
DB_USER="guard_user"
DB_HOST="localhost"
BACKUP_DIR="/backups/guard"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Create backup directory
mkdir -p $BACKUP_DIR

# Full database backup
pg_dump -h $DB_HOST -U $DB_USER -d $DB_NAME \
  --verbose --clean --no-owner --no-privileges \
  --format=custom \
  --file=$BACKUP_DIR/guard_full_$TIMESTAMP.dump

# Compress backup
gzip $BACKUP_DIR/guard_full_$TIMESTAMP.dump

# Schema-only backup for quick recovery testing
pg_dump -h $DB_HOST -U $DB_USER -d $DB_NAME \
  --schema-only --verbose --clean --no-owner --no-privileges \
  --file=$BACKUP_DIR/guard_schema_$TIMESTAMP.sql

# Cleanup old backups (keep 30 days)
find $BACKUP_DIR -name "*.dump.gz" -mtime +30 -delete
find $BACKUP_DIR -name "*.sql" -mtime +30 -delete

echo "Backup completed: guard_full_$TIMESTAMP.dump.gz"
```

#### Automated Backup Schedule

```bash
# Add to crontab
# Daily full backup at 2 AM
0 2 * * * /opt/guard/scripts/backup-database.sh

# Hourly incremental backup (if using WAL-E or similar)
0 * * * * /opt/guard/scripts/backup-incremental.sh
```

### Database Recovery

```bash
#!/bin/bash
# restore-database.sh

BACKUP_FILE=$1
DB_NAME="guard"
DB_USER="guard_user"
DB_HOST="localhost"

if [ -z "$BACKUP_FILE" ]; then
  echo "Usage: $0 <backup_file>"
  exit 1
fi

# Stop application services
systemctl stop guard-api
systemctl stop guard-ui

# Drop and recreate database
dropdb -h $DB_HOST -U $DB_USER $DB_NAME
createdb -h $DB_HOST -U $DB_USER $DB_NAME

# Restore from backup
if [[ $BACKUP_FILE == *.gz ]]; then
  gunzip -c $BACKUP_FILE | pg_restore -h $DB_HOST -U $DB_USER -d $DB_NAME --verbose
else
  pg_restore -h $DB_HOST -U $DB_USER -d $DB_NAME --verbose $BACKUP_FILE
fi

# Run migrations to ensure schema is up to date
cd /opt/guard && ./guard migrate up

# Restart services
systemctl start guard-api
systemctl start guard-ui

echo "Database restored from $BACKUP_FILE"
```

### Configuration Backup

```bash
#!/bin/bash
# backup-config.sh

CONFIG_DIR="/opt/guard/config"
BACKUP_DIR="/backups/guard/config"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

mkdir -p $BACKUP_DIR

# Backup configuration files
tar -czf $BACKUP_DIR/guard_config_$TIMESTAMP.tar.gz \
  -C /opt/guard \
  config/ \
  docker-compose.yml \
  .env \
  deploy/

# Backup tenant settings from database
psql -h localhost -U guard_user -d guard \
  -c "COPY tenant_settings TO STDOUT WITH CSV HEADER" \
  > $BACKUP_DIR/tenant_settings_$TIMESTAMP.csv

echo "Configuration backup completed: guard_config_$TIMESTAMP.tar.gz"
```

## Performance Optimization

### Database Performance

#### Connection Pooling

```yaml
# docker-compose.yml
services:
  guard-api:
    environment:
      - DB_MAX_OPEN_CONNS=25
      - DB_MAX_IDLE_CONNS=5
      - DB_CONN_MAX_LIFETIME=300s
      - DB_CONN_MAX_IDLE_TIME=60s
```

#### Query Optimization

```sql
-- Monitor slow queries
SELECT query, mean_exec_time, calls, total_exec_time
FROM pg_stat_statements
WHERE mean_exec_time > 100
ORDER BY mean_exec_time DESC
LIMIT 10;

-- Key indexes for performance
CREATE INDEX CONCURRENTLY idx_users_tenant_email ON users(tenant_id, email);
CREATE INDEX CONCURRENTLY idx_sessions_user_tenant ON sessions(user_id, tenant_id);
CREATE INDEX CONCURRENTLY idx_audit_logs_tenant_created ON audit_logs(tenant_id, created_at);
CREATE INDEX CONCURRENTLY idx_rate_limits_key_window ON rate_limits(key, window_start);

-- Analyze table statistics
ANALYZE users;
ANALYZE sessions;
ANALYZE audit_logs;
ANALYZE tenant_settings;
```

### Application Performance

#### Caching Strategy

```bash
# Redis configuration for caching
export REDIS_URL="redis://localhost:6379/0"
export CACHE_TTL_SESSIONS=3600
export CACHE_TTL_SETTINGS=300
export CACHE_TTL_RATE_LIMITS=60

# Cache key patterns:
# - sessions:{session_id}
# - tenant_settings:{tenant_id}
# - rate_limit:{key}:{window}
# - user_permissions:{user_id}:{tenant_id}
```

#### Rate Limiting Optimization

```yaml
# Optimized rate limiting configuration
rate_limits:
  login:
    limit: 10
    window: "1m"
    burst: 5
  signup:
    limit: 5
    window: "1h"
    burst: 2
  mfa_verify:
    limit: 10
    window: "1m"
    burst: 3
  password_reset:
    limit: 3
    window: "1h"
    burst: 1
```

### Load Testing

```bash
# Install k6 for load testing
curl https://github.com/grafana/k6/releases/download/v0.45.0/k6-v0.45.0-linux-amd64.tar.gz -L | tar xvz --strip-components 1

# Load test script
cat > load-test.js << 'EOF'
import http from 'k6/http';
import { check, sleep } from 'k6';

export let options = {
  stages: [
    { duration: '2m', target: 10 },
    { duration: '5m', target: 50 },
    { duration: '2m', target: 100 },
    { duration: '5m', target: 100 },
    { duration: '2m', target: 0 },
  ],
};

export default function() {
  // Test login endpoint
  let loginPayload = JSON.stringify({
    email: 'test@example.com',
    password: 'Password123!',
  });

  let params = {
    headers: {
      'Content-Type': 'application/json',
      'X-Tenant-ID': 'test-tenant',
    },
  };

  let response = http.post('http://localhost:8080/v1/auth/password/login', loginPayload, params);
  
  check(response, {
    'status is 200 or 202': (r) => r.status === 200 || r.status === 202,
    'response time < 500ms': (r) => r.timings.duration < 500,
  });

  sleep(1);
}
EOF

# Run load test
./k6 run load-test.js
```

## Security Operations

### Security Monitoring

```bash
# Monitor failed authentication attempts
tail -f /var/log/guard/auth.log | grep "auth_failure"

# Check for suspicious rate limiting patterns
curl -s http://localhost:8080/metrics | grep guard_rate_limit_hits_total

# Monitor privilege escalation attempts
tail -f /var/log/guard/audit.log | grep "permission_denied"
```

### Security Hardening

```bash
# SSL/TLS configuration
export TLS_CERT_FILE="/etc/ssl/certs/guard.crt"
export TLS_KEY_FILE="/etc/ssl/private/guard.key"
export TLS_MIN_VERSION="1.2"

# Security headers
export SECURITY_HSTS_MAX_AGE=31536000
export SECURITY_CONTENT_TYPE_NOSNIFF=true
export SECURITY_FRAME_DENY=true
export SECURITY_XSS_PROTECTION=true

# CORS configuration
export CORS_ALLOWED_ORIGINS="https://app.example.com,https://admin.example.com"
export CORS_ALLOWED_METHODS="GET,POST,PUT,DELETE,OPTIONS"
export CORS_ALLOWED_HEADERS="Authorization,Content-Type,X-Tenant-ID"
```

### Audit Log Management

```bash
# Audit log rotation
cat > /etc/logrotate.d/guard << 'EOF'
/var/log/guard/*.log {
    daily
    rotate 90
    compress
    delaycompress
    missingok
    notifempty
    create 644 guard guard
    postrotate
        systemctl reload guard-api
    endscript
}
EOF

# Audit log analysis
grep "login_success" /var/log/guard/audit.log | tail -100
grep "permission_granted" /var/log/guard/audit.log | grep "admin" | tail -50
grep "tenant_created" /var/log/guard/audit.log | tail -20
```

## Troubleshooting

### Common Issues

#### High Memory Usage

```bash
# Check memory usage
ps aux | grep guard | awk '{print $4, $11}' | sort -nr

# Monitor Go heap
curl http://localhost:8080/debug/pprof/heap > heap.prof
go tool pprof heap.prof

# Optimize garbage collection
export GOGC=100
export GOMEMLIMIT=1GiB
```

#### Database Connection Issues

```bash
# Check connection pool status
curl http://localhost:8080/health/db/detailed

# Monitor active connections
psql -U guard_user -d guard -c "
SELECT count(*) as active_connections,
       max_conn,
       max_conn - count(*) as available_connections
FROM pg_stat_activity, (SELECT setting::int as max_conn FROM pg_settings WHERE name = 'max_connections') mc
GROUP BY max_conn;"

# Check for long-running queries
psql -U guard_user -d guard -c "
SELECT pid, now() - pg_stat_activity.query_start AS duration, query
FROM pg_stat_activity
WHERE (now() - pg_stat_activity.query_start) > interval '5 minutes';"
```

#### Rate Limiting Issues

```bash
# Check rate limit status
redis-cli keys "rate_limit:*" | head -10
redis-cli get "rate_limit:tenant:test-tenant:login:2024-01-01T10:00:00Z"

# Reset rate limits for debugging
redis-cli flushdb

# Monitor rate limit metrics
curl -s http://localhost:8080/metrics | grep rate_limit
```

### Debug Mode

```bash
# Enable debug logging
export LOG_LEVEL=debug
export DEBUG_MODE=true

# Enable pprof endpoints
export ENABLE_PPROF=true

# Debug endpoints available at:
# - http://localhost:8080/debug/pprof/
# - http://localhost:8080/debug/vars
# - http://localhost:8080/debug/health
```

## Maintenance

### Regular Maintenance Tasks

```bash
#!/bin/bash
# maintenance.sh - Run weekly

echo "Starting Guard maintenance tasks..."

# 1. Database maintenance
echo "Running database maintenance..."
psql -U guard_user -d guard -c "VACUUM ANALYZE;"
psql -U guard_user -d guard -c "REINDEX DATABASE guard;"

# 2. Clean up old sessions
echo "Cleaning up expired sessions..."
psql -U guard_user -d guard -c "
DELETE FROM sessions 
WHERE expires_at < NOW() - INTERVAL '7 days';"

# 3. Clean up old audit logs (keep 90 days)
echo "Cleaning up old audit logs..."
psql -U guard_user -d guard -c "
DELETE FROM audit_logs 
WHERE created_at < NOW() - INTERVAL '90 days';"

# 4. Clean up old rate limit entries
echo "Cleaning up old rate limits..."
redis-cli --scan --pattern "rate_limit:*" | xargs -r redis-cli del

# 5. Update statistics
echo "Updating database statistics..."
psql -U guard_user -d guard -c "
UPDATE pg_stat_user_tables SET n_tup_ins = 0, n_tup_upd = 0, n_tup_del = 0;"

# 6. Check disk usage
echo "Checking disk usage..."
df -h /var/lib/postgresql
df -h /var/log/guard
df -h /backups/guard

echo "Maintenance tasks completed."
```

### Version Updates

```bash
#!/bin/bash
# update-guard.sh

NEW_VERSION=$1
CURRENT_VERSION=$(curl -s http://localhost:8080/health | jq -r '.version')

if [ -z "$NEW_VERSION" ]; then
  echo "Usage: $0 <new_version>"
  exit 1
fi

echo "Updating Guard from $CURRENT_VERSION to $NEW_VERSION"

# 1. Backup before update
./backup-database.sh
./backup-config.sh

# 2. Stop services
systemctl stop guard-api
systemctl stop guard-ui

# 3. Update application
docker-compose pull
docker-compose up -d --no-deps guard-api guard-ui

# 4. Run migrations
docker-compose exec guard-api ./guard migrate up

# 5. Health check
sleep 10
curl -f http://localhost:8080/health || {
  echo "Health check failed, rolling back..."
  # Rollback procedure here
  exit 1
}

echo "Update completed successfully"
```

## Disaster Recovery

### Recovery Procedures

#### Complete System Recovery

```bash
#!/bin/bash
# disaster-recovery.sh

BACKUP_DATE=$1
BACKUP_DIR="/backups/guard"

if [ -z "$BACKUP_DATE" ]; then
  echo "Usage: $0 <backup_date> (format: YYYYMMDD_HHMMSS)"
  exit 1
fi

echo "Starting disaster recovery for backup: $BACKUP_DATE"

# 1. Restore database
echo "Restoring database..."
./restore-database.sh $BACKUP_DIR/guard_full_$BACKUP_DATE.dump.gz

# 2. Restore configuration
echo "Restoring configuration..."
tar -xzf $BACKUP_DIR/guard_config_$BACKUP_DATE.tar.gz -C /opt/guard/

# 3. Restore tenant settings
echo "Restoring tenant settings..."
psql -U guard_user -d guard -c "
COPY tenant_settings FROM '$BACKUP_DIR/tenant_settings_$BACKUP_DATE.csv' WITH CSV HEADER;"

# 4. Start services
echo "Starting services..."
systemctl start guard-api
systemctl start guard-ui

# 5. Verify recovery
echo "Verifying recovery..."
curl -f http://localhost:8080/health
curl -f http://localhost:3000/health

echo "Disaster recovery completed"
```

### Business Continuity

#### Multi-Region Setup

```yaml
# docker-compose.prod.yml
version: '3.8'
services:
  guard-api:
    deploy:
      replicas: 3
      placement:
        constraints:
          - node.role == worker
      restart_policy:
        condition: on-failure
        delay: 5s
        max_attempts: 3
    environment:
      - DB_HOST=postgres-primary
      - DB_REPLICA_HOST=postgres-replica
      - REDIS_CLUSTER_NODES=redis-1:6379,redis-2:6379,redis-3:6379

  postgres-primary:
    image: postgres:15
    environment:
      - POSTGRES_REPLICATION_MODE=master
      - POSTGRES_REPLICATION_USER=replicator
      - POSTGRES_REPLICATION_PASSWORD=replication_password

  postgres-replica:
    image: postgres:15
    environment:
      - POSTGRES_REPLICATION_MODE=slave
      - POSTGRES_MASTER_HOST=postgres-primary
      - POSTGRES_REPLICATION_USER=replicator
      - POSTGRES_REPLICATION_PASSWORD=replication_password
```

This operations guide provides comprehensive coverage of production operations for Corvus Guard. Regular monitoring, proper backup procedures, and proactive maintenance will ensure reliable service delivery and quick recovery from any issues.
