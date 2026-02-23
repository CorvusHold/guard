# Guard ES256 Deployment and Recovery Procedures

This document provides comprehensive deployment and disaster recovery procedures for Guard's ES256 JWT signing infrastructure.

## Table of Contents

- [Pre-Deployment Checklist](#pre-deployment-checklist)
- [Deployment Procedures](#deployment-procedures)
- [Key Rotation Procedures](#key-rotation-procedures)
- [Disaster Recovery](#disaster-recovery)
- [Monitoring and Alerts](#monitoring-and-alerts)
- [Incident Response](#incident-response)

---

## Pre-Deployment Checklist

Before deploying Guard with ES256 JWT signing, complete this checklist:

### Infrastructure Requirements

- [ ] PostgreSQL 14+ is running and accessible
- [ ] Redis 6+ is running and accessible
- [ ] HTTPS endpoint configured with valid TLS certificate
- [ ] Firewall rules allow inbound traffic on port 443/8080
- [ ] Sufficient disk space for logs and backups (minimum 10GB)
- [ ] Monitoring and alerting infrastructure is operational

### Key Management

- [ ] ES256 private key generated (see [Key Generation](#key-generation))
- [ ] Private key stored securely (file permissions 600, or secret manager)
- [ ] Private key backed up in encrypted storage
- [ ] Key backup recovery procedure tested
- [ ] Key rotation schedule defined (recommended: 90 days)
- [ ] Key rotation runbook documented and tested

### Environment Variables

- [ ] `DATABASE_URL` points to correct database
- [ ] `REDIS_ADDR` points to correct Redis instance
- [ ] `JWT_SIGNING_ALGORITHM` set to `ES256`
- [ ] `JWT_PRIVATE_KEY_PATH` points to valid key file
- [ ] `PUBLIC_BASE_URL` set to production domain
- [ ] `ACCESS_TOKEN_TTL` configured (default: 15m)
- [ ] `REFRESH_TOKEN_TTL` configured (default: 720h/30d)

### Testing

- [ ] Deployment tested in staging environment
- [ ] Token issuance tested (login/signup flows)
- [ ] Token verification tested (protected endpoints)
- [ ] JWKS endpoint accessible: `https://domain/t/{tenant_id}/.well-known/jwks.json`
- [ ] OIDC discovery endpoint accessible
- [ ] Load testing completed (target: 1000 RPS minimum)
- [ ] Failover testing completed (database/Redis failures)

### Consuming Applications

- [ ] All consuming applications updated to use JWKS (not HMAC)
- [ ] All applications using tenant-scoped issuer and JWKS URLs
- [ ] JWKS cache refresh implemented on unknown `kid`
- [ ] Error handling tested for key rotation scenarios
- [ ] Consuming applications deployed to staging and validated

---

## Deployment Procedures

### First-Time Deployment

#### Step 1: Generate ES256 Key

```bash
# Generate EC private key
openssl ecparam -genkey -name prime256v1 -noout -out jwt-es256-private.pem

# Secure the key file
chmod 600 jwt-es256-private.pem

# Verify key format
openssl ec -in jwt-es256-private.pem -text -noout | head -n 5

# Expected output includes:
# Private-Key: (256 bit)
# ASN1 OID: prime256v1
# NIST CURVE: P-256
```

#### Step 2: Store Key Securely

**Option A: Local File (Development)**

```bash
# Copy to secure location
sudo mkdir -p /etc/guard/keys
sudo cp jwt-es256-private.pem /etc/guard/keys/
sudo chmod 600 /etc/guard/keys/jwt-es256-private.pem
sudo chown guard:guard /etc/guard/keys/jwt-es256-private.pem
```

**Option B: Kubernetes Secret (Production)**

```bash
# Create namespace
kubectl create namespace guard

# Create secret from key file
kubectl create secret generic guard-jwt-key \
  --from-file=jwt-es256-private.pem=./jwt-es256-private.pem \
  --namespace=guard

# Verify secret created
kubectl get secret guard-jwt-key -n guard -o yaml
```

**Option C: Cloud Secret Manager (Recommended)**

```bash
# AWS Secrets Manager
aws secretsmanager create-secret \
  --name guard/prod/jwt-private-key \
  --secret-string file://jwt-es256-private.pem \
  --region us-east-1 \
  --tags Key=Environment,Value=production Key=Application,Value=guard

# GCP Secret Manager
gcloud secrets create guard-prod-jwt-private-key \
  --data-file=jwt-es256-private.pem \
  --replication-policy=automatic \
  --labels=environment=production,application=guard

# Azure Key Vault
az keyvault secret set \
  --vault-name guard-prod-vault \
  --name jwt-private-key \
  --file jwt-es256-private.pem \
  --tags environment=production application=guard
```

#### Step 3: Deploy Guard Application

**Docker Deployment:**

```bash
# Build image
docker build -t guard:latest .

# Run with key mounted
docker run -d \
  --name guard \
  -p 8080:8080 \
  -v /etc/guard/keys/jwt-es256-private.pem:/etc/guard/keys/jwt-es256-private.pem:ro \
  -e DATABASE_URL="postgres://user:pass@db-host:5432/guard" \
  -e REDIS_ADDR="redis-host:6379" \
  -e JWT_SIGNING_ALGORITHM="ES256" \
  -e JWT_PRIVATE_KEY_PATH="/etc/guard/keys/jwt-es256-private.pem" \
  -e PUBLIC_BASE_URL="https://auth.example.com" \
  --restart unless-stopped \
  guard:latest

# Verify startup
docker logs -f guard | head -n 50

# Look for successful startup messages:
# - "loaded EC keys for ES256 JWT signing"
# - "server listening on :8080"
```

**Kubernetes Deployment:**

```yaml
# guard-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: guard
  namespace: guard
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
              name: guard-config
              key: database-url
        - name: REDIS_ADDR
          valueFrom:
            configMapKeyRef:
              name: guard-config
              key: redis-addr
        - name: JWT_SIGNING_ALGORITHM
          value: "ES256"
        - name: JWT_PRIVATE_KEY_PATH
          value: "/etc/guard/keys/jwt-es256-private.pem"
        - name: PUBLIC_BASE_URL
          value: "https://auth.example.com"
        volumeMounts:
        - name: jwt-key
          mountPath: /etc/guard/keys
          readOnly: true
        livenessProbe:
          httpGet:
            path: /readyz
            port: 8080
          initialDelaySeconds: 10
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /readyz
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 10
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "1000m"
      volumes:
      - name: jwt-key
        secret:
          secretName: guard-jwt-key
          defaultMode: 0400
---
apiVersion: v1
kind: Service
metadata:
  name: guard
  namespace: guard
spec:
  selector:
    app: guard
  ports:
  - port: 8080
    targetPort: 8080
  type: LoadBalancer
```

Deploy:
```bash
kubectl apply -f guard-deployment.yaml

# Watch rollout
kubectl rollout status deployment/guard -n guard

# Verify pods running
kubectl get pods -n guard -l app=guard

# Check logs
kubectl logs -f deployment/guard -n guard
```

#### Step 4: Validate Deployment

```bash
# Test health endpoint
curl https://auth.example.com/readyz

# Expected: {"status":"ok"}

# Test JWKS endpoint
curl https://auth.example.com/t/<tenant_id>/.well-known/jwks.json

# Expected: JSON with "keys" array containing ES256 public keys

# Test token issuance
curl -X POST https://auth.example.com/api/v1/auth/password/login \
  -H "Content-Type: application/json" \
  -d '{
    "email":"admin@example.com",
    "password":"your-password",
    "tenant_id":"<tenant_id>"
  }'

# Expected: JSON with "access_token" and "refresh_token"

# Inspect token
TOKEN="<access_token_from_above>"
echo $TOKEN | cut -d. -f1 | base64 -d | jq .

# Expected header:
# {
#   "alg": "ES256",
#   "typ": "JWT",
#   "kid": "..."
# }
```

### Zero-Downtime Updates

For updating Guard without downtime:

```bash
# Kubernetes rolling update
kubectl set image deployment/guard guard=guard:v2.0.0 -n guard
kubectl rollout status deployment/guard -n guard

# Docker rolling update (with multiple instances behind load balancer)
# Update instance 1
docker pull guard:v2.0.0
docker stop guard-1
docker run -d --name guard-1 ... guard:v2.0.0

# Wait 30 seconds, verify health
sleep 30
curl http://guard-1:8080/readyz

# Update instance 2
docker stop guard-2
docker run -d --name guard-2 ... guard:v2.0.0

# Repeat for remaining instances
```

---

## Key Rotation Procedures

Guard supports zero-downtime key rotation using the `signing_keys` table. This allows old keys to remain valid for verification while new keys are used for signing.

### Scheduled Key Rotation (Recommended Frequency: 90 days)

#### Step 1: Generate New Key

```bash
# Generate new ES256 key
openssl ecparam -genkey -name prime256v1 -noout -out jwt-es256-private-new.pem
chmod 600 jwt-es256-private-new.pem

# Verify format
openssl ec -in jwt-es256-private-new.pem -text -noout | grep "Private-Key"

# Backup both old and new keys
cp jwt-es256-private-new.pem ~/backups/jwt-es256-$(date +%Y%m%d).pem
gpg --encrypt --recipient admin@example.com ~/backups/jwt-es256-$(date +%Y%m%d).pem
```

#### Step 2: Deploy New Key to Secret Manager

```bash
# AWS
aws secretsmanager update-secret \
  --secret-id guard/prod/jwt-private-key \
  --secret-string file://jwt-es256-private-new.pem

# GCP
gcloud secrets versions add guard-prod-jwt-private-key \
  --data-file=jwt-es256-private-new.pem

# Azure
az keyvault secret set \
  --vault-name guard-prod-vault \
  --name jwt-private-key \
  --file jwt-es256-private-new.pem
```

#### Step 3: Rolling Restart Guard Instances

```bash
# Kubernetes
kubectl rollout restart deployment/guard -n guard
kubectl rollout status deployment/guard -n guard

# Docker (one at a time)
for instance in guard-1 guard-2 guard-3; do
  docker restart $instance
  sleep 30  # Wait for health check
  curl http://$instance:8080/readyz || { echo "Failed: $instance"; exit 1; }
done
```

#### Step 4: Verify New Key in JWKS

```bash
# Fetch JWKS
curl https://auth.example.com/t/<tenant_id>/.well-known/jwks.json | jq .

# Should show 2 keys now: old key + new key
# New key will have a different "kid" value
```

#### Step 5: Monitor Token Issuance

```bash
# Issue new token
TOKEN=$(curl -X POST https://auth.example.com/api/v1/auth/password/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"***","tenant_id":"<tenant_id>"}' \
  | jq -r .access_token)

# Verify new token uses new kid
echo $TOKEN | cut -d. -f1 | base64 -d | jq .kid

# Should match the new key's kid from JWKS
```

#### Step 6: Wait for Old Token Expiry

```bash
# Wait for refresh token TTL (default: 30 days)
# During this period, both keys remain in JWKS for verification

# Schedule reminder to retire old key
echo "Retire old JWT key" | at now + 31 days
```

#### Step 7: Retire Old Key (After TTL)

```sql
-- Connect to Guard database
psql $DATABASE_URL

-- Mark old key as retired
UPDATE signing_keys
SET active = FALSE, retired_at = NOW()
WHERE kid = '<old-key-kid>';

-- Verify only new key is active
SELECT kid, active, created_at, retired_at
FROM signing_keys
WHERE tenant_id IS NULL OR tenant_id = '<tenant_id>'
ORDER BY created_at DESC;
```

#### Step 8: Remove Old Key from JWKS (After Additional Grace Period)

```sql
-- After additional 7 days grace period
DELETE FROM signing_keys
WHERE kid = '<old-key-kid>'
  AND retired_at < NOW() - INTERVAL '7 days';
```

### Emergency Key Rotation (Compromise/Leak)

If a private key is compromised, rotate immediately:

```bash
# 1. Generate new key immediately
openssl ecparam -genkey -name prime256v1 -noout -out jwt-es256-emergency.pem
chmod 600 jwt-es256-emergency.pem

# 2. Deploy to production immediately (no gradual rollout)
kubectl set image deployment/guard guard=guard:latest -n guard
kubectl set env deployment/guard JWT_PRIVATE_KEY_PATH=/etc/guard/keys/jwt-es256-emergency.pem -n guard

# Update secret
kubectl delete secret guard-jwt-key -n guard
kubectl create secret generic guard-jwt-key \
  --from-file=jwt-es256-private.pem=./jwt-es256-emergency.pem \
  --namespace=guard

# 3. Rolling restart
kubectl rollout restart deployment/guard -n guard

# 4. Revoke all active refresh tokens (forces re-authentication)
psql $DATABASE_URL <<SQL
UPDATE sessions SET revoked_at = NOW() WHERE revoked_at IS NULL;
SQL

# 5. Delete compromised key from JWKS immediately
psql $DATABASE_URL <<SQL
DELETE FROM signing_keys WHERE kid = '<compromised-key-kid>';
SQL

# 6. Notify consuming applications
# Send alert to force JWKS cache refresh
# Invalidate all cached tokens

# 7. Post-incident review
# - How was key compromised?
# - Update security procedures
# - Improve key access controls
```

---

## Disaster Recovery

### Scenario 1: Private Key Loss

**Symptom:** Private key file deleted, secret manager corrupted, no backup accessible

**Recovery Steps:**

```bash
# 1. Generate new emergency key
openssl ecparam -genkey -name prime256v1 -noout -out jwt-es256-emergency.pem
chmod 600 jwt-es256-emergency.pem

# 2. Deploy immediately to all Guard instances
# (Follow deployment procedure above)

# 3. All existing tokens are now invalid
# Users must re-authenticate

# 4. Communicate to users
# - "System maintenance: Please log in again"
# - Expected downtime: ~5 minutes

# 5. Monitor re-authentication rate
# - Watch for login failures
# - Provide support for users having issues
```

**Prevention:**
- Store encrypted key backups in multiple locations
- Use cloud secret manager with automatic backups
- Document key recovery procedures
- Test recovery quarterly

### Scenario 2: Database Failure

**Symptom:** PostgreSQL is down, Guard cannot issue/verify tokens

**Recovery Steps:**

```bash
# 1. Verify database status
psql $DATABASE_URL -c "SELECT 1"

# If connection fails:

# 2. Check database server status
# AWS RDS:
aws rds describe-db-instances --db-instance-identifier guard-db

# 3. Failover to read replica (if available)
# Update DATABASE_URL to point to replica promoted to primary
kubectl set env deployment/guard DATABASE_URL="postgres://user:pass@replica-host:5432/guard" -n guard

# 4. If no replica, restore from backup
# AWS RDS:
aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier guard-db-restored \
  --db-snapshot-identifier guard-db-snapshot-latest

# 5. Update Guard to point to restored database
# 6. Verify functionality
```

**Prevention:**
- Enable automated database backups
- Set up read replicas for high availability
- Configure automatic failover
- Test failover procedure monthly

### Scenario 3: Redis Failure

**Symptom:** Redis is down, SSO state tokens lost, magic links broken

**Recovery Steps:**

```bash
# 1. Redis is only used for ephemeral state
# Token validation still works (uses database)

# 2. Check Redis status
redis-cli -h redis-host ping

# 3. Restart Redis
docker restart redis
# or
kubectl rollout restart statefulset/redis -n guard

# 4. Impact:
# - In-progress SSO flows fail (users retry)
# - In-progress magic link flows fail (request new link)
# - Existing access tokens still work

# 5. No data loss (state is ephemeral)
```

**Prevention:**
- Enable Redis persistence (AOF or RDB)
- Set up Redis Sentinel for automatic failover
- Use Redis Cluster for high availability

### Scenario 4: JWKS Endpoint Unreachable

**Symptom:** Consuming applications cannot fetch JWKS, token validation fails

**Diagnosis:**

```bash
# Test JWKS endpoint
curl -v https://auth.example.com/t/<tenant_id>/.well-known/jwks.json

# Check for:
# - DNS resolution failures
# - TLS certificate issues
# - Network connectivity
# - Guard application errors
```

**Recovery Steps:**

```bash
# 1. Verify Guard is running
kubectl get pods -n guard
docker ps | grep guard

# 2. Check Guard logs
kubectl logs -f deployment/guard -n guard | grep -i "jwks\|keys"

# 3. Verify JWKS endpoint registered
curl http://localhost:8080/t/<tenant_id>/.well-known/jwks.json

# If local curl works but external fails:
# - Check load balancer configuration
# - Check ingress/service configuration
# - Check firewall rules

# 4. Temporary workaround: Consuming apps use cached JWKS
# Most JWKS libraries cache for 1 hour by default

# 5. Fix root cause (DNS, firewall, etc.)

# 6. Verify resolution
curl https://auth.example.com/t/<tenant_id>/.well-known/jwks.json | jq .
```

**Prevention:**
- Monitor JWKS endpoint uptime (target: 99.95%)
- Set up alerts for JWKS fetch failures
- Use CDN or caching layer for JWKS endpoint
- Implement aggressive JWKS caching in consumers

---

## Monitoring and Alerts

### Key Metrics to Monitor

#### Application Metrics

```bash
# Token issuance rate (requests/second)
# Alert: Sudden drop >50% OR spike >10x normal

# Token verification failures (%)
# Alert: >1% failure rate

# JWKS endpoint response time (ms)
# Alert: p95 >500ms

# Key loading errors (count)
# Alert: Any occurrence

# Database connection failures (count)
# Alert: >0 in 5 minutes

# Redis connection failures (count)
# Alert: >0 in 5 minutes (warning, not critical)
```

#### Infrastructure Metrics

```bash
# CPU usage (%)
# Alert: >80% for 5 minutes

# Memory usage (%)
# Alert: >90% for 5 minutes

# Disk usage (%)
# Alert: >85%

# Network latency (ms)
# Alert: >100ms to database

# Pod/container restarts (count)
# Alert: >3 in 10 minutes
```

### Example Prometheus Alerts

```yaml
# alerts.yaml
groups:
- name: guard-jwt
  rules:
  - alert: JWTSigningKeyLoadFailure
    expr: guard_key_load_errors_total > 0
    for: 1m
    labels:
      severity: critical
    annotations:
      summary: "Guard failed to load JWT signing key"
      description: "Guard instance {{ $labels.instance }} failed to load ES256 private key"

  - alert: JWTVerificationFailureHigh
    expr: rate(guard_token_verification_failures_total[5m]) > 0.01
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "High JWT verification failure rate"
      description: "{{ $value | humanizePercentage }} of token verifications failing"

  - alert: JWKSEndpointDown
    expr: up{job="guard",endpoint="jwks"} == 0
    for: 2m
    labels:
      severity: critical
    annotations:
      summary: "JWKS endpoint is unreachable"
      description: "Guard JWKS endpoint has been down for 2 minutes"

  - alert: GuardPodCrashLooping
    expr: rate(kube_pod_container_status_restarts_total{pod=~"guard-.*"}[15m]) > 0
    for: 5m
    labels:
      severity: critical
    annotations:
      summary: "Guard pod is crash looping"
      description: "Pod {{ $labels.pod }} is restarting frequently"
```

### Health Checks

```bash
# Readiness probe (Kubernetes)
# Checks: Database connection, Redis connection, Key loaded
GET /readyz

# Liveness probe (Kubernetes)
# Checks: Application is running and responding
GET /healthz

# Deep health check (manual)
curl https://auth.example.com/api/v1/health

# Expected response:
{
  "status": "healthy",
  "timestamp": "2026-02-23T12:00:00Z",
  "checks": {
    "database": "ok",
    "redis": "ok",
    "jwt_key": "ok"
  }
}
```

---

## Incident Response

### Incident Severity Levels

**P0 - Critical (Respond immediately, page on-call)**
- All token issuance failing
- Private key compromised/leaked
- JWKS endpoint down for >5 minutes
- Database completely unavailable

**P1 - High (Respond within 15 minutes)**
- Elevated token verification failure rate (>5%)
- Partial service degradation
- Key rotation failure

**P2 - Medium (Respond within 2 hours)**
- Individual user authentication issues
- JWKS cache issues
- Performance degradation (<50% normal throughput)

**P3 - Low (Respond within 1 business day)**
- Documentation issues
- Non-critical logging errors
- Minor configuration warnings

### Incident Response Runbook

#### 1. Detection and Triage (0-5 minutes)

```bash
# Alert received: "High JWT verification failure rate"

# Step 1: Verify alert is real (not false positive)
curl https://auth.example.com/readyz

# Step 2: Check Guard status
kubectl get pods -n guard
kubectl logs -f deployment/guard -n guard | tail -n 100

# Step 3: Check recent deployments
kubectl rollout history deployment/guard -n guard

# Step 4: Determine severity level (P0-P3)

# Step 5: Page appropriate team if P0/P1
```

#### 2. Investigation (5-15 minutes)

```bash
# Check metrics dashboard
# - Token issuance rate
# - Verification failure rate
# - Error logs

# Check dependencies
psql $DATABASE_URL -c "SELECT 1"  # Database
redis-cli -h redis-host ping     # Redis

# Check JWKS endpoint
curl https://auth.example.com/t/<tenant_id>/.well-known/jwks.json

# Check recent changes
git log --since="1 hour ago" --oneline
kubectl describe deployment/guard -n guard | grep Image
```

#### 3. Mitigation (15-30 minutes)

```bash
# Option A: Rollback recent deployment
kubectl rollout undo deployment/guard -n guard
kubectl rollout status deployment/guard -n guard

# Option B: Scale up if capacity issue
kubectl scale deployment/guard --replicas=6 -n guard

# Option C: Fix configuration
kubectl edit configmap guard-config -n guard
kubectl rollout restart deployment/guard -n guard

# Option D: Emergency key rotation (if compromise)
# (See Emergency Key Rotation section above)
```

#### 4. Communication (Ongoing)

```bash
# Update status page
curl -X POST https://status.example.com/api/incidents \
  -H "Authorization: Bearer $STATUS_API_KEY" \
  -d '{
    "name": "JWT verification failures",
    "status": "investigating",
    "impact": "partial_outage",
    "message": "We are investigating elevated authentication error rates"
  }'

# Notify stakeholders (email/Slack)
# - Engineering team
# - Product team
# - Customer support
```

#### 5. Resolution and Post-Mortem (After incident)

```bash
# Document timeline
# - Time of first alert
# - Time of triage
# - Time of mitigation
# - Time of resolution

# Root cause analysis
# - What happened?
# - Why did it happen?
# - How did we detect it?
# - How did we resolve it?

# Action items
# - Prevent recurrence
# - Improve detection
# - Improve response time
# - Update runbooks

# Share learnings
# - Internal post-mortem doc
# - Update documentation
# - Improve monitoring/alerts
```

---

## Backup and Restore Procedures

### Private Key Backup

```bash
# Backup key with encryption
gpg --encrypt --recipient admin@example.com jwt-es256-private.pem

# Store in multiple locations:
# 1. Encrypted cloud storage (S3, GCS, Azure Blob)
aws s3 cp jwt-es256-private.pem.gpg s3://guard-backups/keys/$(date +%Y%m%d)/

# 2. Secret manager (automatic backups)
# AWS Secrets Manager: automatic backup
# GCP Secret Manager: versioned (keeps all versions)
# Azure Key Vault: soft delete + purge protection

# 3. Offline encrypted USB drive (air-gapped)
cp jwt-es256-private.pem.gpg /Volumes/BACKUP/guard-keys/

# Test decryption
gpg --decrypt jwt-es256-private.pem.gpg > jwt-es256-private-restored.pem
openssl ec -in jwt-es256-private-restored.pem -text -noout
```

### Database Backup

```bash
# Daily automated backup
pg_dump $DATABASE_URL | gzip > guard-db-$(date +%Y%m%d).sql.gz

# Upload to cloud storage
aws s3 cp guard-db-$(date +%Y%m%d).sql.gz s3://guard-backups/database/

# Verify backup
gunzip -c guard-db-$(date +%Y%m%d).sql.gz | head -n 10

# Retention: 7 daily, 4 weekly, 12 monthly
```

### Restore from Backup

```bash
# Restore database
gunzip -c guard-db-backup.sql.gz | psql $DATABASE_URL

# Restore private key
gpg --decrypt jwt-es256-private.pem.gpg > jwt-es256-private.pem
chmod 600 jwt-es256-private.pem

# Deploy restored key
kubectl create secret generic guard-jwt-key \
  --from-file=jwt-es256-private.pem=./jwt-es256-private.pem \
  --namespace=guard \
  --dry-run=client -o yaml | kubectl apply -f -

# Restart Guard
kubectl rollout restart deployment/guard -n guard

# Verify functionality
curl https://auth.example.com/readyz
```

---

## Testing Procedures

### Pre-Production Testing

```bash
# 1. Unit tests
cd /path/to/guard
go test ./... -v

# 2. Integration tests
make test-integration

# 3. Performance benchmarks
go test -bench=BenchmarkJWT ./internal/auth/keys/... -benchtime=10s

# 4. Load testing
# See ops/k6/ for load test scripts
```

### Production Readiness Checklist

- [ ] All tests passing
- [ ] Load tests completed (target SLA met)
- [ ] Failover tested (database, Redis)
- [ ] Key rotation tested
- [ ] Backup and restore tested
- [ ] Monitoring and alerts configured
- [ ] Incident response runbook documented
- [ ] On-call rotation scheduled
- [ ] Rollback procedure documented and tested

---

## Appendix: Useful Commands

### Debugging

```bash
# Inspect token locally
TOKEN="eyJhbGci..."
echo $TOKEN | cut -d. -f1 | base64 -d | jq .  # Header
echo $TOKEN | cut -d. -f2 | base64 -d | jq .  # Payload

# Verify token signature (requires public key)
echo $TOKEN | jwt decode -

# Check JWKS keys
curl -s https://auth.example.com/t/<tenant_id>/.well-known/jwks.json | jq '.keys[] | {kid, alg, use}'

# Check database signing keys
psql $DATABASE_URL -c "SELECT kid, algorithm, active, created_at, retired_at FROM signing_keys ORDER BY created_at DESC LIMIT 10;"

# Check Guard logs for errors
kubectl logs -f deployment/guard -n guard | grep -i "error\|fatal\|panic"
```

### Performance Tuning

```bash
# Increase Guard replicas
kubectl scale deployment/guard --replicas=5 -n guard

# Adjust resource limits
kubectl set resources deployment/guard -n guard \
  --requests=cpu=500m,memory=512Mi \
  --limits=cpu=2000m,memory=2Gi

# Enable connection pooling
export DB_MAX_CONNS=50
export DB_MIN_CONNS=10

# Tune Redis
redis-cli CONFIG SET maxmemory 2gb
redis-cli CONFIG SET maxmemory-policy allkeys-lru
```

---

## Support

For deployment issues or questions:
- GitHub Issues: https://github.com/CorvusHold/guard/issues
- Documentation: [docs/sso/DEPLOYMENT.md](sso/DEPLOYMENT.md)
- Migration Guide: [docs/IAM_VNEXT_MIGRATION.md](IAM_VNEXT_MIGRATION.md)
