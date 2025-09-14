# Kubernetes Deployment for Corvus Guard

This directory contains Kubernetes manifests for deploying Corvus Guard authentication service in a production-ready configuration with high availability, monitoring, and security.

## Architecture Overview

The deployment includes:
- **Guard API**: 3 replicas with auto-scaling (3-10 pods)
- **Guard UI**: 2 replicas with auto-scaling (2-6 pods)
- **PostgreSQL**: Single instance with persistent storage
- **Redis**: Single instance with persistent storage
- **Ingress**: NGINX with SSL termination and rate limiting
- **Monitoring**: Prometheus metrics and Grafana dashboards
- **Security**: Network policies, RBAC, and security contexts

## Prerequisites

### Required Tools
- `kubectl` (v1.24+)
- `kustomize` (v4.0+)
- `helm` (v3.0+) - optional, for cert-manager

### Cluster Requirements
- Kubernetes v1.24+
- NGINX Ingress Controller
- cert-manager (for SSL certificates)
- Prometheus Operator (for monitoring)
- Metrics Server (for HPA)

### Storage Classes
Ensure you have appropriate storage classes:
```bash
kubectl get storageclass
```

Update `storageClassName` in `postgres.yaml` and `redis.yaml` if needed.

## Quick Start

### 1. Clone and Configure

```bash
git clone https://github.com/corvushold/guard.git
cd guard/deploy/kubernetes
```

### 2. Update Configuration

Edit the following files with your specific values:

**secrets.yaml** - Update all secret values:
```yaml
# Generate secure random values
openssl rand -base64 32  # For JWT secrets
openssl rand -base64 32  # For encryption keys
```

**configmap.yaml** - Update domain and email settings:
```yaml
data:
  NEXT_PUBLIC_GUARD_API_URL: "https://api.yourdomain.com"
  EMAIL_SMTP_FROM: "Guard <noreply@yourdomain.com>"
```

**ingress.yaml** - Update hostnames:
```yaml
spec:
  tls:
  - hosts:
    - api.yourdomain.com
    - app.yourdomain.com
  rules:
  - host: api.yourdomain.com
  - host: app.yourdomain.com
```

### 3. Deploy

```bash
# Apply all manifests
kubectl apply -k .

# Or apply individually
kubectl apply -f namespace.yaml
kubectl apply -f configmap.yaml
kubectl apply -f secrets.yaml
kubectl apply -f postgres.yaml
kubectl apply -f redis.yaml
kubectl apply -f guard-api.yaml
kubectl apply -f guard-ui.yaml
kubectl apply -f ingress.yaml
kubectl apply -f monitoring.yaml
kubectl apply -f hpa.yaml
```

### 4. Verify Deployment

```bash
# Check all pods are running
kubectl get pods -n guard

# Check services
kubectl get svc -n guard

# Check ingress
kubectl get ingress -n guard

# Check HPA status
kubectl get hpa -n guard
```

## Configuration

### Environment-Specific Overlays

Create environment-specific configurations using Kustomize overlays:

```bash
mkdir -p overlays/production
mkdir -p overlays/staging
```

**overlays/production/kustomization.yaml**:
```yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

namespace: guard-prod

resources:
- ../../base

patchesStrategicMerge:
- replica-count.yaml
- resource-limits.yaml

images:
- name: corvushold/guard-api
  newTag: "v1.2.3"
- name: corvushold/guard-ui
  newTag: "v1.2.3"
```

### SSL Certificates

#### Using cert-manager (Recommended)

```bash
# Install cert-manager
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.0/cert-manager.yaml

# Create ClusterIssuer
cat <<EOF | kubectl apply -f -
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: admin@yourdomain.com
    privateKeySecretRef:
      name: letsencrypt-prod
    solvers:
    - http01:
        ingress:
          class: nginx
EOF
```

#### Using Custom Certificates

```bash
# Create TLS secret with your certificates
kubectl create secret tls guard-tls-secret \
  --cert=path/to/tls.crt \
  --key=path/to/tls.key \
  -n guard
```

### Database Migration

Run database migrations after deployment:

```bash
# Get API pod name
API_POD=$(kubectl get pods -n guard -l app.kubernetes.io/name=guard-api -o jsonpath='{.items[0].metadata.name}')

# Run migrations
kubectl exec -n guard $API_POD -- ./guard migrate up

# Seed initial data (optional)
kubectl exec -n guard $API_POD -- ./guard seed default \
  --tenant-name "Default Tenant" \
  --email "admin@yourdomain.com" \
  --password "SecurePassword123!" \
  --enable-mfa
```

## Monitoring

### Prometheus Metrics

Guard API exposes metrics at `/metrics`:
- `guard_http_requests_total`
- `guard_http_request_duration_seconds`
- `guard_auth_attempts_total`
- `guard_auth_failures_total`
- `guard_database_connections`

### Grafana Dashboard

Import the provided dashboard:
```bash
kubectl apply -f monitoring.yaml
```

Access Grafana and import the Guard dashboard from the ConfigMap.

### Alerts

The deployment includes PrometheusRule with alerts for:
- API downtime
- High error rates
- High latency
- Authentication failures
- Database connection issues
- Pod crashes

## Scaling

### Manual Scaling

```bash
# Scale API
kubectl scale deployment guard-api --replicas=5 -n guard

# Scale UI
kubectl scale deployment guard-ui --replicas=3 -n guard
```

### Auto Scaling

HPA is configured to scale based on:
- CPU utilization (70%)
- Memory utilization (80%)
- Custom metrics (requests per second)

```bash
# Check HPA status
kubectl get hpa -n guard

# Describe HPA for details
kubectl describe hpa guard-api-hpa -n guard
```

## Security

### Network Policies

Network policies restrict traffic to:
- Allow ingress from NGINX controller
- Allow internal communication within namespace
- Allow monitoring from Prometheus
- Block all other traffic

### Pod Security

All pods run with:
- Non-root user
- Read-only root filesystem
- Dropped capabilities
- Security contexts

### RBAC

Service accounts with minimal required permissions:
```bash
kubectl get serviceaccount -n guard
kubectl describe serviceaccount guard-api -n guard
```

## Backup and Recovery

### Database Backup

```bash
# Create backup job
cat <<EOF | kubectl apply -f -
apiVersion: batch/v1
kind: Job
metadata:
  name: postgres-backup-$(date +%Y%m%d-%H%M%S)
  namespace: guard
spec:
  template:
    spec:
      containers:
      - name: postgres-backup
        image: postgres:15-alpine
        command:
        - /bin/bash
        - -c
        - |
          pg_dump -h postgres-service -U guard_user -d guard \
            --verbose --clean --no-owner --no-privileges \
            --format=custom > /backup/guard-backup-$(date +%Y%m%d-%H%M%S).dump
        env:
        - name: PGPASSWORD
          valueFrom:
            secretKeyRef:
              name: postgres-secrets
              key: POSTGRES_PASSWORD
        volumeMounts:
        - name: backup-storage
          mountPath: /backup
      volumes:
      - name: backup-storage
        persistentVolumeClaim:
          claimName: backup-pvc
      restartPolicy: Never
EOF
```

### Configuration Backup

```bash
# Backup all configurations
kubectl get configmap,secret -n guard -o yaml > guard-config-backup.yaml
```

## Troubleshooting

### Common Issues

#### Pods Not Starting

```bash
# Check pod status
kubectl get pods -n guard

# Check pod logs
kubectl logs -n guard deployment/guard-api

# Describe pod for events
kubectl describe pod -n guard <pod-name>
```

#### Database Connection Issues

```bash
# Check PostgreSQL pod
kubectl logs -n guard deployment/postgres

# Test connection from API pod
kubectl exec -n guard deployment/guard-api -- \
  psql -h postgres-service -U guard_user -d guard -c "SELECT 1;"
```

#### SSL Certificate Issues

```bash
# Check certificate status
kubectl get certificate -n guard

# Check cert-manager logs
kubectl logs -n cert-manager deployment/cert-manager
```

#### Ingress Issues

```bash
# Check ingress status
kubectl describe ingress guard-ingress -n guard

# Check NGINX controller logs
kubectl logs -n ingress-nginx deployment/ingress-nginx-controller
```

### Debug Commands

```bash
# Get all resources
kubectl get all -n guard

# Check resource usage
kubectl top pods -n guard
kubectl top nodes

# Check events
kubectl get events -n guard --sort-by='.lastTimestamp'

# Port forward for local testing
kubectl port-forward -n guard svc/guard-api-service 8080:8080
kubectl port-forward -n guard svc/guard-ui-service 3000:3000
```

## Maintenance

### Updates

```bash
# Update image tags in kustomization.yaml
# Then apply
kubectl apply -k .

# Check rollout status
kubectl rollout status deployment/guard-api -n guard
kubectl rollout status deployment/guard-ui -n guard

# Rollback if needed
kubectl rollout undo deployment/guard-api -n guard
```

### Cleanup

```bash
# Delete all resources
kubectl delete -k .

# Or delete namespace (removes everything)
kubectl delete namespace guard
```

## Production Checklist

- [ ] Update all secrets with secure random values
- [ ] Configure proper domain names in ingress
- [ ] Set up SSL certificates (cert-manager or custom)
- [ ] Configure email provider settings
- [ ] Set up monitoring and alerting
- [ ] Configure backup strategy
- [ ] Test disaster recovery procedures
- [ ] Review resource limits and requests
- [ ] Configure log aggregation
- [ ] Set up network policies
- [ ] Review security contexts
- [ ] Test auto-scaling behavior
- [ ] Configure persistent volume backup
- [ ] Set up external DNS (if needed)
- [ ] Configure load balancer health checks

## Support

For issues and questions:
- Check the troubleshooting section above
- Review logs: `kubectl logs -n guard deployment/guard-api`
- Check GitHub issues: https://github.com/corvushold/guard/issues
- Contact support: support@corvushold.com
