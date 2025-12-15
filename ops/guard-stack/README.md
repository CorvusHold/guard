# Guard Stack Helm Chart

Production-ready Helm chart for deploying Corvus Guard - a multi-tenant Central Authentication Service (CAS).

## Features

- **API Server**: Go-based authentication API with JWT, MFA, SSO support
- **Admin UI**: React-based administration interface
- **CloudNative-PG**: Recommended PostgreSQL operator for production (or external database)
- **Valkey**: Redis-compatible cache for sessions and rate-limiting
- **Automatic TLS**: cert-manager integration for automatic certificate management
- **Horizontal Pod Autoscaling**: Scale based on CPU/memory utilization
- **Pod Disruption Budgets**: Ensure high availability during updates
- **Network Policies**: Secure pod-to-pod communication
- **Prometheus Monitoring**: ServiceMonitor and alerting rules

## Prerequisites

- Kubernetes 1.25+
- Helm 3.10+
- PV provisioner support (for Valkey persistence)
- [CloudNative-PG operator](https://cloudnative-pg.io) (recommended for PostgreSQL)
- cert-manager (optional, for automatic TLS)
- nginx-ingress or similar ingress controller

## Quick Start

### Add the Helm repository (if published)

```bash
helm repo add corvushold https://charts.corvushold.com
helm repo update
```

### Install CloudNative-PG operator (recommended)

```bash
# Install CNPG operator
kubectl apply -f https://github.com/cloudnative-pg/cloudnative-pg/releases/latest/download/cnpg-1.25.0.yaml

# Wait for operator to be ready
kubectl wait --for=condition=Available deployment/cnpg-controller-manager -n cnpg-system --timeout=60s
```

### Install from local chart

```bash
# Update dependencies
cd ops/guard-stack
helm dependency update

# Install with CNPG enabled (recommended)
helm install guard . -n guard --create-namespace \
  --set cnpg.enabled=true \
  --set secrets.jwtSigningKey=$(openssl rand -base64 32) \
  --set secrets.databasePassword=$(openssl rand -base64 16) \
  --set secrets.valkeyPassword=$(openssl rand -base64 16)

# Or install with external database
helm install guard . -n guard --create-namespace \
  --set database.host=your-postgres-host \
  --set secrets.jwtSigningKey=$(openssl rand -base64 32) \
  --set secrets.databasePassword=your-db-password \
  --set secrets.valkeyPassword=$(openssl rand -base64 16)
```

## Configuration

### Global Settings

| Parameter | Description | Default |
|-----------|-------------|---------|
| `global.environment` | Environment name | `production` |
| `global.domain` | Domain for the Guard stack | `guard.example.com` |
| `global.tls.enabled` | Enable TLS | `true` |
| `global.tls.certManager` | Use cert-manager | `true` |

### API Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `api.enabled` | Enable API deployment | `true` |
| `api.replicaCount` | Number of API replicas | `2` |
| `api.image.repository` | API image repository | `ghcr.io/corvushold/guard` |
| `api.image.tag` | API image tag | `Chart.AppVersion` |
| `api.resources.requests.cpu` | CPU request | `100m` |
| `api.resources.requests.memory` | Memory request | `128Mi` |
| `api.autoscaling.enabled` | Enable HPA | `true` |
| `api.autoscaling.minReplicas` | Minimum replicas | `2` |
| `api.autoscaling.maxReplicas` | Maximum replicas | `10` |

### UI Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `ui.enabled` | Enable UI deployment | `true` |
| `ui.replicaCount` | Number of UI replicas | `2` |
| `ui.image.repository` | UI image repository | `ghcr.io/corvushold/guard-ui` |
| `ui.config.apiBaseUrl` | API base URL for UI | `/api` |

### Application Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `config.appEnv` | Application environment | `production` |
| `config.publicBaseUrl` | Public URL for callbacks | `https://guard.example.com` |
| `config.forceHttps` | Force HTTPS redirects | `true` |
| `config.corsAllowedOrigins` | CORS origins | `https://guard.example.com` |
| `config.defaultAuthMode` | Auth mode (bearer/cookie) | `bearer` |
| `config.jwt.accessTokenTtl` | Access token TTL | `15m` |
| `config.jwt.refreshTokenTtl` | Refresh token TTL | `720h` |

### Secrets

| Parameter | Description | Default |
|-----------|-------------|---------|
| `secrets.create` | Create secrets from values | `true` |
| `secrets.existingSecret` | Use existing secret | `""` |
| `secrets.jwtSigningKey` | JWT signing key (required) | `""` |
| `secrets.databasePassword` | Database password | `""` |
| `secrets.valkeyPassword` | Valkey password | `""` |

### Database Configuration (CloudNative-PG)

| Parameter | Description | Default |
|-----------|-------------|---------|
| `database.host` | External database host | `""` |
| `database.port` | Database port | `5432` |
| `database.name` | Database name | `guard` |
| `database.user` | Database user | `guard` |
| `database.sslMode` | SSL mode | `require` |
| `cnpg.enabled` | Create CNPG Cluster | `false` |
| `cnpg.instances` | Number of PostgreSQL instances | `3` |
| `cnpg.storage.size` | PVC size per instance | `10Gi` |

### Valkey Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `valkey.enabled` | Enable bundled Valkey | `true` |
| `valkey.master.persistence.size` | PVC size | `2Gi` |
| `externalValkey.addr` | External Valkey/Redis address | `""` |
| `externalValkey.db` | Database number | `0` |

## Production Deployment

For production deployments, we recommend:

1. **Use CloudNative-PG for PostgreSQL**: Install the operator and enable `cnpg.enabled=true`, or use a managed service (RDS, Cloud SQL).

2. **Configure proper secrets management**: Use External Secrets Operator, Sealed Secrets, or Vault.

3. **Enable monitoring**: Set `monitoring.serviceMonitor.enabled=true` and `monitoring.prometheusRule.enabled=true`.

4. **Configure network policies**: Set `networkPolicy.enabled=true`.

5. **Use proper resource limits**: Adjust based on your load testing results.

6. **Enable CNPG backups**: Configure S3 backups for disaster recovery.

See `values-production.yaml` for a complete production configuration example.

## Upgrading

```bash
# Update dependencies
helm dependency update

# Upgrade release
helm upgrade guard . -n guard -f your-values.yaml
```

## Uninstalling

```bash
helm uninstall guard -n guard
```

**Note**: This will not delete PVCs. To fully clean up:

```bash
kubectl delete pvc -n guard -l app.kubernetes.io/instance=guard
```

## Troubleshooting

### Check pod status

```bash
kubectl get pods -n guard -l app.kubernetes.io/instance=guard
```

### View API logs

```bash
kubectl logs -f deploy/guard-guard-stack-api -n guard
```

### Check database connectivity

```bash
kubectl exec -it deploy/guard-guard-stack-api -n guard -- wget -qO- http://localhost:8080/healthz
```

### Run migrations manually

```bash
kubectl create job --from=job/guard-guard-stack-migration migration-manual -n guard
```

## License

Functional Source License (FSL-1.1-ALv2) - see [LICENSE](../../LICENSE.md) for details.
