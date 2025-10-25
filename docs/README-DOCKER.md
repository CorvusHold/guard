# Guard Docker Environments

This document explains how to use the different Docker Compose configurations for Guard.

## Quick Start

```bash
# Development (default)
docker-compose up

# Or explicitly use development
docker-compose -f docker-compose.dev.yml up

# Production
docker-compose -f docker-compose.prod.yml up -d

# Testing
docker-compose -f docker-compose.test.yml up
```

## Environment Configurations

### Development (`docker-compose.dev.yml`)

**Purpose**: Local development with hot reload and debugging tools.

**Services**:
- PostgreSQL on port 5433
- Valkey (Redis) on port 6380
- Guard API on port 8080 with hot reload
- MailHog for email testing (ports 1025/8025)
- Optional monitoring stack (use `--profile monitoring`)

**Features**:
- Source code mounted for hot reload
- Development-friendly CORS settings
- Debug logging enabled
- MailHog for email testing

```bash
# Start development environment
docker-compose -f docker-compose.dev.yml up

# With monitoring
docker-compose -f docker-compose.dev.yml --profile monitoring up

# View logs
docker-compose -f docker-compose.dev.yml logs -f api
```

### Production (`docker-compose.prod.yml`)

**Purpose**: Production deployment with security and performance optimizations.

**Services**:
- PostgreSQL with persistent storage and backups
- Valkey with production configuration
- Guard API built from Dockerfile
- Monitoring stack (Prometheus, Grafana, AlertManager)
- Optional Nginx reverse proxy (use `--profile proxy`)

**Features**:
- Built images (no source mounting)
- Environment variable validation
- Resource limits and health checks
- Production logging (JSON format)
- SSL/TLS ready

```bash
# Copy and configure environment
cp .env.prod.example .env.prod
# Edit .env.prod with your settings

# Start production environment
docker-compose -f docker-compose.prod.yml up -d

# With reverse proxy
docker-compose -f docker-compose.prod.yml --profile proxy up -d

# View status
docker-compose -f docker-compose.prod.yml ps
```

### Testing (`docker-compose.test.yml`)

**Purpose**: Isolated testing environment for CI/CD and E2E tests.

**Services**:
- PostgreSQL on port 5544 (isolated)
- Valkey on port 6481 (isolated)
- Guard API on port 8081
- MailHog on ports 1026/8026 (different from dev)
- Optional SDK conformance tests (use `--profile conformance`)
- Optional load testing (use `--profile load-test`)

**Features**:
- Isolated from development environment
- Fast startup for CI/CD
- Test-specific configurations
- SDK conformance testing

```bash
# Start test environment
docker-compose -f docker-compose.test.yml up

# Run conformance tests
docker-compose -f docker-compose.test.yml --profile conformance up

# Run load tests
docker-compose -f docker-compose.test.yml --profile load-test up
```

## Environment Variables

### Development
Copy `.env.dev.example` to `.env.dev` and customize:
```bash
cp .env.dev.example .env.dev
```

### Production
Copy `.env.prod.example` to `.env.prod` and customize:
```bash
cp .env.prod.example .env.prod
# IMPORTANT: Change all passwords and secrets!
```

## Port Mappings

| Environment | Service | Host Port | Purpose |
|-------------|---------|-----------|---------|
| Development | PostgreSQL | 5433 | Database |
| Development | Valkey | 6380 | Cache/Sessions |
| Development | API | 8080 | Guard API |
| Development | MailHog SMTP | 1025 | Email testing |
| Development | MailHog UI | 8025 | Email UI |
| Development | Prometheus | 9090 | Metrics |
| Development | Grafana | 3000 | Dashboards |
| Production | PostgreSQL | 5432 | Database |
| Production | API | 8080 | Guard API |
| Testing | PostgreSQL | 5544 | Test database |
| Testing | Valkey | 6481 | Test cache |
| Testing | API | 8081 | Test API |
| Testing | MailHog SMTP | 1026 | Test email |
| Testing | MailHog UI | 8026 | Test email UI |

## Profiles

Use profiles to enable optional services:

```bash
# Development with monitoring
docker-compose -f docker-compose.dev.yml --profile monitoring up

# Production with reverse proxy
docker-compose -f docker-compose.prod.yml --profile proxy up -d

# Testing with conformance tests
docker-compose -f docker-compose.test.yml --profile conformance up

# Testing with load tests
docker-compose -f docker-compose.test.yml --profile load-test up
```

## Common Commands

```bash
# View logs
docker-compose -f docker-compose.dev.yml logs -f api

# Execute commands in containers
docker-compose -f docker-compose.dev.yml exec api go run ./cmd/seed --help

# Stop and remove containers
docker-compose -f docker-compose.dev.yml down

# Stop and remove containers + volumes
docker-compose -f docker-compose.dev.yml down -v

# Rebuild images
docker-compose -f docker-compose.prod.yml build --no-cache

# View container status
docker-compose -f docker-compose.dev.yml ps
```

## Troubleshooting

### Port Conflicts
If you get port conflicts, check what's running:
```bash
lsof -i :8080  # Check if port 8080 is in use
```

### Database Issues
Reset the database:
```bash
docker-compose -f docker-compose.dev.yml down -v
docker-compose -f docker-compose.dev.yml up
```

### Permission Issues
Fix volume permissions:
```bash
sudo chown -R $USER:$USER ./data
```

### View Container Logs
```bash
# All services
docker-compose -f docker-compose.dev.yml logs

# Specific service
docker-compose -f docker-compose.dev.yml logs api

# Follow logs
docker-compose -f docker-compose.dev.yml logs -f api
```

## Security Notes

### Development
- Uses weak passwords (fine for local development)
- Permissive CORS settings
- Debug logging enabled

### Production
- **MUST** change all default passwords
- **MUST** configure proper CORS origins
- **MUST** use HTTPS in production
- **MUST** secure database access
- Consider using Docker secrets for sensitive data

### Testing
- Isolated from other environments
- Uses test-specific configurations
- Safe to reset/recreate frequently
