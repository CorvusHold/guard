# Guard CAS

[![CI](https://github.com/corvusHold/guard/actions/workflows/ci.yml/badge.svg)](https://github.com/corvusHold/guard/actions/workflows/ci.yml)

Central Authentication Service (multi-tenant). See `PROJECT.md` for architecture and API spec.

## Prerequisites
- Go (>= 1.21)
- Docker + Docker Compose
- CLI tools (install once):
  - Air (live reload): `go install github.com/air-verse/air@latest`
  - Goose (migrations): `go install github.com/pressly/goose/v3/cmd/goose@latest`
  - sqlc (codegen): `go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest`

## Run local services
```bash
make compose-up
```
- Postgres: `localhost:5433` (user/pass/db: guard/guard/guard)
- Valkey (Redis): `localhost:6380`

## Configure
```bash
cp .env.example .env
# then edit .env as needed
```

## Development
```bash
make dev
```
This builds and runs `./cmd/api` with live reload via `air`.

## Database migrations
```bash
make migrate-up     # apply
make migrate-down   # rollback latest
make migrate-status # list
```

## sqlc
```bash
make sqlc
```

## Tests
```bash
make test
```

## Notes
- `.env` is gitignored; use `.env.example` for defaults.
- Postgres and Valkey are defined in `docker-compose.yml`.
- Implementation starts with Step 01/02 in `TODO.md`.

## MFA Challenge Flow (Password Login)

When a user has MFA enabled, `POST /v1/auth/password/login` returns a 202 with a short-lived challenge token instead of tokens.

Example login request:

```bash
curl -s -X POST \
  -H 'Content-Type: application/json' \
  http://localhost:8080/v1/auth/password/login \
  -d '{
    "tenant_id": "<TENANT_UUID>",
    "email": "user@example.com",
    "password": "Password!123"
  }'
```

Possible responses:

- 200 OK (no MFA):

```json
{
  "access_token": "...",
  "refresh_token": "..."
}
```

- 202 Accepted (MFA required):

```json
{
  "challenge_token": "<short-lived-jwt>",
  "methods": ["totp", "backup_code"]
}
```

Then verify the challenge with `POST /v1/auth/mfa/verify` using either TOTP or a backup code.

TOTP verification:

```bash
curl -s -X POST \
  -H 'Content-Type: application/json' \
  http://localhost:8080/v1/auth/mfa/verify \
  -d '{
    "challenge_token": "<challenge-from-login>",
    "method": "totp",
    "code": "123456"
  }'
```

Backup code verification:

```bash
curl -s -X POST \
  -H 'Content-Type: application/json' \
  http://localhost:8080/v1/auth/mfa/verify \
  -d '{
    "challenge_token": "<challenge-from-login>",
    "method": "backup_code",
    "code": "BACKUP-CODE-HERE"
  }'
```

Successful verification returns tokens:

```json
{
  "access_token": "...",
  "refresh_token": "..."
}
```

Notes:

- Challenge tokens are short-lived and signed per-tenant.
- Backup codes are single-use and will be consumed on successful verification.
- Swagger UI: http://localhost:8080/swagger/index.html
