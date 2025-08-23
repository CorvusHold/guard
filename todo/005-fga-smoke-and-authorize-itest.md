# FGA Smoke Flag + Authorize Integration Test

## Checklist
- [x] Add SMOKE_WRITE_ENV flag to `scripts/fga_smoke.sh` (default: disabled).
  - [x] Read-only path `/v1/auth/authorize` with `subject_type:"self"` and no writes.
  - [x] Full flow when enabled (`SMOKE_WRITE_ENV=1|true|yes`): ensure group, add member, create ACL tuple, allow-check, optional delete, deny-check.
- [x] Add integration test `TestHTTP_Authorize_AllowAndDeny` in `internal/auth/controller/http_integration_test.go`.
  - [x] Signup user via HTTP, introspect token to get `user_id`.
  - [x] Service-layer setup: create group, add membership, create ACL tuple (`settings:read` on `tenant`).
  - [x] Verify `/v1/auth/authorize` returns `allowed=true` for `settings:read` and `allowed=false` for `settings:write`.
- [x] Confirm canonical permissions exist in `migrations/000004_seed_permissions.sql` (`settings:read`, `settings:write`, ...).

## Follow-ups
- [ ] Docs: Document SMOKE_WRITE_ENV with examples; note read-only default and `KEEP_TUPLE` behavior.
- [ ] Docs: Add a short "FGA Quickstart" section in `README.md` referencing smoke scripts.
- [ ] Tests: Add cleanup in the integration test (delete ACL tuple/group) if test DB is long-lived.
- [ ] Tests: Additional authorize cases
  - [ ] Object-scoped checks with `object_id`.
  - [ ] `subject_type:"user"` direct ACL path (in addition to group).
  - [ ] Negative inputs (missing `tenant_id`, invalid `subject_type`).
- [ ] CI: Run the new integration test in CI; provide `DATABASE_URL` (or docker-compose DB service).
- [ ] Scripts: Mirror `SMOKE_WRITE_ENV` behavior in `scripts/fga_nonadmin_check.sh` for parity.

## How to run
- Read-only smoke (no writes):
  ```bash
  ./scripts/fga_smoke.sh
  ```
- Full smoke with writes:
  ```bash
  SMOKE_WRITE_ENV=1 ./scripts/fga_smoke.sh
  # or
  SMOKE_WRITE_ENV=true KEEP_TUPLE=1 ./scripts/fga_smoke.sh
  ```
- Run the new integration test (requires DATABASE_URL):
  ```bash
  DATABASE_URL=postgres://user:pass@localhost:5432/db go test ./internal/auth/controller -run Authorize -v
  ```
