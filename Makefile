SHELL := /bin/bash
export RATE_LIMIT_RETRIES ?= 2

# Note: commands that require env vars will source .env inline

.PHONY: compose-up compose-down compose-up-test compose-down-test dev \
        migrate-up migrate-down migrate-status migrate-up-test migrate-down-test \
        sqlc test test-e2e lint db-check redis-ping db-test-check redis-test-ping \
        swagger obsv-up obsv-down seed-test k6-setup k6-all k6-smoke k6-login-stress k6-rate-limit-login k6-mfa-invalid \
        k6-portal-link-smoke k6-rate-limit-portal-link \
        grafana-url prometheus-url alertmanager-url mailhog-url \
        api-test-wait conformance-up conformance conformance-down \
        migrate-up-test-dc examples-up examples-down examples-wait examples-seed examples-url \
        test-rbac-admin test-fga test-integration test-fga-smoke test-fga-nonadmin-check \
        portal-e2e-setup portal-e2e portal-e2e-suite-no-down portal-e2e-suite portal-e2e-down

compose-up:
	docker compose -f docker-compose.dev.yml up -d --remove-orphans

compose-down:
	docker compose -f docker-compose.dev.yml down

# Test stack (dedicated Postgres/Redis for integration/E2E)
compose-up-test:
	docker compose -f docker-compose.test.yml up -d --remove-orphans

compose-down-test:
	docker compose -f docker-compose.test.yml down -v

# Live-reload dev server (requires: air)
dev:
	air -c .air.toml

# Database migrations (uses `go run` goose; no host goose binary required)
migrate-up:
	bash -lc 'set -a; [ -f .env ] && source .env; set +a; go run github.com/pressly/goose/v3/cmd/goose@latest -dir ./migrations postgres "$$DATABASE_URL" up'

migrate-down:
	bash -lc 'set -a; [ -f .env ] && source .env; set +a; go run github.com/pressly/goose/v3/cmd/goose@latest -dir ./migrations postgres "$$DATABASE_URL" down'

migrate-status:
	bash -lc 'set -a; [ -f .env ] && source .env; set +a; go run github.com/pressly/goose/v3/cmd/goose@latest -dir ./migrations postgres "$$DATABASE_URL" status'

migrate-up-test:
	bash -lc 'set -a; if [ -f .env.test ]; then source .env.test; else source .env.test.example; fi; set +a; go run github.com/pressly/goose/v3/cmd/goose@latest -dir ./migrations postgres "$$DATABASE_URL" up'

migrate-down-test:
	bash -lc 'set -a; if [ -f .env.test ]; then source .env.test; else source .env.test.example; fi; set +a; go run github.com/pressly/goose/v3/cmd/goose@latest -dir ./migrations postgres "$$DATABASE_URL" down'

# sqlc codegen (requires: sqlc)
sqlc:
	bash -lc 'sqlc generate'

# ---- Tests and linting ----
test:
	go test ./...

# Run E2E/integration tests against test stack. No extra host tools required.
test-e2e: compose-up-test db-wait-test db-purge-test migrate-up-test-dc
	bash -lc 'set -a; if [ -f .env.test ]; then source .env.test; else source .env.test.example; fi; set +a; go test ./...'
	make compose-down-test

# Run only the RBAC admin controller tests against the dockerized test stack
test-rbac-admin: compose-up-test db-wait-test db-purge-test migrate-up-test-dc
	bash -lc 'set -a; if [ -f .env.test ]; then source .env.test; else source .env.test.example; fi; set +a; go test -v ./internal/auth/controller -run HTTP_RBAC_Admin'
	make compose-down-test

# Run only FGA authorization integration tests against the dockerized test stack
test-fga: compose-up-test db-wait-test db-purge-test migrate-up-test-dc
	bash -lc 'set -a; if [ -f .env.test ]; then source .env.test; else source .env.test.example; fi; set +a; go test -v ./internal/auth/controller -run ^TestHTTP_Authorize_'
	make compose-down-test

test-fga-smoke: compose-up-test db-wait-test db-purge-test migrate-up-test-dc
	bash -lc 'set -a; if [ -f .env.test ]; then source .env.test; else source .env.test.example; fi; set +a; SMOKE_WRITE_ENV=1 bash scripts/fga_smoke.sh'
	make compose-down-test

test-fga-nonadmin-check: compose-up-test db-wait-test db-purge-test  migrate-up-test-dc
	bash -lc 'set -a; if [ -f .env.test ]; then source .env.test; else source .env.test.example; fi; set +a; PRE_CLEAN=1 PRE_CLEAN_MEMBERSHIP=1 bash scripts/fga_nonadmin_check.sh'
	make compose-down-test

# Run Go integration tests (build tag 'integration') against dockerized test stack
test-integration: compose-up-test db-wait-test db-purge-test migrate-up-test-dc
	bash -lc 'set -a; if [ -f .env.test ]; then source .env.test; else source .env.test.example; fi; set +a; go test -tags=integration -v ./...'
	make compose-down-test

lint:
	go vet ./...

# ---- Conformance runner (TS SDK) ----

# Wait for API test container to be ready (poll /readyz on host port 8081)
api-test-wait:
	bash -lc 'for i in {1..60}; do curl -fsS http://localhost:8081/readyz >/dev/null 2>&1 && echo "API is ready" && exit 0; echo "Waiting for API... ($$i)"; sleep 1; done; echo "API not ready after timeout" >&2; exit 1'

# Run test DB migrations inside the api_test container (no host goose required)
migrate-up-test-dc:
	docker compose -f docker-compose.test.yml exec -T api_test \
	  sh -lc 'export PATH=/usr/local/go/bin:/go/bin:$$PATH; \
	  go run github.com/pressly/goose/v3/cmd/goose@latest -dir ./migrations postgres "$$DATABASE_URL" up'

# Bring up full test stack (db/redis/mailhog/api)
conformance-up:
	docker compose -f docker-compose.test.yml up -d --remove-orphans

# Run SDK conformance inside container. You can provide TENANT_ID/EMAIL/PASSWORD/TOTP_SECRET envs
# Optionally create a .env.conformance file and they will be sourced automatically.
conformance: conformance-up
	# Run migrations and seed tenants/users via guard-cli (using bootstrap token), then wait for API and run SDK conformance
	make db-purge-test
	make migrate-up-test-dc
	bash -lc 'scripts/seed-conformance.sh'
	make api-test-wait
	# Reset Redis to avoid cross-run rate-limit pollution
	docker compose -f docker-compose.test.yml exec -T valkey_test valkey-cli FLUSHALL >/dev/null || true
	bash -lc 'set -a; [ -f .env.conformance ] && source .env.conformance; set +a; \
	MFA_TENANT_ID=$$(grep -m 1 "^TENANT_ID=" .env.conformance | cut -d= -f2-); \
	MFA_EMAIL=$$(grep -m 1 "^EMAIL=" .env.conformance | cut -d= -f2-); \
	MFA_PASSWORD=$$(grep -m 1 "^PASSWORD=" .env.conformance | cut -d= -f2-); \
	MFA_TOTP_SECRET=$$(grep -m 1 "^TOTP_SECRET=" .env.conformance | cut -d= -f2-); \
	docker compose -f docker-compose.test.yml run --rm \
	  -e BASE_URL=http://api_test:8080 \
	  -e TENANT_ID="$$MFA_TENANT_ID" -e EMAIL="$$MFA_EMAIL" -e PASSWORD="$$MFA_PASSWORD" \
	  -e NONMFA_TENANT_ID="$$NONMFA_TENANT_ID" -e NONMFA_EMAIL="$$NONMFA_EMAIL" -e NONMFA_PASSWORD="$$NONMFA_PASSWORD" \
	  -e NONMFA2_TENANT_ID="$$NONMFA2_TENANT_ID" -e NONMFA2_EMAIL="$$NONMFA2_EMAIL" -e NONMFA2_PASSWORD="$$NONMFA2_PASSWORD" \
	  -e TOTP_SECRET="$$MFA_TOTP_SECRET" -e AUTO_MAGIC_TOKEN="$${AUTO_MAGIC_TOKEN:-true}" \
	  -e SCENARIO="$${SCENARIO:-}" -e SCENARIO_FILTER="$${SCENARIO_FILTER:-}" \
	  -e RATE_LIMIT_RETRIES="$${RATE_LIMIT_RETRIES:-}" \
	  $${SDK_SERVICE:-sdk_conformance}'

# Tear down the test stack (including volumes)
conformance-down:
	docker compose -f docker-compose.test.yml down -v

# Generate Swagger docs (requires: swag CLI)
swagger:
	# Install swag if missing: go install github.com/swaggo/swag/cmd/swag@latest
	bash -lc 'swag init -g cmd/api/main.go -o docs'
	bash -lc 'cp docs/swagger.json sdk/spec/openapi.json'
	bash -lc 'cp docs/swagger.yaml sdk/spec/openapi.yaml'

# Quick checks for local services (dockerized, no host tools required)
db-check:
	docker compose -f docker-compose.dev.yml exec -T db pg_isready -U guard || true

redis-ping:
	docker compose -f docker-compose.dev.yml exec -T valkey valkey-cli ping || true

db-test-check:
	docker compose -f docker-compose.test.yml exec -T db_test pg_isready -U guard || true

db-wait-test:
	bash -lc 'for i in {1..60}; do docker compose -f docker-compose.test.yml exec -T db_test pg_isready -U guard >/dev/null 2>&1 && echo "Postgres is ready" && exit 0; echo "Waiting for Postgres... ($$i)"; sleep 1; done; echo "Postgres not ready after timeout" >&2; exit 1'

# Clean up test DB schema to avoid data pollution between runs
db-purge-test:
	docker compose -f docker-compose.test.yml exec -T db_test psql -U guard -d guard_test -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"

redis-test-ping:
	docker compose -f docker-compose.test.yml exec -T valkey_test valkey-cli ping || true

# ---- Observability stack helpers ----

obsv-up:
	docker compose -f docker-compose.dev.yml --profile monitoring up -d --remove-orphans

obsv-down:
	docker compose -f docker-compose.dev.yml --profile monitoring down -v

grafana-url:
	@echo "Grafana: http://localhost:3000 (admin/admin)"

prometheus-url:
	@echo "Prometheus: http://localhost:9090"

alertmanager-url:
	@echo "Alertmanager: http://localhost:9093"

mailhog-url:
	@echo "MailHog: http://localhost:8025"

# ---- Examples stack helpers ----

# Bring up the examples stack using the classic compose file, with API on :8081 and SMTP via MailHog.
examples-up:
	docker compose -f docker-compose.dev.yml up -d --remove-orphans db valkey mailhog examples_setup api_examples

# Wait until the examples API is ready
examples-wait:
	bash -lc 'for i in {1..60}; do curl -fsS http://localhost:8081/readyz >/dev/null 2>&1 && echo "API (examples) is ready" && exit 0; echo "Waiting for API (examples)... ($$i)"; sleep 1; done; echo "API (examples) not ready after timeout" >&2; exit 1'

# Re-run seeding/migrations for examples (idempotent). Also updates examples/nextjs/.env.local
examples-seed:
	docker compose -f docker-compose.dev.yml run --rm examples_setup

# Tear down the examples stack
examples-down:
	docker compose -f docker-compose.dev.yml down -v

# Quick URLs
examples-url:
	@echo "Examples API: http://localhost:8081"
	@echo "MailHog: http://localhost:8025"

# ---- k6 scenarios (via compose service 'k6') ----

k6-setup: conformance-up
	make db-purge-test
	make migrate-up-test-dc
	bash -lc 'scripts/seed-k6.sh'
	make api-test-wait
	docker compose -f docker-compose.test.yml exec -T valkey_test valkey-cli FLUSHALL >/dev/null || true

k6-all: k6-setup
	make k6-smoke
	make k6-login-stress
	make k6-rate-limit-login
	make k6-mfa-invalid
	make k6-portal-link-smoke
	make k6-rate-limit-portal-link

k6-smoke:
	bash -lc 'set -a; [ -f .env.k6 ] && source .env.k6; set +a; docker compose -f docker-compose.test.yml run --rm -e K6_BASE_URL=http://api_test:8080 k6 "k6 run /scripts/smoke.js"'

k6-login-stress:
	bash -lc 'set -a; [ -f .env.k6 ] && source .env.k6; set +a; docker compose -f docker-compose.test.yml run --rm \
		-e K6_BASE_URL=http://api_test:8080 \
		-e K6_TENANT_ID="$$K6_TENANT_ID" -e K6_EMAIL="$$K6_EMAIL" -e K6_PASSWORD="$$K6_PASSWORD" \
		k6 "k6 run /scripts/login_stress.js"'

k6-rate-limit-login:
	bash -lc 'set -a; [ -f .env.k6 ] && source .env.k6; : $${K6_ITERATIONS:=300}; set +a; docker compose -f docker-compose.test.yml run --rm \
		-e K6_BASE_URL=http://api_test:8080 \
		-e K6_TENANT_ID="$$K6_TENANT_ID" -e K6_EMAIL="$$K6_EMAIL" -e K6_PASSWORD="$$K6_PASSWORD" \
		-e K6_ITERATIONS="$$K6_ITERATIONS" \
		k6 "k6 run /scripts/rate_limit_login.js"'

k6-mfa-invalid:
	bash -lc 'set -a; [ -f .env.k6 ] && source .env.k6; set +a; docker compose -f docker-compose.test.yml run --rm -e K6_BASE_URL=http://api_test:8080 k6 "k6 run /scripts/mfa_verify_invalid.js"'

k6-portal-link-smoke:
	bash -lc 'set -a; [ -f .env.k6 ] && source .env.k6; set +a; docker compose -f docker-compose.test.yml run --rm \
		-e K6_BASE_URL=http://api_test:8080 \
		-e K6_TENANT_ID="$$K6_TENANT_ID" -e K6_ORG_ID="$$K6_ORG_ID" -e K6_ADMIN_TOKEN="$$K6_ADMIN_TOKEN" \
		-e K6_INTENT="$${K6_INTENT:-sso}" \
		k6 "k6 run /scripts/portal_link_smoke.js"'

k6-rate-limit-portal-link:
	bash -lc 'set -a; [ -f .env.k6 ] && source .env.k6; : $${K6_ITERATIONS:=300}; set +a; docker compose -f docker-compose.test.yml run --rm \
		-e K6_BASE_URL=http://api_test:8080 \
		-e K6_TENANT_ID="$$K6_TENANT_ID" -e K6_ORG_ID="$$K6_ORG_ID" -e K6_ADMIN_TOKEN="$$K6_ADMIN_TOKEN" \
		-e K6_INTENT="$${K6_INTENT:-sso}" -e K6_ITERATIONS="$$K6_ITERATIONS" \
		k6 "k6 run /scripts/rate_limit_portal_link.js"'

# ---- Seeding helpers ----

# Seed default tenant/user and write credentials into .env.k6
# Variables you can override: TENANT_NAME, EMAIL, PASSWORD, ENABLE_MFA=1
seed-test:
	bash -lc 'set -a; [ -f .env ] && source .env; set +a; \
	if [ "$${ENABLE_MFA:-}" = "1" ]; then ENABLE_MFA_FLAG="--enable-mfa"; else ENABLE_MFA_FLAG=""; fi; \
	eval "$(scripts/bootstrap-token.sh --prefix k6)"; \
	( cd cmd/guard-cli && GUARD_API_TOKEN="$$GUARD_API_TOKEN" go run . seed default \
		--tenant-name "$$TENANT_NAME" --email "$$EMAIL" --password "$$PASSWORD" \
			$$ENABLE_MFA_FLAG \
			--output env ) | tee .env.k6 >/dev/null; \
		echo "Wrote k6 env to .env.k6"'

# ---- SSO Setup Portal fully wired E2E (Playwright) ----

portal-e2e-setup: conformance-up
	make db-purge-test
	make migrate-up-test-dc
	bash -lc 'scripts/seed-sso-portal-e2e.sh'
	make api-test-wait
	docker compose -f docker-compose.test.yml exec -T valkey_test valkey-cli FLUSHALL >/dev/null || true

portal-e2e: portal-e2e-setup
	bash -lc 'set -a; [ -f .env.sso-portal-e2e ] && source .env.sso-portal-e2e; set +a; cd ui && pnpm run test:e2e -- e2e/sso-portal-integration.spec.ts'
	make portal-e2e-down

portal-e2e-suite-no-down: portal-e2e-setup
	bash -lc 'set -a; [ -f .env.sso-portal-e2e ] && source .env.sso-portal-e2e; set +a; cd ui && pnpm run test:e2e -- e2e/sso-portal.spec.ts e2e/sso-portal-integration.spec.ts'

portal-e2e-suite: portal-e2e-suite-no-down
	make portal-e2e-down

portal-e2e-down:
	docker compose -f docker-compose.test.yml down -v
