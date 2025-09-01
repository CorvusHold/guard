SHELL := /bin/bash
export RATE_LIMIT_RETRIES ?= 2

# Note: commands that require env vars will source .env inline

.PHONY: compose-up compose-down compose-up-test compose-down-test dev \
        migrate-up migrate-down migrate-status migrate-up-test migrate-down-test \
        sqlc test test-e2e lint db-check redis-ping db-test-check redis-test-ping \
        swagger obsv-up obsv-down seed-test k6-smoke k6-login-stress k6-rate-limit-login k6-mfa-invalid \
        k6-portal-link-smoke k6-rate-limit-portal-link \
        grafana-url prometheus-url alertmanager-url mailhog-url \
        api-test-wait conformance-up conformance conformance-down \
        migrate-up-test-dc examples-up examples-down examples-wait examples-seed examples-url \
        test-rbac-admin test-fga

compose-up:
	docker compose up -d --remove-orphans

compose-down:
	docker compose down

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
test-e2e: compose-up-test db-wait-test migrate-up-test-dc
	bash -lc 'set -a; if [ -f .env.test ]; then source .env.test; else source .env.test.example; fi; set +a; go test ./...'
	make compose-down-test

# Run only the RBAC admin controller tests against the dockerized test stack
test-rbac-admin: compose-up-test db-wait-test migrate-up-test-dc
	bash -lc 'set -a; if [ -f .env.test ]; then source .env.test; else source .env.test.example; fi; set +a; go test -v ./internal/auth/controller -run HTTP_RBAC_Admin'
	make compose-down-test

# Run only FGA authorization integration tests against the dockerized test stack
test-fga: compose-up-test db-wait-test migrate-up-test-dc
	bash -lc 'set -a; if [ -f .env.test ]; then source .env.test; else source .env.test.example; fi; set +a; go test -v ./internal/auth/controller -run ^TestHTTP_Authorize_'
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
	# Run migrations and seed default tenant/user (with MFA), then wait for API and run SDK conformance
	make migrate-up-test-dc
	docker compose -f docker-compose.test.yml exec -T api_test \
	  sh -lc 'export PATH=/usr/local/go/bin:/go/bin:$$PATH; go run ./cmd/seed default --enable-mfa' | tee .env.conformance
	# Seed a separate non-MFA tenant and user to avoid tenant-scoped login rate limits
	bash -lc 'set -e; set -a; [ -f .env.conformance ] && source .env.conformance; set +a; \
	  NONMFA_TENANT_NAME=$${NONMFA_TENANT_NAME:-test-nomfa}; \
	  NONMFA_EMAIL=$${NONMFA_EMAIL:-nomfa@example.com}; \
	  NONMFA_PASSWORD=$${NONMFA_PASSWORD:-Password123!}; \
	  TEN2=$$(docker compose -f docker-compose.test.yml exec -T api_test sh -lc \
	    "export PATH=/usr/local/go/bin:/go/bin:$$PATH; go run ./cmd/seed tenant --name \"$$NONMFA_TENANT_NAME\"" | grep ^TENANT_ID= | cut -d= -f2); \
	  docker compose -f docker-compose.test.yml exec -T api_test sh -lc \
	    "export PATH=/usr/local/go/bin:/go/bin:$$PATH; go run ./cmd/seed user --tenant-id \"$$TEN2\" --email \"$$NONMFA_EMAIL\" --password \"$$NONMFA_PASSWORD\"" >/dev/null; \
	  { echo "NONMFA_TENANT_ID=$$TEN2"; echo "NONMFA_EMAIL=$$NONMFA_EMAIL"; echo "NONMFA_PASSWORD=$$NONMFA_PASSWORD"; } >> .env.conformance'
	# Seed a second isolated non-MFA tenant/user for rate-limit tests (scenario 011)
	bash -lc 'set -e; set -a; [ -f .env.conformance ] && source .env.conformance; set +a; \
	  NONMFA2_TENANT_NAME=$${NONMFA2_TENANT_NAME:-test-nomfa-2}; \
	  NONMFA2_EMAIL=$${NONMFA2_EMAIL:-nomfa2@example.com}; \
	  NONMFA2_PASSWORD=$${NONMFA2_PASSWORD:-Password123!}; \
	  TEN3=$$(docker compose -f docker-compose.test.yml exec -T api_test sh -lc \
	    "export PATH=/usr/local/go/bin:/go/bin:$$PATH; go run ./cmd/seed tenant --name \"$$NONMFA2_TENANT_NAME\"" | grep ^TENANT_ID= | cut -d= -f2); \
	  docker compose -f docker-compose.test.yml exec -T api_test sh -lc \
	    "export PATH=/usr/local/go/bin:/go/bin:$$PATH; go run ./cmd/seed user --tenant-id \"$$TEN3\" --email \"$$NONMFA2_EMAIL\" --password \"$$NONMFA2_PASSWORD\"" >/dev/null; \
	  { echo "NONMFA2_TENANT_ID=$$TEN3"; echo "NONMFA2_EMAIL=$$NONMFA2_EMAIL"; echo "NONMFA2_PASSWORD=$$NONMFA2_PASSWORD"; } >> .env.conformance'
	make api-test-wait
	# Reset Redis to avoid cross-run rate-limit pollution
	docker compose -f docker-compose.test.yml exec -T valkey_test valkey-cli FLUSHALL >/dev/null || true
	bash -lc 'set -a; [ -f .env.conformance ] && source .env.conformance; set +a; \
	docker compose -f docker-compose.test.yml run --rm \
	  -e BASE_URL=http://api_test:8080 \
	  -e TENANT_ID="$$TENANT_ID" -e EMAIL="$$EMAIL" -e PASSWORD="$$PASSWORD" \
	  -e NONMFA_TENANT_ID="$$NONMFA_TENANT_ID" -e NONMFA_EMAIL="$$NONMFA_EMAIL" -e NONMFA_PASSWORD="$$NONMFA_PASSWORD" \
	  -e NONMFA2_TENANT_ID="$$NONMFA2_TENANT_ID" -e NONMFA2_EMAIL="$$NONMFA2_EMAIL" -e NONMFA2_PASSWORD="$$NONMFA2_PASSWORD" \
	  -e TOTP_SECRET="$$TOTP_SECRET" -e AUTO_MAGIC_TOKEN="$${AUTO_MAGIC_TOKEN:-true}" \
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
	docker compose exec -T db pg_isready -U guard || true

redis-ping:
	docker compose exec -T valkey valkey-cli ping || true

db-test-check:
	docker compose -f docker-compose.test.yml exec -T db_test pg_isready -U guard || true

db-wait-test:
	bash -lc 'for i in {1..60}; do docker compose -f docker-compose.test.yml exec -T db_test pg_isready -U guard >/dev/null 2>&1 && echo "Postgres is ready" && exit 0; echo "Waiting for Postgres... ($$i)"; sleep 1; done; echo "Postgres not ready after timeout" >&2; exit 1'

redis-test-ping:
	docker compose -f docker-compose.test.yml exec -T valkey_test valkey-cli ping || true

# ---- Observability stack helpers ----

obsv-up:
	docker compose up -d --remove-orphans db valkey api prometheus grafana alertmanager am-receiver

obsv-down:
	docker compose down -v

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
	docker compose up -d --remove-orphans db valkey mailhog examples_setup api_examples

# Wait until the examples API is ready
examples-wait:
	bash -lc 'for i in {1..60}; do curl -fsS http://localhost:8081/readyz >/dev/null 2>&1 && echo "API (examples) is ready" && exit 0; echo "Waiting for API (examples)... ($$i)"; sleep 1; done; echo "API (examples) not ready after timeout" >&2; exit 1'

# Re-run seeding/migrations for examples (idempotent). Also updates examples/nextjs/.env.local
examples-seed:
	docker compose run --rm examples_setup

# Tear down the examples stack
examples-down:
	docker compose down -v

# Quick URLs
examples-url:
	@echo "Examples API: http://localhost:8081"
	@echo "MailHog: http://localhost:8025"

# ---- k6 scenarios (via compose service 'k6') ----

k6-smoke:
	bash -lc 'set -a; [ -f .env.k6 ] && source .env.k6; set +a; docker compose run --rm -e K6_BASE_URL=http://api:8080 k6 "k6 run /scripts/smoke.js"'

k6-login-stress:
	bash -lc 'set -a; [ -f .env.k6 ] && source .env.k6; set +a; docker compose run --rm \
		-e K6_BASE_URL=http://api:8080 \
		-e K6_TENANT_ID="$$K6_TENANT_ID" -e K6_EMAIL="$$K6_EMAIL" -e K6_PASSWORD="$$K6_PASSWORD" \
		k6 "k6 run /scripts/login_stress.js"'

k6-rate-limit-login:
	bash -lc 'set -a; [ -f .env.k6 ] && source .env.k6; : $${K6_ITERATIONS:=300}; set +a; docker compose run --rm \
		-e K6_BASE_URL=http://api:8080 \
		-e K6_TENANT_ID="$$K6_TENANT_ID" -e K6_EMAIL="$$K6_EMAIL" -e K6_PASSWORD="$$K6_PASSWORD" \
		-e K6_ITERATIONS="$$K6_ITERATIONS" \
		k6 "k6 run /scripts/rate_limit_login.js"'

k6-mfa-invalid:
	bash -lc 'set -a; [ -f .env.k6 ] && source .env.k6; set +a; docker compose run --rm -e K6_BASE_URL=http://api:8080 k6 "k6 run /scripts/mfa_verify_invalid.js"'

k6-portal-link-smoke:
	bash -lc 'set -a; [ -f .env.k6 ] && source .env.k6; set +a; docker compose run --rm \
		-e K6_BASE_URL=http://api:8080 \
		-e K6_TENANT_ID="$$K6_TENANT_ID" -e K6_ORG_ID="$$K6_ORG_ID" -e K6_ADMIN_TOKEN="$$K6_ADMIN_TOKEN" \
		-e K6_INTENT="$${K6_INTENT:-sso}" \
		k6 "k6 run /scripts/portal_link_smoke.js"'

k6-rate-limit-portal-link:
	bash -lc 'set -a; [ -f .env.k6 ] && source .env.k6; : $${K6_ITERATIONS:=300}; set +a; docker compose run --rm \
		-e K6_BASE_URL=http://api:8080 \
		-e K6_TENANT_ID="$$K6_TENANT_ID" -e K6_ORG_ID="$$K6_ORG_ID" -e K6_ADMIN_TOKEN="$$K6_ADMIN_TOKEN" \
		-e K6_INTENT="$${K6_INTENT:-sso}" -e K6_ITERATIONS="$$K6_ITERATIONS" \
		k6 "k6 run /scripts/rate_limit_portal_link.js"'

# ---- Seeding helpers ----

# Seed default tenant/user and write credentials into .env.k6
# Variables you can override: TENANT_NAME, EMAIL, PASSWORD, ENABLE_MFA=1
seed-test:
	bash -lc 'set -a; [ -f .env ] && source .env; set +a; \
	go run ./cmd/seed default --tenant-name "$$TENANT_NAME" --email "$$EMAIL" --password "$$PASSWORD" | tee .env.k6 >/dev/null; \
	echo "Wrote k6 env to .env.k6"'
