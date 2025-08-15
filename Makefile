SHELL := /bin/bash

# Note: commands that require env vars will source .env inline

.PHONY: compose-up compose-down compose-up-test compose-down-test dev \
        migrate-up migrate-down migrate-status migrate-up-test migrate-down-test \
        sqlc test test-e2e lint db-check redis-ping db-test-check redis-test-ping \
        swagger obsv-up obsv-down seed-test k6-smoke k6-login-stress k6-rate-limit-login k6-mfa-invalid \
        grafana-url prometheus-url alertmanager-url mailhog-url \
        api-test-wait conformance-up conformance conformance-down \
        migrate-up-test-dc

compose-up:
	docker compose up -d

compose-down:
	docker compose down

# Test stack (dedicated Postgres/Redis for integration/E2E)
compose-up-test:
	docker compose -f docker-compose.test.yml up -d

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
test-e2e: compose-up-test db-wait-test redis-test-ping migrate-up-test-dc
	bash -lc 'set -a; if [ -f .env.test ]; then source .env.test; else source .env.test.example; fi; set +a; go test ./...'
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
	docker compose -f docker-compose.test.yml up -d

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
	make api-test-wait
	bash -lc 'set -a; [ -f .env.conformance ] && source .env.conformance; set +a; \
	docker compose -f docker-compose.test.yml run --rm \
	  -e BASE_URL=http://api_test:8080 \
	  -e TENANT_ID="$$TENANT_ID" -e EMAIL="$$EMAIL" -e PASSWORD="$$PASSWORD" \
	  -e NONMFA_TENANT_ID="$$NONMFA_TENANT_ID" -e NONMFA_EMAIL="$$NONMFA_EMAIL" -e NONMFA_PASSWORD="$$NONMFA_PASSWORD" \
	  -e TOTP_SECRET="$$TOTP_SECRET" -e AUTO_MAGIC_TOKEN="$${AUTO_MAGIC_TOKEN:-true}" \
	  -e SCENARIO="$${SCENARIO:-}" -e SCENARIO_FILTER="$${SCENARIO_FILTER:-}" \
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
	docker compose up -d db valkey api prometheus grafana alertmanager am-receiver

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

# ---- Seeding helpers ----

# Seed default tenant/user and write credentials into .env.k6
# Variables you can override: TENANT_NAME, EMAIL, PASSWORD, ENABLE_MFA=1
seed-test:
	bash -lc 'set -a; [ -f .env ] && source .env; set +a; \
	go run ./cmd/seed default --tenant-name "$$TENANT_NAME" --email "$$EMAIL" --password "$$PASSWORD" | tee .env.k6 >/dev/null; \
	echo "Wrote k6 env to .env.k6"'
