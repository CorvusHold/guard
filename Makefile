SHELL := /bin/bash

# Note: commands that require env vars will source .env inline

.PHONY: compose-up compose-down compose-up-test compose-down-test dev \
        migrate-up migrate-down migrate-status migrate-up-test migrate-down-test \
        sqlc test test-e2e lint db-check redis-ping db-test-check redis-test-ping \
        swagger

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

# Database migrations (requires: goose)
migrate-up:
	bash -lc 'set -a; [ -f .env ] && source .env; set +a; goose -dir ./migrations postgres "$$DATABASE_URL" up'

migrate-down:
	bash -lc 'set -a; [ -f .env ] && source .env; set +a; goose -dir ./migrations postgres "$$DATABASE_URL" down'

migrate-status:
	bash -lc 'set -a; [ -f .env ] && source .env; set +a; goose -dir ./migrations postgres "$$DATABASE_URL" status'

migrate-up-test:
	bash -lc 'set -a; if [ -f .env.test ]; then source .env.test; else source .env.test.example; fi; set +a; goose -dir ./migrations postgres "$$DATABASE_URL" up'

migrate-down-test:
	bash -lc 'set -a; if [ -f .env.test ]; then source .env.test; else source .env.test.example; fi; set +a; goose -dir ./migrations postgres "$$DATABASE_URL" down'

# sqlc codegen (requires: sqlc)
sqlc:
	bash -lc 'sqlc generate'

# Tests and linting
test:
	go test ./...

# Run tests with dedicated TEST env (.env.test or example) for E2E/integration
test-e2e: compose-up-test db-wait-test redis-test-ping migrate-up-test
	bash -lc 'set -a; if [ -f .env.test ]; then source .env.test; else source .env.test.example; fi; set +a; gotestsum --format standard-verbose -- ./...'
	make compose-down-test

lint:
	go vet ./...

# Generate Swagger docs (requires: swag CLI)
swagger:
	# Install swag if missing: go install github.com/swaggo/swag/cmd/swag@latest
	bash -lc 'swag init -g cmd/api/main.go -o docs'

# Quick checks for local services
db-check:
	bash -lc 'set -a; [ -f .env ] && source .env; set +a; pg_isready -d "$$DATABASE_URL" || true'

redis-ping:
	valkey-cli -p 6380 ping || true

db-test-check:
	bash -lc 'set -a; if [ -f .env.test ]; then source .env.test; else source .env.test.example; fi; set +a; pg_isready -d "$$DATABASE_URL" || true'

db-wait-test:
	bash -lc 'set -a; if [ -f .env.test ]; then source .env.test; else source .env.test.example; fi; set +a; for i in {1..60}; do pg_isready -d "$$DATABASE_URL" >/dev/null 2>&1 && echo "Postgres is ready" && exit 0; echo "Waiting for Postgres... ($$i)"; sleep 1; done; echo "Postgres not ready after timeout" >&2; exit 1'

redis-test-ping:
	valkey-cli -p 6481 ping || true
