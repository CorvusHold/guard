# Agent Guide: Contributing to Corvus Guard

This guide provides conventions and procedures for AI agents contributing code and tests to the Corvus Guard repository.

## OpenAPI / Swagger Workflow

**IMPORTANT**: OpenAPI spec files are auto-generated. Do NOT edit them directly.

### Generated Files (Do NOT Edit Manually)
- `docs/docs.go` - Generated Go file
- `docs/swagger.json` - Generated JSON spec
- `docs/swagger.yaml` - Generated YAML spec
- `sdk/spec/openapi.json` - Copied from docs/swagger.json
- `sdk/spec/openapi.yaml` - Copied from docs/swagger.yaml
- `sdk/spec/openapi.v3.yaml` - Converted from swagger.json to OpenAPI 3.0

### How to Update OpenAPI Specs

1. **Edit the Go source code** with swag annotations in the relevant controller/types files
2. **Run `make swagger`** to regenerate all spec files
3. The Makefile will:
   - Run `swag init` to generate docs/
   - Copy specs to sdk/spec/
   - Convert to OpenAPI 3.0 for the Go SDK

### Swag Annotation Examples

#### Adding Enum to a Field
```go
type updateProviderRequest struct {
    // Use `enums` tag and trailing comment for description
    LinkingPolicy *string `json:"linking_policy,omitempty" enums:"never,verified_email,always"` // Policy for linking SSO identities
}
```

#### Endpoint Documentation
```go
// @Summary      Update SSO provider
// @Description  Updates an existing SSO provider configuration
// @Tags         SSO
// @Accept       json
// @Produce      json
// @Param        id    path   string                  true  "Provider ID (UUID)"
// @Param        body  body   updateProviderRequest   true  "Updated provider configuration"
// @Success      200   {object}  map[string]interface{}
// @Failure      400   {object}  map[string]string
// @Router       /api/v1/auth/sso/providers/{id} [put]
func (h *Handler) updateProvider(c echo.Context) error {
```

### Key Locations for Swagger Annotations
- **SSO Controller**: `internal/auth/sso/controller/http.go`, `types.go`
- **Auth Controller**: `internal/auth/controller/http.go`
- **Settings Controller**: `internal/settings/controller/http.go`
- **Tenants Controller**: `internal/tenants/controller/http.go`

## Project Layout (Key Paths)

- Backend controllers and tests: `internal/auth/controller/`
- Backend services: `internal/**`
- UI (React + Vite + TS): `ui/`
- TS SDK: `sdk/ts/`
- Go SDK: `sdk/go/`
- Docs: `docs/`

## Test Protocol

See `docs/TEST_PROTOCOL.md` for the canonical testing procedure. Highlights:

- Backend unit tests: `go test ./...`
- UI E2E (Playwright): `cd ui && pnpm run test:e2e`
- UI lint/typecheck: `cd ui && pnpm run lint && pnpm run typecheck`
- Go integration tests (dockerized): `make test-integration`

## Backend Testing Conventions

- Keep default `go test ./...` green and fast
- Place long-running or external dependency tests under `//go:build integration`
- Use `Makefile` helpers for integration runs: `make test-integration`
- Handle `config.Load()` errors properly in tests (use `require.NoError`)

## UI Testing Conventions

- Use `data-testid` attributes for all interactable or asserted elements
- For network dependencies, mock with `page.route`
- Avoid Playwright strict mode ambiguity by selecting via unique test ids

## Commit and PR Guidance

- Describe the change succinctly: what was changed, why
- Ensure `go test ./...`, `pnpm run lint`, `pnpm run typecheck`, and `pnpm run test:e2e` pass locally before submitting
- Run `make swagger` after modifying any swag annotations

## Security & Secrets

- Do not hardcode real API keys
- For SSO/Email integrations, use mocks or test fixtures
