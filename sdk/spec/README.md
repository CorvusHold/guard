# SDK Spec Usage

Source of truth: the server-side OpenAPI files in `docs/`.

- JSON: `docs/swagger.json`
- YAML: `docs/swagger.yaml`

Do not copy large spec files into this folder. Consumers should reference `../../docs/swagger.json` directly for code generation. CI will validate that generated client types are up-to-date with that file.

Examples (non-binding, for reference):

TypeScript (types only):
```bash
# openapi-typescript must be installed in the SDK package
openapi-typescript ../../docs/swagger.json -o src/generated/types.ts
```

Go (types/models only):
```bash
# using oapi-codegen: https://github.com/deepmap/oapi-codegen
# generate types (a package name will be selected by the Go SDK)
oapi-codegen -generate types -package apitypes ../../docs/swagger.yaml > internal/apitypes/types.gen.go
```

Rust (types only):
```bash
# using openapi-generator-cli with rust clients
openapi-generator-cli generate -i ../../docs/swagger.yaml -g rust -o generated
```

Validation in CI:
- Regenerate DTOs from `docs/swagger.json`.
- Fail if any diff is detected against committed generated files.
