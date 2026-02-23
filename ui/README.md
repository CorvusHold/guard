## Getting Started

### Install

Install dependencies.

```bash
pnpm install
```

Serve with hot reload at <http://localhost:5173>.

```bash
pnpm run dev
```

### Lint

```bash
pnpm run lint
```

### Typecheck

```bash
pnpm run typecheck
```

### Build

```bash
pnpm run build
```

### Test

```bash
pnpm run test
```

View and interact with your tests via UI.

```bash
pnpm run test:ui
```

## IAM vNext Integration Notes

For frontend teams integrating against the new Guard IAM token model:

- Use tenant-aware discovery for OAuth/OIDC app onboarding:
  - `/.well-known/oauth-authorization-server?tenant_id=<tenant_id>`
  - `/t/<tenant_id>/.well-known/openid-configuration`
- Assume ES256 JWT signatures in external token validators.
- Do not rely on shared JWT signing secrets in frontend or BFF integrations.
- Prefer PKCE and standard browser authorize flows for user-facing apps.

For full migration guidance, see `docs/IAM_VNEXT_MIGRATION.md` and `docs/OAUTH2_PROVIDER_GUIDE.md`.

## License

This project is licensed under the MIT License.
