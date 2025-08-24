# TypeScript SDK (Reference)

Reference SDK for Guard CAS targeting Node.js, browsers, and React Native.

This SDK uses a spec‑first approach. Core auth flows implemented:

- Password login (MFA challenge aware)
- MFA verify (TOTP / backup)
- Refresh tokens
- Logout (revoke refresh)
- Current user profile (`me`)
- Token introspection
- Magic link: send + verify

Explicit configuration is required for `baseUrl`. The `X-Guard-Client` header is set automatically as `ts-sdk/<package.version>`.

## Install

```bash
npm install @corvushold/guard-sdk
```

## Node (>=18)

```ts
import { GuardClient, InMemoryStorage, isTokensResp, isMfaChallengeResp } from '@corvushold/guard-sdk';

const client = new GuardClient({
  baseUrl: 'https://guard.example.com', // required
  storage: new InMemoryStorage(),
  // fetchImpl: global fetch in Node 18+; inject a polyfill if needed
});

// Password login returns a union: Tokens or MFA Challenge
const login = await client.passwordLogin({ email: 'a@example.com', password: 'pw', tenant_id: 'tenant_123' });
if (login.meta.status === 200 && isTokensResp(login.data)) {
  // access/refresh tokens persisted into storage
} else if (login.meta.status === 202 && isMfaChallengeResp(login.data)) {
  // MFA challenge flow
  const verify = await client.mfaVerify({ challenge_token: login.data.challenge_token, method: 'totp', code: '123456' });
}

// Me (Authorization header auto‑injected from storage)
const me = await client.me();

// Refresh
const refreshed = await client.refresh(); // uses stored refresh token if omitted

// Logout
await client.logout(); // clears stored refresh on 204

// Introspect
const info = await client.introspect();

// Magic link
await client.magicSend({ tenant_id: 'tenant_123', email: 'a@example.com', redirect_url: 'https://app.example.com/callback' });
const verified = await client.magicVerify({ token: 'magic_token_from_email' });
```

## Browser

```ts
import { GuardClient, WebLocalStorage } from '@corvushold/guard-sdk';

const client = new GuardClient({
  baseUrl: 'https://guard.example.com',
  storage: new WebLocalStorage('myapp'), // persists in localStorage
});

// Then same as Node usage above
```

## React Native

```ts
import { GuardClient, reactNativeStorageAdapter } from '@corvushold/guard-sdk';
import AsyncStorage from '@react-native-async-storage/async-storage';

const client = new GuardClient({
  baseUrl: 'https://guard.example.com',
  storage: reactNativeStorageAdapter(AsyncStorage, 'myapp'),
  // fetchImpl: RN provides global fetch; inject custom fetch if desired
});
```

## Errors and rate limits

- Non‑2xx responses throw `ApiError` with fields: `status`, `message`, `code?`, `requestId?`, `headers?`, `raw?`.
- 429 responses throw `RateLimitError` and parse `Retry-After` into `retryAfter` seconds and `nextRetryAt: Date`.

## Notes

- `baseUrl` must be provided explicitly.
- `Authorization: Bearer <access_token>` is injected automatically from the configured storage, when present.
- `X-Guard-Client` is sent as `ts-sdk/<pkg.version>`.
- `passwordLogin()` returns a union of tokens or MFA challenge. Use the exported type guards `isTokensResp()` and `isMfaChallengeResp()` to narrow.
- The SDK uses generated DTOs; see `src/generated/openapi.d.ts` for types.
