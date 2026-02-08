# Guard Mobile SDKs

## Overview

Mobile SDKs for Guard IAM, providing native authentication flows for iOS and Android.

## Planned SDKs

### iOS (Swift)
- PKCE-based OAuth 2.0 flow
- Biometric authentication (Face ID / Touch ID) integration
- Secure token storage via Keychain
- WebAuthn/Passkey support via ASAuthorization

### Android (Kotlin)
- PKCE-based OAuth 2.0 flow
- Biometric authentication (fingerprint / face) integration
- Secure token storage via EncryptedSharedPreferences
- WebAuthn/Passkey support via FIDO2 API

### React Native
- Cross-platform wrapper around native SDKs
- Expo plugin for managed workflow
- Secure storage via react-native-keychain

### Flutter
- Cross-platform Dart SDK
- Platform channel bridges to native auth
- Secure storage via flutter_secure_storage

## Common Features

All mobile SDKs will support:
- Login (email/password, magic link, SSO)
- Token refresh with automatic rotation
- MFA enrollment and verification
- Session management
- API key authentication for service contexts
- Offline token caching with secure storage

## Authentication Flow

```
Mobile App                    Guard API
    │                            │
    ├─── POST /oauth/authorize ──▶│  (PKCE: code_challenge)
    │                            │
    │◀── 302 redirect ──────────┤
    │                            │
    ├─── POST /oauth/token ──────▶│  (code + code_verifier)
    │                            │
    │◀── { access_token, ────────┤
    │      refresh_token }       │
    │                            │
    ├─── GET /api/v1/auth/me ───▶│  (Bearer access_token)
    │                            │
    │◀── { user profile } ───────┤
```

## Status

🚧 **Under Development** — SDK stubs and interfaces are being defined. Contributions welcome.

## Getting Started (Development)

See the conformance test suite in `sdk/conformance/` for expected API behavior that all SDKs must implement.
