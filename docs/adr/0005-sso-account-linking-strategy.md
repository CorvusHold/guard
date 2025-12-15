# ADR-0005: SSO Account Linking Strategy

## Status
Accepted

## Date
2025-12-07

## Context

When a user attempts to sign in via SSO (SAML/OIDC) with an email address that already exists in the system (e.g., from a previous password-based signup), the system needs to decide how to handle this situation.

The current behavior fails with a database constraint violation:
```
ERROR: duplicate key value violates unique constraint "auth_identities_tenant_id_email_key"
```

This is a common scenario in enterprise environments where:
1. Users initially sign up with email/password during a trial period
2. Organization later enables SSO for all users
3. Existing users need to transition to SSO without losing their accounts

However, automatically linking accounts poses security risks:
- **Account takeover**: An attacker could create an account on a compromised IdP with a victim's email
- **Email spoofing**: Some IdPs don't verify email ownership
- **Compliance**: Some regulations require explicit user consent for account linking

## Decision

We implement a configurable **Account Linking Policy** per SSO provider with three modes:

### Linking Policies

| Policy | Value | Behavior | Security | Use Case |
|--------|-------|----------|----------|----------|
| **Never** | `never` | Never link to existing accounts. SSO users must be new. | Highest | High-security environments, separate user pools |
| **Verified Email** | `verified_email` | Link only if IdP confirms email is verified AND existing account email is verified | Medium | Default - safe for trusted enterprise IdPs |
| **Always** | `always` | Always link if email matches | Lowest | Internal apps with fully trusted IdPs only |

### Default Behavior

The default policy is `verified_email` because:
1. Most enterprise IdPs (Azure AD, Okta, Google Workspace) verify email ownership
2. It provides a good balance between security and user experience
3. It prevents account takeover from untrusted IdPs while allowing legitimate linking

### Implementation Flow

```
SSO Callback
    │
    ▼
┌─────────────────────────────┐
│ 1. Validate IdP Response    │
│ 2. Extract Profile (email)  │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│ 3. Check SSO Identity       │──── Exists ────► Login User
│    (provider_id + subject)  │
└─────────────┬───────────────┘
              │ Not Found
              ▼
┌─────────────────────────────┐
│ 4. Check User by Email      │──── Not Found ──► Create New User
└─────────────┬───────────────┘                   (if AllowSignup)
              │ Found
              ▼
┌─────────────────────────────┐
│ 5. Apply Linking Policy     │
└─────────────┬───────────────┘
              │
    ┌─────────┼─────────┐
    │         │         │
    ▼         ▼         ▼
 never   verified    always
    │      email        │
    │         │         │
    ▼         ▼         ▼
 Error    Check      Link
         Verified   Account
            │
      ┌─────┴─────┐
      │           │
   Both OK    Not OK
      │           │
      ▼           ▼
    Link        Error
   Account
```

### Error Messages

Clear, actionable error messages for users:

| Scenario | Error Code | User Message |
|----------|------------|--------------|
| Policy=never, account exists | `account_exists` | "An account with this email already exists. Please sign in with your password or contact support to link your accounts." |
| Policy=verified_email, IdP email not verified | `idp_email_not_verified` | "Your identity provider has not verified your email address. Please verify your email with your IdP and try again." |
| Policy=verified_email, existing account not verified | `account_email_not_verified` | "Please verify your existing account's email address before linking with SSO." |

### Database Schema

Add `linking_policy` column to `sso_providers`:

```sql
ALTER TABLE sso_providers
    ADD COLUMN linking_policy VARCHAR(20) DEFAULT 'verified_email'
    CHECK (linking_policy IN ('never', 'verified_email', 'always'));
```

### API Changes

The SSO provider configuration API accepts `linking_policy`:

```json
{
  "name": "Azure AD",
  "slug": "azure-ad",
  "provider_type": "saml",
  "linking_policy": "verified_email",
  ...
}
```

## Consequences

### Positive
- **Security**: Configurable policy allows organizations to choose their security posture
- **Flexibility**: Supports various enterprise scenarios (migration, hybrid auth)
- **User Experience**: Clear error messages guide users to resolution
- **Compliance**: `never` policy supports strict separation requirements

### Negative
- **Complexity**: Additional configuration option for administrators
- **Migration**: Existing providers default to `verified_email`, which may change behavior

### Neutral
- **Documentation**: Requires clear documentation of each policy's implications
- **UI**: Admin UI needs to expose this setting with appropriate warnings

## Security Considerations

1. **Default to `verified_email`**: Safest default that works for most cases
2. **Warn on `always`**: UI should display security warning when selecting this policy
3. **Audit logging**: All account linking events should be logged for security review
4. **IdP trust**: `verified_email` policy trusts the IdP's email_verified claim - ensure IdP is trustworthy

## Alternatives Considered

### 1. Always Create New Account
- Reject: Poor UX for legitimate account migration scenarios

### 2. Always Link Automatically
- Reject: Security risk from untrusted IdPs

### 3. Manual Admin Linking Only
- Reject: Too much operational overhead for large organizations

### 4. User-Initiated Linking (Post-Login)
- Considered for future: Allow users to link accounts after authenticating with both methods
- Not implemented now due to complexity

## References

- [OWASP Account Linking](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [RFC 7636 - PKCE](https://tools.ietf.org/html/rfc7636) (related security considerations)
- [NIST SP 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html) (identity proofing)
