# Google Workspace OIDC Setup Guide

This guide walks you through configuring Google Workspace (formerly G Suite) as an OIDC identity provider for Guard.

## Prerequisites

- Google Workspace account with admin access
- Access to Google Cloud Console
- Guard instance with OIDC support

## Overview

Google Workspace uses Google's OAuth 2.0 / OIDC implementation. The setup involves:

1. Creating an OAuth 2.0 Client ID in Google Cloud Console
2. Configuring the OAuth consent screen
3. Setting up redirect URIs
4. Configuring Guard with the credentials

## Step 1: Create Google Cloud Project

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Click **Select a Project** → **New Project**
3. Enter project details:
   - **Project Name**: `Guard SSO` (or your preferred name)
   - **Organization**: Select your Google Workspace organization
4. Click **Create**

## Step 2: Configure OAuth Consent Screen

1. In Google Cloud Console, go to **APIs & Services** → **OAuth consent screen**
2. Select **User Type**:
   - **Internal**: Only users in your Google Workspace organization (recommended)
   - **External**: Any Google account (requires verification for production)
3. Click **Create**

### Configure Consent Screen

1. **App Information**:
   - **App name**: `Guard Authentication`
   - **User support email**: Your support email
   - **App logo**: (Optional) Upload your logo

2. **App Domain**:
   - **Application home page**: `https://yourapp.com`
   - **Application privacy policy**: `https://yourapp.com/privacy`
   - **Application terms of service**: `https://yourapp.com/terms`

3. **Authorized domains**:
   - Add your application domain (e.g., `yourapp.com`)

4. **Developer contact information**:
   - Add your email address

5. Click **Save and Continue**

### Configure Scopes

1. Click **Add or Remove Scopes**
2. Select the following scopes:
   - ✅ `openid` - OpenID Connect authentication
   - ✅ `https://www.googleapis.com/auth/userinfo.email` - Email address
   - ✅ `https://www.googleapis.com/auth/userinfo.profile` - Basic profile information

3. Optional scopes for additional functionality:
   - `https://www.googleapis.com/auth/admin.directory.user.readonly` - Read user information (requires admin consent)
   - `https://www.googleapis.com/auth/admin.directory.group.readonly` - Read group membership

4. Click **Update** → **Save and Continue**

### Test Users (External Apps Only)

If you selected "External" user type, add test users during development:

1. Click **Add Users**
2. Enter email addresses of test users
3. Click **Save and Continue**

## Step 3: Create OAuth 2.0 Credentials

1. Go to **APIs & Services** → **Credentials**
2. Click **Create Credentials** → **OAuth client ID**
3. Configure the client:
   - **Application type**: **Web application**
   - **Name**: `Guard OIDC Client`

4. **Authorized JavaScript origins**: (Optional)
   - Add your application URLs if needed

5. **Authorized redirect URIs**:
   - Add your Guard callback URL:
     ```
     https://yourapp.com/auth/sso/t/{tenant_id}/google/callback
     ```
   - For local development:
     ```
     http://localhost:3000/auth/sso/t/{tenant_id}/google/callback
     ```

6. Click **Create**

7. **Save Credentials**:
   - Copy the **Client ID** (looks like: `123456789-abc...xyz.apps.googleusercontent.com`)
   - Copy the **Client Secret**
   - Store these securely - you'll need them for Guard configuration

## Step 4: Configure Guard

### Create OIDC Provider in Guard

```go
import (
    "context"
    "github.com/corvusHold/guard/internal/auth/sso/domain"
    "github.com/corvusHold/guard/internal/auth/sso/provider"
    "github.com/google/uuid"
)

ctx := context.Background()

config := &domain.Config{
    ID:           uuid.New(),
    TenantID:     yourTenantID,
    Name:         "Google Workspace",
    Slug:         "google",
    ProviderType: domain.ProviderTypeOIDC,

    // OIDC Configuration
    Issuer:       "https://accounts.google.com",
    ClientID:     "YOUR_CLIENT_ID.apps.googleusercontent.com",
    ClientSecret: "YOUR_CLIENT_SECRET",
    Scopes:       []string{"openid", "profile", "email"},

    // User Provisioning
    Enabled:            true,
    AllowSignup:        true,
    TrustEmailVerified: true,
    Domains:            []string{"yourcompany.com"}, // Restrict to your domain

    // Attribute Mapping (Google uses standard OIDC claims)
    AttributeMapping: nil, // Use defaults
}

// Create provider
googleProvider, err := provider.NewOIDCProvider(ctx, config)
if err != nil {
    log.Fatal(err)
}
```

### Database Configuration

Insert the provider configuration into your database:

```sql
INSERT INTO sso_providers (
    id,
    tenant_id,
    name,
    slug,
    provider_type,
    issuer,
    client_id,
    client_secret,
    scopes,
    enabled,
    allow_signup,
    trust_email_verified,
    domains,
    created_at,
    updated_at
) VALUES (
    gen_random_uuid(),
    'YOUR_TENANT_ID',
    'Google Workspace',
    'google',
    'oidc',
    'https://accounts.google.com',
    'YOUR_CLIENT_ID.apps.googleusercontent.com',
    'YOUR_CLIENT_SECRET',
    ARRAY['openid', 'profile', 'email'],
    true,
    true,
    true,
    ARRAY['yourcompany.com'],
    NOW(),
    NOW()
);
```

## Step 5: Test the Integration

### 1. Initiate Login

Create a login button that redirects to:

```
https://yourapp.com/auth/sso/t/{tenant_id}/google/login
```

### 2. Verify Flow

The user should:
1. Be redirected to Google's login page
2. See your app name and requested permissions
3. Authenticate with their Google Workspace account
4. Be redirected back to your app with a valid session

### 3. Test Cases

Test the following scenarios:

✅ **Happy Path**:
- User with valid Google Workspace account
- Email domain matches allowed domains
- User can log in successfully

✅ **Domain Restriction**:
- User with email outside allowed domains
- Should be rejected

✅ **First-Time Login** (if `AllowSignup: true`):
- New user account is created
- Profile populated from Google claims

✅ **Existing User**:
- User account linked to Google identity
- Login succeeds without creating duplicate

## Google-Specific Claims

Google's ID token includes these standard claims:

```json
{
  "iss": "https://accounts.google.com",
  "sub": "10769150350006150715113082367",
  "aud": "your-client-id.apps.googleusercontent.com",
  "exp": 1612345678,
  "iat": 1612342078,
  "email": "user@yourcompany.com",
  "email_verified": true,
  "name": "John Doe",
  "picture": "https://lh3.googleusercontent.com/...",
  "given_name": "John",
  "family_name": "Doe",
  "locale": "en",
  "hd": "yourcompany.com"
}
```

### Hosted Domain (HD) Claim

The `hd` claim contains the hosted domain for Google Workspace users. You can use this to enforce domain restrictions:

```go
// In your callback handler
if hdomain, ok := profile.RawAttributes["hd"].(string); ok {
    if hdomain != "yourcompany.com" {
        return errors.New("invalid domain")
    }
}
```

## Advanced Configuration

### Custom Scopes

Request additional Google-specific scopes:

```go
Scopes: []string{
    "openid",
    "profile",
    "email",
    "https://www.googleapis.com/auth/admin.directory.user.readonly",
},
```

Note: Additional scopes may require admin consent and domain-wide delegation.

### Domain-Wide Delegation

For service account access to Google Workspace APIs:

1. Go to **Google Workspace Admin Console**
2. Navigate to **Security** → **API Controls** → **Domain-wide Delegation**
3. Add your Client ID with required scopes
4. Configure service account in Guard

### Admin SDK Integration

To fetch group memberships or additional user data:

```go
// After successful authentication
if profile.AccessToken != "" {
    // Use access token to call Google Admin SDK
    groups, err := fetchGoogleGroups(profile.AccessToken, profile.Email)
    if err != nil {
        log.Error("Failed to fetch groups:", err)
    } else {
        profile.Groups = groups
    }
}
```

## Troubleshooting

### Error: "redirect_uri_mismatch"

**Cause**: The redirect URI in the auth request doesn't match configured URIs.

**Solution**:
1. Go to Google Cloud Console → Credentials
2. Edit your OAuth client
3. Ensure exact match (including protocol and path):
   - `https://yourapp.com/auth/sso/t/{tenant_id}/google/callback` ✅
   - `https://yourapp.com/auth/sso/t/{tenant_id}/google/callback/` ❌ (trailing slash)

### Error: "access_denied"

**Cause**: User denied consent or doesn't have access.

**Solution**:
- For internal apps: Ensure user is part of your Google Workspace organization
- For external apps: Verify app is published or user is added as test user
- Check OAuth consent screen configuration

### Error: "invalid_client"

**Cause**: Client ID or secret is incorrect.

**Solution**:
1. Verify Client ID and Secret from Google Cloud Console
2. Ensure no extra spaces or characters when copying
3. Check client is enabled and not deleted

### Email Not Verified

**Cause**: Google returns `email_verified: false` for new accounts.

**Solution**:
- Set `TrustEmailVerified: false` in Guard config to require manual verification
- Or, trust Google's verification: `TrustEmailVerified: true` (recommended)

### Users Outside Domain Can Login

**Cause**: Domain restriction not enforced.

**Solution**:
1. Set `Domains: []string{"yourcompany.com"}` in config
2. Check `hd` claim in callback
3. For internal apps, use "Internal" user type in OAuth consent screen

## Security Best Practices

### Production Checklist

- [ ] Use "Internal" user type for Google Workspace-only access
- [ ] Set specific authorized redirect URIs (no wildcards)
- [ ] Store client secret encrypted in database
- [ ] Enable domain restrictions
- [ ] Use HTTPS for all redirect URIs
- [ ] Implement rate limiting on auth endpoints
- [ ] Monitor auth logs for suspicious activity
- [ ] Regularly rotate client secrets
- [ ] Review and minimize requested scopes
- [ ] Set up alerts for auth failures

### Monitoring

Monitor these metrics:
- Failed login attempts
- Logins from unexpected domains
- Changes to OAuth client configuration
- Unusual geographic login patterns

## References

- [Google Identity Platform - OIDC](https://developers.google.com/identity/protocols/oauth2/openid-connect)
- [Google OAuth 2.0 Playground](https://developers.google.com/oauthplayground/)
- [Google Workspace Admin Console](https://admin.google.com/)
- [Google Cloud Console](https://console.cloud.google.com/)

## Support

For Google-specific issues:
- [Google Workspace Admin Help](https://support.google.com/a)
- [Google Cloud Support](https://cloud.google.com/support)

For Guard integration issues:
- Check Guard logs for detailed error messages
- Review OIDC implementation guide
- Verify configuration matches this guide
