# Azure AD / Microsoft Entra ID OIDC Setup Guide

This guide walks you through configuring Azure Active Directory (Azure AD), now known as Microsoft Entra ID, as an OIDC identity provider for Guard.

## Prerequisites

- Azure AD subscription with admin access
- Access to Azure Portal
- Guard instance with OIDC support

## Overview

Azure AD provides enterprise-grade identity management with OIDC/OAuth 2.0 support. The setup involves:

1. Creating an App Registration in Azure Portal
2. Configuring authentication settings
3. Setting API permissions
4. Creating a client secret
5. Configuring Guard with the credentials

## Step 1: Create App Registration

1. Sign in to [Azure Portal](https://portal.azure.com/)
2. Navigate to **Azure Active Directory** (or **Microsoft Entra ID**)
3. Go to **App registrations** → **New registration**

### Configure App Registration

1. **Name**: `Guard Authentication`
2. **Supported account types**: Select one:
   - **Single tenant**: Only users in your Azure AD (recommended for most use cases)
   - **Multitenant**: Users from any Azure AD organization
   - **Multitenant + Personal**: Includes Microsoft personal accounts
3. **Redirect URI**:
   - Platform: **Web**
   - URI: `https://yourapp.com/auth/sso/callback/azure`
   - For local development, also add: `http://localhost:3000/auth/sso/callback/azure`
4. Click **Register**

### Save Important Values

After registration, note these values from the **Overview** page:

- **Application (client) ID**: e.g., `12345678-1234-1234-1234-123456789abc`
- **Directory (tenant) ID**: e.g., `87654321-4321-4321-4321-cba987654321`
- **Supported account types**: Verify your selection

## Step 2: Configure Authentication

1. In your app registration, go to **Authentication**

### Platform Settings

1. Under **Platform configurations** → **Web**:
   - Verify redirect URIs are correct
   - Add additional URIs if needed

2. **Front-channel logout URL**: (Optional)
   - Add: `https://yourapp.com/auth/logout`

3. **Implicit grant and hybrid flows**:
   - ❌ Do NOT check "Access tokens"
   - ❌ Do NOT check "ID tokens"
   - (Guard uses Authorization Code flow, not implicit grant)

4. **Allow public client flows**: No (leave disabled)

5. Click **Save**

## Step 3: Create Client Secret

1. Go to **Certificates & secrets**
2. Click **New client secret**
3. Configure:
   - **Description**: `Guard OIDC Client Secret`
   - **Expires**: Select expiration period (recommended: 12 months)
4. Click **Add**

5. **IMPORTANT**: Copy the secret **Value** immediately
   - This is shown only once
   - Store securely - you'll need it for Guard configuration
   - Do NOT copy the "Secret ID" - copy the "Value"

### Secret Rotation

Set a reminder to rotate the secret before expiration:
- Create new secret 1 month before expiry
- Update Guard configuration with new secret
- Delete old secret after verification

## Step 4: Configure API Permissions

1. Go to **API permissions**
2. Click **Add a permission**

### Microsoft Graph Permissions

Select **Microsoft Graph** → **Delegated permissions**:

**Required permissions**:
- ✅ `OpenId permissions` → `openid` - Sign in and read user profile
- ✅ `OpenId permissions` → `email` - View users' email address
- ✅ `OpenId permissions` → `profile` - View users' basic profile

**Optional permissions** (for enhanced functionality):
- `User` → `User.Read` - Read signed-in user's profile
- `GroupMember` → `GroupMember.Read.All` - Read group memberships (requires admin consent)
- `Directory` → `Directory.Read.All` - Read directory data (requires admin consent)

### Grant Admin Consent

For organizational permissions:
1. Click **Grant admin consent for [Your Organization]**
2. Click **Yes** to confirm
3. Verify all permissions show "Granted" status

## Step 5: Configure Token Claims

1. Go to **Token configuration**
2. Click **Add optional claim**

### ID Token Claims

Select **ID** token type and add:
- ✅ `email` - User's email address
- ✅ `family_name` - User's last name
- ✅ `given_name` - User's first name
- ✅ `upn` - User principal name
- ✅ `groups` - Security groups (if using group-based access)

3. Click **Add**
4. If prompted, check "Turn on the Microsoft Graph permission" and click **Add**

## Step 6: Configure Guard

### Determine Your Issuer URL

Azure AD v2.0 endpoint (recommended):
```
https://login.microsoftonline.com/{tenant-id}/v2.0
```

Replace `{tenant-id}` with your Directory (tenant) ID.

For multi-tenant apps, use:
```
https://login.microsoftonline.com/common/v2.0
```

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
    Name:         "Azure AD",
    Slug:         "azure",
    ProviderType: domain.ProviderTypeOIDC,

    // OIDC Configuration
    Issuer:       "https://login.microsoftonline.com/YOUR_TENANT_ID/v2.0",
    ClientID:     "YOUR_APPLICATION_CLIENT_ID",
    ClientSecret: "YOUR_CLIENT_SECRET_VALUE",
    Scopes:       []string{"openid", "profile", "email"},

    // User Provisioning
    Enabled:            true,
    AllowSignup:        true,
    TrustEmailVerified: true,
    Domains:            []string{"yourcompany.com"}, // Optional: restrict to your domain

    // Attribute Mapping for Azure AD
    AttributeMapping: map[string][]string{
        "email":      {"email", "mail", "preferred_username", "upn"},
        "first_name": {"given_name", "givenname"},
        "last_name":  {"family_name", "surname"},
        "name":       {"name"},
        "groups":     {"groups"},
    },
}

// Create provider
azureProvider, err := provider.NewOIDCProvider(ctx, config)
if err != nil {
    log.Fatal(err)
}
```

### Database Configuration

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
    attribute_mapping,
    created_at,
    updated_at
) VALUES (
    gen_random_uuid(),
    'YOUR_TENANT_ID',
    'Azure AD',
    'azure',
    'oidc',
    'https://login.microsoftonline.com/YOUR_AZURE_TENANT_ID/v2.0',
    'YOUR_APPLICATION_CLIENT_ID',
    'YOUR_CLIENT_SECRET_VALUE',
    ARRAY['openid', 'profile', 'email'],
    true,
    true,
    true,
    ARRAY['yourcompany.com'],
    '{"email": ["email", "mail", "preferred_username", "upn"], "first_name": ["given_name"], "last_name": ["family_name"], "groups": ["groups"]}'::jsonb,
    NOW(),
    NOW()
);
```

## Step 7: Test the Integration

### 1. Initiate Login

Create a login button that redirects to:

```
https://yourapp.com/auth/sso/start/azure
```

### 2. Verify Flow

The user should:
1. Be redirected to Microsoft login page
2. Authenticate with their Azure AD account
3. See consent screen (first time only)
4. Be redirected back to your app with a valid session

### 3. Test Cases

✅ **Happy Path**:
- User with valid Azure AD account
- User can log in successfully
- Profile populated with name and email

✅ **Domain Restriction** (if configured):
- User with email outside allowed domains
- Should be rejected

✅ **Group Membership** (if configured):
- User's groups included in claims
- Can use for role-based access

## Azure AD-Specific Claims

Azure AD's ID token includes these claims:

```json
{
  "iss": "https://login.microsoftonline.com/{tenant-id}/v2.0",
  "sub": "AAAAAAAAAAAAAAAAAAAAAIkzqFVrSaSaFHy782bbtaQ",
  "aud": "your-client-id",
  "exp": 1612345678,
  "iat": 1612342078,
  "nbf": 1612342078,
  "name": "John Doe",
  "preferred_username": "john.doe@yourcompany.com",
  "email": "john.doe@yourcompany.com",
  "given_name": "John",
  "family_name": "Doe",
  "oid": "00000000-0000-0000-0000-000000000000",
  "tid": "your-tenant-id",
  "upn": "john.doe@yourcompany.com",
  "groups": ["group-id-1", "group-id-2"]
}
```

### Important Claims

- **oid**: Object ID - unique user identifier in Azure AD
- **tid**: Tenant ID - Azure AD tenant
- **upn**: User Principal Name - typically the user's email
- **preferred_username**: Preferred username (use for login hint)
- **groups**: Group object IDs (requires group claims configuration)

### Using Groups for Authorization

If you need group names instead of IDs:

1. In Azure AD, go to **Token configuration** → **Add groups claim**
2. Select group types to include
3. Choose **Group ID** or **sAMAccountName** (for on-prem synced groups)

Or resolve group IDs via Microsoft Graph API:

```go
// After authentication
if groupIDs, ok := profile.RawAttributes["groups"].([]interface{}); ok {
    groupNames, err := resolveAzureGroupNames(profile.AccessToken, groupIDs)
    if err != nil {
        log.Error("Failed to resolve groups:", err)
    } else {
        profile.Groups = groupNames
    }
}
```

## Advanced Configuration

### Multi-Tenant Configuration

For apps that support users from multiple Azure AD tenants:

1. Set **Supported account types** to **Multitenant**
2. Use common endpoint:
   ```
   Issuer: "https://login.microsoftonline.com/common/v2.0"
   ```
3. Validate tenant ID in callback:
   ```go
   if tid, ok := profile.RawAttributes["tid"].(string); ok {
       if !isAllowedTenant(tid) {
           return errors.New("tenant not allowed")
       }
   }
   ```

### Conditional Access Policies

Azure AD Conditional Access can enforce additional security:

1. Go to **Azure AD** → **Security** → **Conditional Access**
2. Create policy for your app
3. Configure requirements:
   - MFA requirement
   - Device compliance
   - Location restrictions
   - Risk-based access

### App Roles

Define custom roles in your app registration:

1. Go to **App roles** → **Create app role**
2. Define role:
   - **Display name**: `Admin`
   - **Allowed member types**: `Users/Groups`
   - **Value**: `admin`
   - **Description**: `Administrator access`
3. Assign users/groups to roles in **Enterprise Applications**
4. Roles appear in `roles` claim of ID token

## Troubleshooting

### Error: "AADSTS50011: The redirect URI doesn't match"

**Cause**: Redirect URI mismatch.

**Solution**:
1. Verify exact match in Azure Portal → App Registration → Authentication
2. Check for trailing slashes, protocol (http vs https), and path
3. Ensure the URI is added as a "Web" platform redirect URI

### Error: "AADSTS650053: The application asked for scope that doesn't exist"

**Cause**: Invalid scope requested.

**Solution**:
1. Verify scopes in Guard config: `["openid", "profile", "email"]`
2. Check API permissions in Azure Portal
3. Grant admin consent if required

### Error: "AADSTS7000218: The request body must contain the client_assertion parameter"

**Cause**: Using certificate authentication but didn't configure correctly.

**Solution**:
- Use client secret authentication (not certificate)
- Or, configure certificate in Guard if using certificate auth

### Email Claim Missing

**Cause**: User doesn't have email in Azure AD or scope not requested.

**Solution**:
1. Add `email` scope to Guard config
2. Add optional claim in Token configuration
3. Verify user has email in Azure AD profile
4. Use `preferred_username` or `upn` as fallback

### Groups Not Included

**Cause**: Group claims not configured or user has too many groups.

**Solution**:
1. Add groups claim in Token configuration
2. If user has >200 groups, Azure AD includes `_claim_names` and `_claim_sources` instead
3. Fetch groups via Microsoft Graph API using access token

## Security Best Practices

### Production Checklist

- [ ] Use single-tenant app for organization-only access
- [ ] Store client secret encrypted in database
- [ ] Set client secret expiration and rotation schedule
- [ ] Enable Conditional Access policies
- [ ] Restrict redirect URIs to production domains only
- [ ] Use HTTPS for all redirect URIs
- [ ] Enable sign-in logs and monitoring
- [ ] Review API permissions regularly
- [ ] Implement app-level authorization (don't rely solely on Azure AD)
- [ ] Set up alerts for suspicious sign-ins

### Monitoring

Monitor these in Azure AD:
- Sign-in logs (successful and failed attempts)
- Audit logs (configuration changes)
- Risky sign-ins and users
- Token lifetime and refresh patterns

Enable diagnostic settings to send logs to:
- Log Analytics workspace
- Storage account
- Event Hub

## References

- [Microsoft Identity Platform Documentation](https://docs.microsoft.com/en-us/azure/active-directory/develop/)
- [Azure AD OpenID Connect](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-protocols-oidc)
- [Microsoft Graph API](https://docs.microsoft.com/en-us/graph/)
- [Azure AD App Registration](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app)

## Support

For Azure AD-specific issues:
- [Microsoft Identity Platform Support](https://docs.microsoft.com/en-us/azure/active-directory/develop/developer-support-help-options)
- [Azure Portal](https://portal.azure.com/)

For Guard integration issues:
- Check Guard logs for detailed error messages
- Review OIDC implementation guide
- Verify configuration matches this guide
