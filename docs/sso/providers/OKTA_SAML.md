# Okta SAML 2.0 Integration Guide

This guide walks you through configuring Guard as a SAML Service Provider (SP) with Okta as the Identity Provider (IdP).

## Prerequisites

- Okta account (free developer account available at [developer.okta.com](https://developer.okta.com))
- Guard instance with SAML support
- Admin access to your Okta organization

## Overview

This integration allows users to authenticate to Guard using their Okta credentials via SAML 2.0.

## Step 1: Generate Guard SP Metadata

First, generate your Service Provider metadata from Guard.

### Option A: Via API/Code

```go
import (
    "github.com/corvusHold/guard/internal/auth/sso/domain"
    "github.com/corvusHold/guard/internal/auth/sso/provider"
)

config := &domain.Config{
    EntityID:       "https://your-app.com/saml/metadata",
    ACSUrl:         "https://your-app.com/saml/acs",
    SLOUrl:         "https://your-app.com/saml/slo", // Optional
    IdPMetadataXML: "", // Will be filled later
    ProviderType:   domain.ProviderTypeSAML,
}

// This will auto-generate a certificate
provider, err := provider.NewSAMLProvider(ctx, config)
if err != nil {
    panic(err)
}

metadata, err := provider.GetMetadata(ctx)
if err != nil {
    panic(err)
}

// Save this metadata XML - you'll upload it to Okta
fmt.Println(metadata.MetadataXML)

// IMPORTANT: Save the generated certificate for persistence
// Store config.SPCertificate and config.SPPrivateKey in your database
```

### Option B: Note Your URLs

If you're configuring manually, you'll need these URLs:

- **Entity ID / Audience URI**: `https://your-app.com/saml/metadata`
- **ACS URL**: `https://your-app.com/saml/acs`
- **Single Logout URL** (optional): `https://your-app.com/saml/slo`

## Step 2: Create SAML Application in Okta

1. Log in to your Okta Admin Console
2. Navigate to **Applications** → **Applications**
3. Click **Create App Integration**
4. Select:
   - **Sign-in method**: SAML 2.0
   - Click **Next**

## Step 3: Configure General Settings

1. **App name**: Enter "Guard" (or your app name)
2. **App logo** (optional): Upload your logo
3. **App visibility**: Configure as needed
4. Click **Next**

## Step 4: Configure SAML Settings

### General SAML Settings

- **Single sign-on URL**: `https://your-app.com/saml/acs`
  - ☑ Check "Use this for Recipient URL and Destination URL"
  - **Default RelayState**: Leave blank (Guard handles this)

- **Audience URI (SP Entity ID)**: `https://your-app.com/saml/metadata`

- **Name ID format**: `EmailAddress`

- **Application username**: `Email`

- **Update application username on**: `Create and update`

### Advanced Settings (Click "Show Advanced Settings")

- **Response**: `Signed`
- **Assertion Signature**: `Signed`
- **Signature Algorithm**: `RSA-SHA256`
- **Digest Algorithm**: `SHA256`
- **Assertion Encryption**: `Unencrypted` (Guard doesn't support encryption yet)
- **SAML Single Logout**:
  - **Enabled**: Yes (if using SLO)
  - **Single Logout URL**: `https://your-app.com/saml/slo`
  - **SP Issuer**: `https://your-app.com/saml/metadata`

## Step 5: Configure Attribute Statements

Add these attribute mappings:

| Name | Name Format | Value |
|------|-------------|-------|
| `email` | `Unspecified` | `user.email` |
| `firstName` | `Unspecified` | `user.firstName` |
| `lastName` | `Unspecified` | `user.lastName` |
| `displayName` | `Unspecified` | `user.displayName` |

### Optional: Group Attribute Statements

To include user groups:

| Name | Name Format | Filter | Value |
|------|-------------|--------|-------|
| `groups` | `Unspecified` | `Matches regex: .*` | `appuser.groups` |

## Step 6: Finish Application Setup

1. Click **Next**
2. Select:
   - **I'm an Okta customer adding an internal app**
   - **This is an internal app that we have created**
3. Click **Finish**

## Step 7: Assign Users/Groups

1. Go to the **Assignments** tab
2. Click **Assign** → **Assign to People** or **Assign to Groups**
3. Select users/groups and click **Assign**
4. Click **Done**

## Step 8: Download IdP Metadata

1. Go to the **Sign On** tab
2. Under **SAML Signing Certificates**, find the active certificate
3. Click **Actions** → **View IdP metadata**
4. Save the metadata XML or copy the URL

You should see XML like this:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
                  entityID="http://www.okta.com/exk...">
  <IDPSSODescriptor>
    ...
  </IDPSSODescriptor>
</EntityDescriptor>
```

## Step 9: Configure Guard with Okta Metadata

Update your Guard SAML configuration:

```go
config := &domain.Config{
    // SP Configuration
    EntityID:      "https://your-app.com/saml/metadata",
    ACSUrl:        "https://your-app.com/saml/acs",
    SLOUrl:        "https://your-app.com/saml/slo",

    // Okta IdP Configuration
    IdPMetadataURL: "https://your-org.okta.com/app/exk.../sso/saml/metadata",
    // OR provide the XML directly:
    // IdPMetadataXML: "<EntityDescriptor>...</EntityDescriptor>",

    // Security Settings
    WantAssertionsSigned: true,
    WantResponseSigned:   true,
    SignRequests:         false, // Okta doesn't require signed requests

    // Attribute Mapping
    AttributeMapping: map[string][]string{
        "email":      {"email"},
        "first_name": {"firstName"},
        "last_name":  {"lastName"},
        "name":       {"displayName"},
        "groups":     {"groups"},
    },

    // Provider Settings
    ProviderType: domain.ProviderTypeSAML,
    Name:         "Okta",
    Slug:         "okta",
    Enabled:      true,
}
```

## Step 10: Test the Integration

### Test from Okta

1. In Okta Admin Console, go to your application
2. Click **View SAML setup instructions**
3. Use the login URL provided
4. You should be redirected to Guard's callback URL after successful authentication

### Test from Guard

1. Initiate SAML login from your Guard application
2. You should be redirected to Okta login
3. Enter Okta credentials
4. You should be redirected back to Guard with a valid session

### Verify User Profile

Check that Guard receives the correct attributes:

```go
profile, err := provider.Callback(ctx, callbackRequest)
if err != nil {
    log.Error("SAML callback failed", err)
    return err
}

log.Printf("User authenticated: %s (%s)", profile.Email, profile.Name)
log.Printf("Groups: %v", profile.Groups)
```

## Common Okta-Specific Attributes

Okta provides these standard attributes that you can map:

| Okta Attribute | Description | Guard Field |
|---------------|-------------|-------------|
| `user.email` | User's email address | `email` |
| `user.firstName` | First/given name | `first_name` |
| `user.lastName` | Last/family name | `last_name` |
| `user.displayName` | Full display name | `name` |
| `user.login` | Okta username | - |
| `user.secondEmail` | Secondary email | - |
| `user.mobilePhone` | Mobile phone | - |
| `appuser.groups` | App-specific groups | `groups` |

## Troubleshooting

### "Access Denied" Error

**Cause**: User is not assigned to the application

**Solution**:
1. Go to **Assignments** tab
2. Assign the user to the application

### Signature Verification Failed

**Cause**: Certificate mismatch

**Solution**:
1. Re-download Okta's IdP metadata
2. Update Guard configuration
3. Verify certificate hasn't been rotated

### Missing Attributes

**Cause**: Attribute statements not configured correctly

**Solution**:
1. Go to **Sign On** tab → **Edit**
2. Verify attribute statements match exactly as shown in Step 5
3. Save and test again

### Clock Skew Error

**Cause**: Time difference between Guard and Okta

**Solution**:
1. Ensure Guard server time is synchronized (use NTP)
2. Check system timezone is configured correctly

### Invalid ACS URL

**Cause**: URL mismatch between Okta and Guard config

**Solution**:
1. Verify ACS URL in Okta matches exactly: `https://your-app.com/saml/acs`
2. Check for trailing slashes (must match exactly)
3. Verify HTTPS is used (Okta requires HTTPS for production)

## Advanced Configuration

### Custom Domain

If using an Okta custom domain:

```go
config.IdPMetadataURL = "https://login.your-company.com/app/exk.../sso/saml/metadata"
```

### Multiple Okta Orgs

To support multiple Okta organizations:

1. Create separate SAML provider configs for each org
2. Use different slugs: `okta-org1`, `okta-org2`
3. Each will have its own IdP metadata URL

### Group-Based Authorization

```go
// After authentication, check groups
if !contains(profile.Groups, "guard-users") {
    return errors.New("user not authorized")
}
```

## Security Best Practices

1. **Always use HTTPS** for production
2. **Enable signature verification**:
   ```go
   config.WantAssertionsSigned = true
   config.WantResponseSigned = true
   ```
3. **Monitor certificate expiration**:
   - Okta rotates certificates periodically
   - Set up alerts for metadata changes
4. **Use strong Entity IDs**:
   - Use your production domain
   - Don't use localhost or test domains in production
5. **Implement Single Logout** for better security
6. **Regularly audit** assigned users and groups

## Resources

- [Okta SAML Documentation](https://developer.okta.com/docs/guides/build-sso-integration/saml2/main/)
- [Okta Developer Console](https://developer.okta.com)
- [Guard SAML Implementation Guide](../SAML_IMPLEMENTATION.md)

## Support

For Okta-specific issues:
- Check Okta's system log (Reports → System Log)
- Contact Okta Support

For Guard-specific issues:
- Check Guard application logs
- Review SAML response/assertion details
