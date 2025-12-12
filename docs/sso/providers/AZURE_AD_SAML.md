# Azure AD SAML 2.0 Integration Guide

This guide walks you through configuring Guard as a SAML Service Provider (SP) with Azure Active Directory (Azure AD) as the Identity Provider (IdP).

## Prerequisites

- Azure AD tenant (available with Microsoft 365 or Azure subscription)
- Guard instance with SAML support
- Global Administrator or Application Administrator role in Azure AD
- Azure AD Premium license (for advanced features like conditional access)

## Overview

This integration allows users to authenticate to Guard using their Azure AD credentials via SAML 2.0.

## Step 1: Prepare Guard Configuration

Note these URLs that you'll need when configuring Azure AD:

- **Entity ID / Identifier**: `https://your-app.com/saml/metadata`
- **Reply URL (ACS URL)**: `https://your-app.com/saml/acs`
- **Sign-on URL**: `https://your-app.com/login` (where users start login)
- **Logout URL** (optional): `https://your-app.com/saml/slo`

## Step 2: Create Enterprise Application in Azure AD

1. Sign in to [Azure Portal](https://portal.azure.com)
2. Navigate to **Azure Active Directory**
3. Click **Enterprise applications** in the left menu
4. Click **+ New application**
5. Click **+ Create your own application**
6. Enter:
   - **Name**: "Guard" (or your application name)
   - Select: **Integrate any other application you don't find in the gallery (Non-gallery)**
7. Click **Create**

## Step 3: Configure Single Sign-On

1. In your new Enterprise Application, click **Single sign-on** in the left menu
2. Select **SAML** as the single sign-on method

## Step 4: Basic SAML Configuration

Click **Edit** in the "Basic SAML Configuration" section:

### Required Settings

- **Identifier (Entity ID)**: `https://your-app.com/saml/metadata`
  - Click **+ Add identifier** if adding additional identifiers

- **Reply URL (Assertion Consumer Service URL)**: `https://your-app.com/saml/acs`
  - Click **+ Add reply URL** if adding additional URLs
  - ☑ Check **Set as default** for your primary ACS URL

### Optional Settings

- **Sign on URL**: `https://your-app.com/login`
- **Relay State**: Leave blank (Guard handles this)
- **Logout URL**: `https://your-app.com/saml/slo`

Click **Save**

## Step 5: Configure Attributes & Claims

Click **Edit** in the "Attributes & Claims" section:

### Required Claims

Azure AD provides these by default:

| Claim name | Source attribute |
|-----------|-----------------|
| `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress` | `user.mail` |
| `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname` | `user.givenname` |
| `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname` | `user.surname` |
| `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name` | `user.userprincipalname` |

### Recommended: Simplify Claim Names

To use simpler attribute names, modify the claims:

1. Click on each claim to edit
2. Change **Name** to use simple names:

| Original Name | New Name | Source Attribute |
|--------------|----------|------------------|
| `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress` | `email` | `user.mail` |
| `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname` | `firstName` | `user.givenname` |
| `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname` | `lastName` | `user.surname` |
| `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name` | `displayName` | `user.displayname` |

### Optional: Add Group Claims

To include user groups:

1. Click **+ Add a group claim**
2. Select **Security groups** or **All groups**
3. Under **Source attribute**, select **Group ID** or **sAMAccountName**
4. **Advanced options**:
   - ☑ **Customize the name of the group claim**
   - **Name**: `groups`

Click **Save**

## Step 6: Download SAML Certificate and Metadata

In the "SAML Signing Certificate" section:

1. **Certificate (Base64)**: Download (optional, for manual verification)
2. **Federation Metadata XML**: Click **Download**
   - Save this file - you'll need it for Guard configuration
3. Note the **App Federation Metadata Url** - you can use this URL to fetch metadata dynamically

## Step 7: Note Application Configuration URLs

In the "Set up Guard" section, note these URLs (you'll need them if not using metadata XML):

- **Login URL**: e.g., `https://login.microsoftonline.com/.../saml2`
- **Azure AD Identifier**: e.g., `https://sts.windows.net/.../`
- **Logout URL**: e.g., `https://login.microsoftonline.com/.../saml2`

## Step 8: Assign Users and Groups

1. Click **Users and groups** in the left menu
2. Click **+ Add user/group**
3. Select users or groups to grant access
4. Click **Assign**

## Step 9: Configure Guard

### Option A: Using Metadata URL (Recommended)

```go
config := &domain.Config{
    // SP Configuration
    EntityID:      "https://your-app.com/saml/metadata",
    ACSUrl:        "https://your-app.com/saml/acs",
    SLOUrl:        "https://your-app.com/saml/slo",

    // Azure AD IdP Configuration
    IdPMetadataURL: "https://login.microsoftonline.com/TENANT-ID/federationmetadata/2007-06/federationmetadata.xml",

    // Security Settings
    WantAssertionsSigned: true,
    WantResponseSigned:   true,
    SignRequests:         false,

    // Attribute Mapping (using simplified names from Step 5)
    AttributeMapping: map[string][]string{
        "email":      {"email"},
        "first_name": {"firstName"},
        "last_name":  {"lastName"},
        "name":       {"displayName"},
        "groups":     {"groups"},
    },

    // Provider Settings
    ProviderType: domain.ProviderTypeSAML,
    Name:         "Azure AD",
    Slug:         "azure-ad",
    Enabled:      true,
}
```

### Option B: Using Metadata XML

If you downloaded the Federation Metadata XML file:

```go
config := &domain.Config{
    // SP Configuration
    EntityID:      "https://your-app.com/saml/metadata",
    ACSUrl:        "https://your-app.com/saml/acs",
    SLOUrl:        "https://your-app.com/saml/slo",

    // Azure AD IdP Configuration
    IdPMetadataXML: string(metadataXMLBytes), // Read from downloaded file

    // ... rest of config same as Option A
}
```

### Option C: Using Default Azure AD Claim Names

If you kept the default Azure AD claim names (long URIs):

```go
config := &domain.Config{
    // ... SP and IdP config same as above ...

    // Attribute Mapping (using default Azure AD claim names)
    AttributeMapping: map[string][]string{
        "email": {
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
            "email",
        },
        "first_name": {
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
            "firstName",
        },
        "last_name": {
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
            "lastName",
        },
        "name": {
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
            "displayName",
        },
        "groups": {
            "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups",
            "groups",
        },
    },

    // ... rest of config
}
```

## Step 10: Test the Integration

### Test from Azure Portal

1. In your Enterprise Application, go to **Single sign-on**
2. Scroll to bottom and click **Test**
3. Click **Test sign in**
4. You should be redirected to Guard after successful authentication

### Test from Guard

1. Navigate to `https://your-app.com/login`
2. Click "Sign in with Azure AD" (or similar)
3. You should be redirected to Microsoft login
4. Enter your Azure AD credentials
5. You should be redirected back to Guard with a valid session

### Verify in Azure AD Sign-in Logs

1. Go to **Azure Active Directory** → **Sign-in logs**
2. Find your test sign-in
3. Review for any errors or warnings

## Common Azure AD Attributes

| Azure AD Attribute | Description | Guard Field |
|-------------------|-------------|-------------|
| `user.mail` | Primary email | `email` |
| `user.givenname` | First/given name | `first_name` |
| `user.surname` | Last/family name | `last_name` |
| `user.displayname` | Display name | `name` |
| `user.userprincipalname` | UPN (username@domain) | - |
| `user.objectid` | Unique object ID | - |
| `user.department` | Department | - |
| `user.jobtitle` | Job title | - |
| `user.groups` | Group memberships | `groups` |

## Troubleshooting

### AADSTS50011: The reply URL does not match

**Cause**: ACS URL mismatch

**Solution**:
1. Verify **Reply URL** in Azure AD exactly matches Guard's `ACSUrl`
2. Check for:
   - Trailing slashes
   - HTTP vs HTTPS
   - Case sensitivity

### AADSTS700016: Application not found

**Cause**: Entity ID / Identifier mismatch

**Solution**:
1. Verify **Identifier** in Azure AD matches Guard's `EntityID`
2. Check you're signing in to the correct Azure AD tenant

### Signature Verification Failed

**Cause**: Certificate mismatch or expired

**Solution**:
1. Re-download Federation Metadata XML
2. Update Guard configuration
3. Check if Azure AD rotated certificates

### User Not Assigned to Application

**Error**: `AADSTS50105: The signed in user is not assigned to a role for the application`

**Solution**:
1. Go to **Users and groups**
2. Add the user/group to the application
3. Try again

### Missing Email Attribute

**Cause**: User doesn't have `mail` attribute populated

**Solution**:
1. Use `user.userprincipalname` instead of `user.mail` for email claim
2. Or ensure all users have email addresses in Azure AD

### Clock Skew Error

**Cause**: Time synchronization issue

**Solution**:
1. Ensure Guard server time is synchronized (use NTP)
2. Azure AD allows for some clock skew, but keep it minimal

## Advanced Configuration

### Conditional Access

Enforce additional security with Azure AD Conditional Access:

1. Go to **Azure AD** → **Security** → **Conditional Access**
2. Create a new policy
3. Assign to your Guard application
4. Configure conditions (location, device, risk, etc.)
5. Set access controls (require MFA, compliant device, etc.)

### Custom Signing Certificate

To use your own certificate instead of Azure AD's:

1. Generate a certificate with private key
2. **SAML Signing Certificate** → **Import Certificate**
3. Upload your certificate
4. Set as active

### Multi-Tenant Azure AD

For multi-tenant applications:

```go
// Use common endpoint
config.IdPMetadataURL = "https://login.microsoftonline.com/common/federationmetadata/2007-06/federationmetadata.xml"
```

Note: This requires additional application configuration in Azure AD.

### B2B Guest Users

To allow external users (B2B guests):

1. In **Users and groups**, add guest users
2. Ensure guests have required attributes populated
3. Test guest user sign-in

### Azure AD B2C

For customer-facing applications with Azure AD B2C:

1. Create user flow or custom policy
2. Configure SAML application in B2C
3. Use B2C-specific metadata URL:
   ```
   https://YOUR-TENANT.b2clogin.com/YOUR-TENANT.onmicrosoft.com/B2C_1A_YOUR_POLICY/samlp/metadata
   ```

## Security Best Practices

1. **Use HTTPS only** for all URLs
2. **Enable signature verification**:
   ```go
   config.WantAssertionsSigned = true
   config.WantResponseSigned = true
   ```
3. **Implement Conditional Access** for production
4. **Monitor sign-in logs** regularly
5. **Set up alerts** for suspicious activities
6. **Use managed identities** when hosting in Azure
7. **Rotate certificates** before expiration
8. **Implement least-privilege access** - only assign necessary users
9. **Enable Azure AD Identity Protection** for risk-based policies
10. **Use Azure AD audit logs** for compliance

## Resources

- [Azure AD SAML Documentation](https://docs.microsoft.com/en-us/azure/active-directory/develop/single-sign-on-saml-protocol)
- [Azure AD Enterprise Application Tutorials](https://docs.microsoft.com/en-us/azure/active-directory/saas-apps/tutorial-list)
- [Azure Portal](https://portal.azure.com)
- [Guard SAML Implementation Guide](../SAML_IMPLEMENTATION.md)

## Support

For Azure AD-specific issues:
- Check Azure AD sign-in logs
- Review audit logs
- Contact Microsoft Support

For Guard-specific issues:
- Check Guard application logs
- Review SAML response/assertion details
- Verify attribute mappings
