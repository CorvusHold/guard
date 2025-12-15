import { expect, test } from '@playwright/test'

const UI_BASE = 'http://localhost:4173'
const TENANT_ID = 'f9637251-1cd9-4394-9a39-a62a1e210fa3'

function cors(headers: Record<string, string> = {}) {
  return {
    'access-control-allow-origin': '*',
    'access-control-expose-headers': 'location,x-request-id,content-type',
    ...headers
  }
}

// Mock authenticated admin user
async function mockAuthMe(page: import('@playwright/test').Page) {
  await page.route('**/api/v1/auth/me', async (route) => {
    const req = route.request()
    if (req.method() === 'OPTIONS') {
      return route.fulfill({
        status: 204,
        headers: cors({
          'access-control-allow-methods': 'GET,OPTIONS',
          'access-control-allow-headers':
            'content-type,authorization,accept,x-guard-client'
        })
      })
    }
    return route.fulfill({
      status: 200,
      body: JSON.stringify({
        id: 'user-123',
        email: 'admin@example.com',
        first_name: 'Admin',
        last_name: 'User',
        roles: ['admin'],
        tenant_id: TENANT_ID
      }),
      headers: cors({ 'content-type': 'application/json' })
    })
  })
}

async function mockTenantSettings(page: import('@playwright/test').Page) {
  await page.route(`**/api/v1/tenants/${TENANT_ID}/settings`, async (route) => {
    const req = route.request()
    if (req.method() === 'OPTIONS') {
      return route.fulfill({
        status: 204,
        headers: cors({
          'access-control-allow-methods': 'GET,OPTIONS',
          'access-control-allow-headers':
            'content-type,authorization,accept,x-guard-client'
        })
      })
    }
    return route.fulfill({
      status: 200,
      body: JSON.stringify({}),
      headers: cors({ 'content-type': 'application/json' })
    })
  })
}

// Mock SSO providers list
async function mockSsoProviders(page: import('@playwright/test').Page) {
  await page.route('**/api/v1/sso/providers**', async (route) => {
    const req = route.request()
    if (req.method() === 'OPTIONS') {
      return route.fulfill({
        status: 204,
        headers: cors({
          'access-control-allow-methods': 'GET,POST,PUT,DELETE,OPTIONS',
          'access-control-allow-headers':
            'content-type,authorization,accept,x-guard-client'
        })
      })
    }
    if (req.method() === 'GET') {
      return route.fulfill({
        status: 200,
        body: JSON.stringify({ providers: [], total: 0 }),
        headers: cors({ 'content-type': 'application/json' })
      })
    }
    return route.fulfill({
      status: 201,
      body: JSON.stringify({
        id: 'provider_123',
        name: 'Test Provider',
        slug: 'test-provider',
        provider_type: 'saml',
        enabled: true
      }),
      headers: cors({ 'content-type': 'application/json' })
    })
  })
}

// Mock SP Info endpoint with V2 tenant-scoped URLs
async function mockSpInfo(page: import('@playwright/test').Page, options: { 
  shouldFail?: boolean
  errorMessage?: string 
} = {}) {
  await page.route('**/api/v1/sso/sp-info**', async (route) => {
    const req = route.request()
    if (req.method() === 'OPTIONS') {
      return route.fulfill({
        status: 204,
        headers: cors({
          'access-control-allow-methods': 'GET,OPTIONS',
          'access-control-allow-headers':
            'content-type,authorization,accept,x-guard-client'
        })
      })
    }

    // Check for required parameters
    const url = new URL(req.url())
    const slug = url.searchParams.get('slug')
    const tenantId = url.searchParams.get('tenant_id')

    // Simulate missing bearer token error
    const authHeader = req.headers()['authorization']
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return route.fulfill({
        status: 401,
        body: JSON.stringify({ error: 'missing bearer token' }),
        headers: cors({ 'content-type': 'application/json' })
      })
    }

    // Simulate missing slug error
    if (!slug) {
      return route.fulfill({
        status: 400,
        body: JSON.stringify({ error: 'slug query parameter is required' }),
        headers: cors({ 'content-type': 'application/json' })
      })
    }

    // Simulate custom error
    if (options.shouldFail) {
      return route.fulfill({
        status: 400,
        body: JSON.stringify({ error: options.errorMessage || 'Failed to compute SP info' }),
        headers: cors({ 'content-type': 'application/json' })
      })
    }

    // Use tenant_id from query or default
    const effectiveTenantId = tenantId || TENANT_ID
    
    // V2 tenant-scoped URL format
    return route.fulfill({
      status: 200,
      body: JSON.stringify({
        entity_id: 'http://localhost:8080/auth/sso/t/' + effectiveTenantId + '/' + slug + '/metadata',
        acs_url: 'http://localhost:8080/auth/sso/t/' + effectiveTenantId + '/' + slug + '/callback',
        slo_url: 'http://localhost:8080/auth/sso/t/' + effectiveTenantId + '/' + slug + '/logout',
        metadata_url: 'http://localhost:8080/auth/sso/t/' + effectiveTenantId + '/' + slug + '/metadata',
        login_url: 'http://localhost:8080/auth/sso/t/' + effectiveTenantId + '/' + slug + '/login',
        base_url: 'http://localhost:8080',
        tenant_id: effectiveTenantId
      }),
      headers: cors({ 'content-type': 'application/json' })
    })
  })
}

test.describe('SSO SP Info API Integration', () => {
  test.beforeEach(async ({ page, context }) => {
    page.on('console', (msg) => {
      if (msg.type() === 'error') {
        console.log('PAGE ERROR:', msg.text())
      }
    })

    try {
      await context.grantPermissions(['clipboard-read', 'clipboard-write'])
    } catch {
      try {
        await context.grantPermissions(['clipboard-write'])
      } catch {
        // ignore
      }
    }

    await page.addInitScript(() => {
      const w = window as any
      w.__e2eClipboard = ''

      const nav: any = navigator
      if (!nav.clipboard) nav.clipboard = {}

      if (typeof nav.clipboard.writeText !== 'function') {
        nav.clipboard.writeText = async (text: string) => {
          w.__e2eClipboard = text
        }
      }

      if (typeof nav.clipboard.readText !== 'function') {
        nav.clipboard.readText = async () => w.__e2eClipboard
      }
    })

    await page.route('**/api/v1/auth/refresh', async (route) => {
      const req = route.request()
      if (req.method() === 'OPTIONS') {
        return route.fulfill({
          status: 204,
          headers: cors({
            'access-control-allow-methods': 'POST,OPTIONS',
            'access-control-allow-headers':
              'content-type,authorization,accept,x-guard-client'
          })
        })
      }
      return route.fulfill({
        status: 401,
        body: JSON.stringify({ message: 'unauthorized' }),
        headers: cors({ 'content-type': 'application/json' })
      })
    })
  })

  async function seedBearer(page: import('@playwright/test').Page) {
    await page.addInitScript((tenantId: string) => {
      localStorage.setItem(
        'guard_runtime',
        JSON.stringify({
          guard_base_url: 'http://localhost:8080',
          source: 'direct',
          auth_mode: 'bearer'
        })
      )
      localStorage.setItem('guard_ui:guard_access_token', 'test-token-123')
      localStorage.setItem('guard_ui:guard_refresh_token', 'test-refresh-123')
      localStorage.setItem('guard_ui:tenant_id', tenantId)
      localStorage.setItem('tenant_id', tenantId)
      localStorage.setItem('tenant_name', 'Test Organization')
    }, TENANT_ID)
  }

  test('displays V2 tenant-scoped SP URLs when creating SAML provider', async ({ page }) => {
    await mockAuthMe(page)
    await mockTenantSettings(page)
    await mockSsoProviders(page)
    await mockSpInfo(page)

    await seedBearer(page)

    // Navigate to admin settings
    await page.goto(UI_BASE + '/admin/settings')
    await page.waitForLoadState('networkidle')

    await page.getByTestId('admin-load-settings').click()

    const ssoTab = page.getByTestId('tab-sso')
    await expect(ssoTab).toBeVisible({ timeout: 10000 })
    await ssoTab.click()

    // Click Create Provider button
    const createBtn = page.getByTestId('sso-create')
    await expect(createBtn).toBeVisible({ timeout: 5000 })
    await createBtn.click()

    // Fill in basic info
    await page.fill('input[id="name"]', 'Azure AD SAML')
    await page.fill('input[id="slug"]', 'azuread')

    // Switch to SAML tab
    const samlTab = page.getByRole('tab', { name: /saml/i })
    await samlTab.click()

    // Wait for checklist to appear
    const checklist = page.getByTestId('sso-setup-checklist')
    await expect(checklist).toBeVisible({ timeout: 5000 })

    // Wait for SP URLs to load
    const spUrls = page.getByTestId('sp-info-urls')
    await expect(spUrls).toBeVisible({ timeout: 5000 })

    // Verify SP URLs contain V2 tenant-scoped format
    const entityIdField = page.getByTestId('sp-field-sp-entity-id')
    await expect(entityIdField).toBeVisible()
    await expect(entityIdField).toContainText('/auth/sso/t/' + TENANT_ID + '/azuread/metadata')

    const acsUrlField = page.getByTestId('sp-field-acs-url')
    await expect(acsUrlField).toBeVisible()
    await expect(acsUrlField).toContainText('/auth/sso/t/' + TENANT_ID + '/azuread/callback')

    const sloUrlField = page.getByTestId('sp-field-slo-url')
    await expect(sloUrlField).toBeVisible()
    await expect(sloUrlField).toContainText('/auth/sso/t/' + TENANT_ID + '/azuread/logout')

    const metadataUrlField = page.getByTestId('sp-field-metadata-url')
    await expect(metadataUrlField).toBeVisible()
    await expect(metadataUrlField).toContainText('/auth/sso/t/' + TENANT_ID + '/azuread/metadata')
  })

  test('copy buttons work for SP URLs', async ({ page }) => {
    await mockAuthMe(page)
    await mockTenantSettings(page)
    await mockSsoProviders(page)
    await mockSpInfo(page)

    await seedBearer(page)

    await page.goto(UI_BASE + '/admin/settings')
    await page.waitForLoadState('networkidle')

    await page.getByTestId('admin-load-settings').click()

    await page.getByTestId('tab-sso').click()

    await page.getByTestId('sso-create').click()

    await page.fill('input[id="name"]', 'Test SAML')
    await page.fill('input[id="slug"]', 'test-saml')

    const samlTab = page.getByRole('tab', { name: /saml/i })
    await samlTab.click()

    // Wait for SP URLs to load
    await expect(page.getByTestId('sp-info-urls')).toBeVisible({ timeout: 5000 })

    // Test copy button for Entity ID
    const copyEntityIdBtn = page.getByTestId('copy-sp-entity-id')
    await expect(copyEntityIdBtn).toBeVisible()
    await expect(copyEntityIdBtn).toHaveText('Copy')
    
    // Click copy and verify it changes to "Copied!"
    await copyEntityIdBtn.click()
    await expect(copyEntityIdBtn).toHaveText('Copied!')
    
    // Wait for it to reset back to "Copy"
    await expect(copyEntityIdBtn).toHaveText('Copy', { timeout: 3000 })
  })

  test('shows error when SP info fetch fails', async ({ page }) => {
    await mockAuthMe(page)
    await mockTenantSettings(page)
    await mockSsoProviders(page)
    await mockSpInfo(page, { 
      shouldFail: true, 
      errorMessage: 'base URL is not configured' 
    })

    await seedBearer(page)

    await page.goto(UI_BASE + '/admin/settings')
    await page.waitForLoadState('networkidle')

    await page.getByTestId('admin-load-settings').click()

    await page.getByTestId('tab-sso').click()

    await page.getByTestId('sso-create').click()

    await page.fill('input[id="name"]', 'Test SAML')
    await page.fill('input[id="slug"]', 'test-saml')

    const samlTab = page.getByRole('tab', { name: /saml/i })
    await samlTab.click()

    // Wait for error to appear
    const errorAlert = page.getByTestId('sp-info-error')
    await expect(errorAlert).toBeVisible({ timeout: 5000 })
    await expect(errorAlert).toContainText('base URL is not configured')
  })

  test('checklist items can be toggled and shows ready state', async ({ page }) => {
    await mockAuthMe(page)
    await mockTenantSettings(page)
    await mockSsoProviders(page)
    await mockSpInfo(page)

    await seedBearer(page)

    await page.goto(UI_BASE + '/admin/settings')
    await page.waitForLoadState('networkidle')

    await page.getByTestId('admin-load-settings').click()

    await page.getByTestId('tab-sso').click()

    await page.getByTestId('sso-create').click()

    await page.fill('input[id="name"]', 'Test SAML')
    await page.fill('input[id="slug"]', 'test-saml')

    const samlTab = page.getByRole('tab', { name: /saml/i })
    await samlTab.click()

    const checklist = page.getByTestId('sso-setup-checklist')
    await expect(checklist).toBeVisible({ timeout: 5000 })

    // Initially, "Ready to proceed" should not be visible
    await expect(page.getByText(/ready to proceed/i)).not.toBeVisible()

    // Find and click all checkboxes
    const checkboxes = checklist.locator('input[type="checkbox"]')
    const count = await checkboxes.count()
    expect(count).toBe(3)

    // Toggle all checkboxes
    for (let i = 0; i < count; i++) {
      await checkboxes.nth(i).click()
    }

    // Verify success message appears
    await expect(page.getByText(/ready to proceed/i)).toBeVisible()
  })

  test('shows loading state while fetching SP info', async ({ page }) => {
    await mockAuthMe(page)
    await mockTenantSettings(page)
    await mockSsoProviders(page)
    
    // Delay the SP info response
    await page.route('**/api/v1/sso/sp-info**', async (route) => {
      const req = route.request()
      if (req.method() === 'OPTIONS') {
        return route.fulfill({
          status: 204,
          headers: cors({
            'access-control-allow-methods': 'GET,OPTIONS',
            'access-control-allow-headers':
              'content-type,authorization,accept,x-guard-client'
          })
        })
      }
      
      // Add delay to see loading state
      await new Promise(resolve => setTimeout(resolve, 500))
      
      const url = new URL(req.url())
      const slug = url.searchParams.get('slug') || 'test'
      
      return route.fulfill({
        status: 200,
        body: JSON.stringify({
          entity_id: 'http://localhost:8080/auth/sso/t/' + TENANT_ID + '/' + slug + '/metadata',
          acs_url: 'http://localhost:8080/auth/sso/t/' + TENANT_ID + '/' + slug + '/callback',
          slo_url: 'http://localhost:8080/auth/sso/t/' + TENANT_ID + '/' + slug + '/logout',
          metadata_url: 'http://localhost:8080/auth/sso/t/' + TENANT_ID + '/' + slug + '/metadata',
          login_url: 'http://localhost:8080/auth/sso/t/' + TENANT_ID + '/' + slug + '/login',
          base_url: 'http://localhost:8080',
          tenant_id: TENANT_ID
        }),
        headers: cors({ 'content-type': 'application/json' })
      })
    })

    await seedBearer(page)

    await page.goto(UI_BASE + '/admin/settings')
    await page.waitForLoadState('networkidle')

    await page.getByTestId('admin-load-settings').click()
    await page.getByTestId('tab-sso').click()
    await page.getByTestId('sso-create').click()

    await page.fill('input[id="name"]', 'Test SAML')
    await page.fill('input[id="slug"]', 'test-saml')

    const samlTab = page.getByRole('tab', { name: /saml/i })
    await samlTab.click()

    // Should show loading state
    const loadingIndicator = page.getByTestId('sp-info-loading')
    await expect(loadingIndicator).toBeVisible({ timeout: 2000 })

    // Then should show the URLs
    await expect(page.getByTestId('sp-info-urls')).toBeVisible({ timeout: 5000 })
  })

  test('SP URLs update when slug changes', async ({ page }) => {
    await mockAuthMe(page)
    await mockTenantSettings(page)
    await mockSsoProviders(page)
    await mockSpInfo(page)

    await seedBearer(page)

    await page.goto(UI_BASE + '/admin/settings')
    await page.waitForLoadState('networkidle')

    await page.getByTestId('admin-load-settings').click()

    await page.getByTestId('tab-sso').click()

    await page.getByTestId('sso-create').click()

    await page.fill('input[id="name"]', 'Test SAML')
    await page.fill('input[id="slug"]', 'okta')

    const samlTab = page.getByRole('tab', { name: /saml/i })
    await samlTab.click()

    // Wait for SP URLs with 'okta' slug
    await expect(page.getByTestId('sp-info-urls')).toBeVisible({ timeout: 5000 })
    await expect(page.getByTestId('sp-field-sp-entity-id')).toContainText('/okta/metadata')

    // Change the slug
    await page.fill('input[id="slug"]', 'azure-ad')

    // Wait for SP URLs to update with new slug
    await expect(page.getByTestId('sp-field-sp-entity-id')).toContainText('/azure-ad/metadata', { timeout: 5000 })
    await expect(page.getByTestId('sp-field-acs-url')).toContainText('/azure-ad/callback')
  })
})
