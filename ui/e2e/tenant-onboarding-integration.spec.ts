import { expect, test } from '@playwright/test'

const UI_BASE = 'http://localhost:4173'
const API_BASE = 'http://localhost:8080'

function cors(headers: Record<string, string> = {}) {
  return {
    'access-control-allow-origin': '*',
    'access-control-expose-headers': 'location,x-request-id,content-type',
    'content-type': 'application/json',
    ...headers
  }
}

test.describe('Tenant Onboarding Integration', () => {
  test.beforeEach(async ({ page, context }) => {
    await page.addInitScript((apiBase: string) => {
      localStorage.setItem(
        'guard_runtime',
        JSON.stringify({
          guard_base_url: apiBase,
          source: 'e2e',
          auth_mode: 'bearer'
        })
      )
      localStorage.setItem('guard_ui:guard_access_token', 'e2e-access-token')
      localStorage.setItem('guard_ui:guard_refresh_token', 'e2e-refresh-token')
    }, API_BASE)

    // Console logging for debugging
    page.on('console', (msg) => {
      const loc = msg.location()
      console.log(
        `PAGE CONSOLE [${msg.type()}]`,
        msg.text(),
        loc?.url ? `@ ${loc.url}:${loc.lineNumber}:${loc.columnNumber}` : ''
      )
    })
    page.on('pageerror', (err) => {
      console.log('PAGE ERROR', err?.message || String(err))
    })
    
    // Network request logging
    page.on('request', (req) => {
      if (req.url().includes('/api/v1/'))
        console.log('REQ', req.method(), req.url())
    })
    page.on('response', async (res) => {
      if (res.url().includes('/api/v1/'))
        console.log('RES', res.status(), res.url())
    })

    await page.route('**/api/v1/auth/me', async (route) => {
      const req = route.request()
      if (req.method() === 'OPTIONS') {
        return route.fulfill({ status: 204, headers: cors() })
      }
      return route.fulfill({
        status: 200,
        headers: cors({ 'content-type': 'application/json' }),
        body: JSON.stringify({ id: 'user_e2e', email: 'e2e@example.com' })
      })
    })
  })

  test('complete tenant onboarding wizard flow', async ({ page }) => {
    const tenantId = `tenant_${Date.now()}`
    const adminEmail = `admin_${Date.now()}@example.com`
    
    // Mock tenant creation API
    await page.route(`${API_BASE}/api/v1/tenants`, async (route) => {
      if (route.request().method() === 'POST') {
        const requestBody = await route.request().postDataJSON()
        expect(requestBody.name).toBeTruthy()
        
        await route.fulfill({
          status: 201,
          headers: cors(),
          body: JSON.stringify({
            id: tenantId,
            name: requestBody.name,
            is_active: true,
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString()
          })
        })
      }
    })

    // Mock admin user creation API
    await page.route(`${API_BASE}/api/v1/auth/password/signup`, async (route) => {
      const requestBody = await route.request().postDataJSON()
      expect(requestBody.email).toBe(adminEmail)
      expect(requestBody.password).toBeTruthy()
      
      await route.fulfill({
        status: 201,
        headers: cors({ 'x-tenant-id': tenantId }),
        body: JSON.stringify({
          user_id: `user_${Date.now()}`,
          email: requestBody.email,
          first_name: requestBody.first_name,
          last_name: requestBody.last_name
        })
      })
    })

    // Mock tenant settings update API
    await page.route(`${API_BASE}/api/v1/tenants/${tenantId}/settings`, async (route) => {
      if (route.request().method() === 'PUT') {
        const requestBody = await route.request().postDataJSON()
        console.log('Settings update:', requestBody)
        
        await route.fulfill({
          status: 200,
          headers: cors(),
          body: JSON.stringify({ success: true })
        })
      }
    })

    // Navigate to tenant onboarding wizard
    await page.goto(`${UI_BASE}/admin/tenants/onboard`)
    
    // Step 1: Tenant Details
    await expect(page.locator('[data-testid="onboarding-step-1"]')).toBeVisible()
    await page.fill('[data-testid="tenant-name"]', 'Test Company Inc')
    await page.click('[data-testid="next-step"]')

    // Step 2: Admin User Creation
    await expect(page.locator('[data-testid="onboarding-step-2"]')).toBeVisible()
    await page.fill('[data-testid="admin-email"]', adminEmail)
    await page.fill('[data-testid="admin-password"]', 'SecurePass123!')
    await page.fill('[data-testid="admin-first-name"]', 'Admin')
    await page.fill('[data-testid="admin-last-name"]', 'User')
    await page.check('[data-testid="enable-mfa"]')
    await page.click('[data-testid="next-step"]')

    // Step 3: Tenant Settings
    await expect(page.locator('[data-testid="onboarding-step-3"]')).toBeVisible()
    
    // Security settings tab
    await page.click('[data-testid="settings-tab-security"]')
    await page.selectOption('[data-testid="access-token-ttl"]', '30m')
    await page.selectOption('[data-testid="refresh-token-ttl"]', '720h')
    
    // CORS settings tab
    await page.click('[data-testid="settings-tab-cors"]')
    await page.fill('[data-testid="cors-origins"]', 'https://app.testcompany.com,https://admin.testcompany.com')
    
    // SSO settings tab
    await page.click('[data-testid="settings-tab-sso"]')
    await page.selectOption('[data-testid="sso-provider"]', 'workos')
    await page.fill('[data-testid="workos-client-id"]', 'client_test123')
    await page.fill('[data-testid="workos-client-secret"]', 'wk_test_secret')
    
    await page.click('[data-testid="next-step"]')

    // Step 4: Review and Confirm
    await expect(page.locator('[data-testid="onboarding-step-4"]')).toBeVisible()
    
    // Verify tenant details are displayed
    await expect(page.locator('[data-testid="review-tenant-name"]')).toContainText('Test Company Inc')
    await expect(page.locator('[data-testid="review-admin-email"]')).toContainText(adminEmail)
    await expect(page.locator('[data-testid="review-mfa-enabled"]')).toContainText('Yes')
    
    // Verify settings are displayed
    await expect(page.locator('[data-testid="review-access-token-ttl"]')).toContainText('30m')
    await expect(page.locator('[data-testid="review-sso-provider"]')).toContainText('WorkOS')
    
    // Complete onboarding
    await page.click('[data-testid="complete-onboarding"]')
    
    // Verify success message
    await expect(page.locator('[data-testid="onboarding-success"]')).toBeVisible()
    await expect(page.locator('[data-testid="tenant-id-display"]')).toContainText(tenantId)
    
    // Verify copy-to-clipboard functionality
    await page.click('[data-testid="copy-tenant-id"]')
    await expect(page.locator('[data-testid="copy-success-toast"]')).toBeVisible()
  })

  test('tenant settings management integration', async ({ page }) => {
    const tenantId = 'test-tenant-123'
    
    // Mock get tenant settings API
    await page.route(`${API_BASE}/api/v1/tenants/${tenantId}/settings`, async (route) => {
      if (route.request().method() === 'GET') {
        await route.fulfill({
          status: 200,
          headers: cors(),
          body: JSON.stringify({
            settings: {
              auth_access_token_ttl: '15m',
              auth_refresh_token_ttl: '720h',
              app_cors_allowed_origins: 'https://app.example.com',
              sso_provider: 'workos',
              sso_workos_client_id: 'client_123',
              email_provider: 'smtp',
              email_smtp_host: 'smtp.gmail.com',
              email_smtp_port: '587'
            }
          })
        })
      } else if (route.request().method() === 'PUT') {
        const requestBody = await route.request().postDataJSON()
        console.log('Settings update:', requestBody)
        
        await route.fulfill({
          status: 200,
          headers: cors(),
          body: JSON.stringify({ success: true })
        })
      }
    })

    // Navigate to tenant settings
    await page.goto(`${UI_BASE}/admin/tenants/${tenantId}/settings`)
    
    // Wait for settings to load
    await expect(page.locator('[data-testid="settings-loading"]')).not.toBeVisible()
    
    // Verify settings are loaded correctly
    await expect(page.locator('[data-testid="access-token-ttl"]')).toHaveValue('15m')

    // CORS field lives under the CORS tab
    await page.click('[data-testid="settings-tab-cors"]')
    await expect(page.locator('[data-testid="cors-origins"]')).toHaveValue('https://app.example.com')
    
    // Test security settings update
    await page.click('[data-testid="settings-tab-security"]')
    await page.selectOption('[data-testid="access-token-ttl"]', '30m')
    await page.selectOption('[data-testid="login-rate-limit"]', '15')
    
    // Test CORS settings update
    await page.click('[data-testid="settings-tab-cors"]')
    await page.fill('[data-testid="cors-origins"]', 'https://app.example.com,https://admin.example.com')
    
    // Test SSO settings update
    await page.click('[data-testid="settings-tab-sso"]')
    await page.fill('[data-testid="workos-client-secret"]', 'new_secret_value')
    
    // Verify unsaved changes indicator
    await expect(page.locator('[data-testid="unsaved-changes"]')).toBeVisible()
    
    // Save settings
    await page.click('[data-testid="save-settings"]')
    
    // Verify success message
    await expect(page.locator('[data-testid="settings-saved-toast"]')).toBeVisible()
    await expect(page.locator('[data-testid="unsaved-changes"]')).not.toBeVisible()
  })

  test('tenant dashboard integration', async ({ page }) => {
    const tenantId = 'dashboard-tenant-123'

    await page.route(`${API_BASE}/api/v1/tenants/${tenantId}/settings`, async (route) => {
      const req = route.request()
      if (req.method() === 'OPTIONS') {
        return route.fulfill({ status: 204, headers: cors() })
      }
      return route.fulfill({
        status: 200,
        headers: cors(),
        body: JSON.stringify({ settings: {} })
      })
    })
    
    // Mock tenant info API
    await page.route(`${API_BASE}/api/v1/tenants/${tenantId}`, async (route) => {
      await route.fulfill({
        status: 200,
        headers: cors(),
        body: JSON.stringify({
          id: tenantId,
          name: 'Dashboard Test Tenant',
          is_active: true,
          created_at: '2024-01-15T10:30:00Z',
          updated_at: '2024-01-15T10:30:00Z'
        })
      })
    })

    // Mock tenant statistics API (would be real endpoints in production)
    await page.route(`${API_BASE}/api/v1/admin/tenants/${tenantId}/stats`, async (route) => {
      await route.fulfill({
        status: 200,
        headers: cors(),
        body: JSON.stringify({
          total_users: 150,
          active_users: 120,
          total_logins_today: 45,
          failed_logins_today: 3,
          mfa_enabled_users: 80,
          sso_configured: true
        })
      })
    })

    // Navigate to tenant dashboard
    await page.goto(`${UI_BASE}/admin/tenants/${tenantId}`)
    
    // Verify tenant info is displayed
    await expect(page.locator('[data-testid="tenant-name"]')).toContainText('Dashboard Test Tenant')
    await expect(page.locator('[data-testid="tenant-id"]')).toContainText(tenantId)
    await expect(page.locator('[data-testid="tenant-status"]')).toContainText('Active')
    
    // Verify statistics cards
    await expect(page.locator('[data-testid="total-users-stat"]')).toContainText('150')
    await expect(page.locator('[data-testid="active-users-stat"]')).toContainText('120')
    await expect(page.locator('[data-testid="logins-today-stat"]')).toContainText('45')
    await expect(page.locator('[data-testid="mfa-users-stat"]')).toContainText('80')
    
    // Test tab navigation
    await page.click('[data-testid="settings-tab"]')
    await expect(page.locator('[data-testid="tenant-settings-panel"]')).toBeVisible()
    
    await page.click('[data-testid="overview-tab"]')
    await expect(page.locator('[data-testid="tenant-overview"]')).toBeVisible()
    
    // Test quick actions
    await page.click('[data-testid="quick-action-settings"]')
    await expect(page.locator('[data-testid="tenant-settings-panel"]')).toBeVisible()
  })

  test('tenant creation panel integration', async ({ page }) => {
    const tenantName = `Test Tenant ${Date.now()}`
    const adminEmail = `admin_${Date.now()}@example.com`
    
    // Mock tenant creation
    await page.route(`${API_BASE}/api/v1/tenants`, async (route) => {
      const requestBody = await route.request().postDataJSON()
      expect(requestBody.name).toBe(tenantName)
      
      await route.fulfill({
        status: 201,
        headers: cors(),
        body: JSON.stringify({
          id: `tenant_${Date.now()}`,
          name: requestBody.name,
          is_active: true,
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString()
        })
      })
    })

    // Mock admin user creation
    await page.route(`${API_BASE}/api/v1/auth/password/signup`, async (route) => {
      const requestBody = await route.request().postDataJSON()
      
      await route.fulfill({
        status: 201,
        headers: cors(),
        body: JSON.stringify({
          user_id: `user_${Date.now()}`,
          email: requestBody.email,
          first_name: requestBody.first_name,
          last_name: requestBody.last_name
        })
      })
    })

    // Navigate to tenant creation
    await page.goto(`${UI_BASE}/admin/tenants/create`)
    
    // Fill tenant creation form
    await page.fill('[data-testid="tenant-name"]', tenantName)
    await page.fill('[data-testid="admin-email"]', adminEmail)
    await page.fill('[data-testid="admin-password"]', 'SecurePass123!')
    await page.fill('[data-testid="admin-first-name"]', 'Admin')
    await page.fill('[data-testid="admin-last-name"]', 'User')
    await page.check('[data-testid="enable-mfa"]')
    
    // Submit form
    await page.click('[data-testid="create-tenant"]')
    
    // Verify success
    await expect(page.locator('[data-testid="creation-success"]')).toBeVisible()
    await expect(page.locator('[data-testid="created-tenant-name"]')).toContainText(tenantName)
  })

  test('error handling and validation', async ({ page }) => {
    // Test API error handling
    await page.route(`${API_BASE}/api/v1/tenants`, async (route) => {
      await route.fulfill({
        status: 400,
        headers: cors(),
        body: JSON.stringify({
          error: 'Tenant name already exists',
          code: 'TENANT_EXISTS'
        })
      })
    })

    await page.goto(`${UI_BASE}/admin/tenants/create`)
    
    // Fill form with duplicate tenant name
    await page.fill('[data-testid="tenant-name"]', 'Existing Tenant')
    await page.fill('[data-testid="admin-first-name"]', 'Admin')
    await page.fill('[data-testid="admin-last-name"]', 'User')
    await page.fill('[data-testid="admin-email"]', 'admin@example.com')
    await page.fill('[data-testid="admin-password"]', 'SecurePass123!')
    
    await page.click('[data-testid="create-tenant"]')
    
    // Verify error message is displayed
    await expect(page.locator('[data-testid="error-message"]')).toContainText('Tenant name already exists')
    
    // Test form validation
    await page.goto(`${UI_BASE}/admin/tenants/onboard`)
    
    // Try to proceed without filling required fields
    await page.click('[data-testid="next-step"]')
    
    // Verify validation errors
    await expect(page.locator('[data-testid="tenant-name-error"]')).toBeVisible()
    
    // Test password validation
    await page.fill('[data-testid="tenant-name"]', 'Valid Tenant')
    await page.click('[data-testid="next-step"]')
    
    await page.fill('[data-testid="admin-email"]', 'invalid-email')
    await page.fill('[data-testid="admin-password"]', '123')
    await page.click('[data-testid="next-step"]')
    
    await expect(page.locator('[data-testid="email-validation-error"]')).toBeVisible()
    await expect(page.locator('[data-testid="password-validation-error"]')).toBeVisible()
  })
})
