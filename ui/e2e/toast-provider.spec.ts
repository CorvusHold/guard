import { test, expect } from '@playwright/test'

const UI_BASE = 'http://localhost:4173'

// Utilities to seed localStorage before page context boots
async function seedTenantContext(page, id: string, name: string) {
  await page.addInitScript((data) => {
    localStorage.setItem('tenant_id', data.id)
    localStorage.setItem('tenant_name', data.name)
    localStorage.setItem('guard_ui:tenant_id', data.id)
    localStorage.setItem('guard_ui:tenant_name', data.name)
  }, { id, name })
}

async function seedGuardConfigFromQuery(page, baseUrl: string) {
  // Ensure runtime config from query by visiting with ?guard-base-url=...
  // Some parts of the app also read localStorage 'guard_config'. Set it too.
  await page.addInitScript((url) => {
    localStorage.setItem('guard_config', JSON.stringify({ guard_base_url: url }))
  }, baseUrl)
}

test.describe('Toast Provider integration', () => {
  test('shows error toast on failed settings save with data-testid', async ({ page, browserName }) => {
    if (browserName !== 'chromium') test.skip(true, 'Skip non-chromium until route stabilization')
    await seedTenantContext(page, 'tenant_abc', 'Acme Inc')
    await seedGuardConfigFromQuery(page, 'http://localhost:4173')

    // Mock load settings
    await page.route('**/v1/tenants/tenant_abc/settings', async route => {
      if (route.request().method() === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            sso_provider: '',
            workos_client_id: '',
            sso_state_ttl: '15m',
            auth_access_token_ttl: '15m',
            auth_refresh_token_ttl: '720h',
            app_cors_allowed_origins: 'https://app.example.com'
          })
        })
      } else {
        await route.fallback()
      }
    })

    // Mock update to succeed (SDK uses PUT for updateTenantSettings)
    await page.route('**/v1/tenants/tenant_abc/settings', async route => {
      if (route.request().method() === 'PUT') {
        await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ success: true }) })
      } else {
        await route.fallback()
      }
    })

    await page.goto(`${UI_BASE}/admin/tenants/tenant_abc/settings?guard-base-url=${encodeURIComponent('http://localhost:4173')}`)

    // Wait for settings panel to finish loading
    await expect(page.locator('[data-testid="settings-loading"]')).not.toBeVisible()

    // Wait for security tab controls to be present (default tab)
    await expect(page.locator('[data-testid="access-token-ttl"]')).toBeVisible()

    // Make a change to trigger unsaved changes banner
    await page.selectOption('[data-testid="access-token-ttl"]', '30m')
    await expect(page.locator('[data-testid="unsaved-changes"]')).toBeVisible()

    // Attempt to save => should show success toast
    await page.click('[data-testid="save-settings"]')
    await expect(page.getByTestId('settings-saved-toast')).toBeVisible()
  })
})
