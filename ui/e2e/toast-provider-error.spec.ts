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
  await page.addInitScript((url) => {
    localStorage.setItem('guard_config', JSON.stringify({ guard_base_url: url }))
  }, baseUrl)
}

test.describe('Toast Provider integration (error case)', () => {
  test('shows error toast on failed settings save with data-testid', async ({ page }) => {
    await seedTenantContext(page, 'tenant_err', 'Error Inc')
    await seedGuardConfigFromQuery(page, 'http://localhost:4173')

    // Mock load settings
    await page.route('**/api/v1/tenants/tenant_err/settings', async route => {
      if (route.request().method() === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            settings: {
              auth_access_token_ttl: '15m',
              auth_refresh_token_ttl: '720h',
              app_cors_allowed_origins: 'https://app.example.com'
            }
          })
        })
      } else {
        await route.fallback()
      }
    })

    // Mock update to fail (PUT 500)
    await page.route('**/api/v1/tenants/tenant_err/settings', async route => {
      if (route.request().method() === 'PUT') {
        await route.fulfill({ status: 500, contentType: 'application/json', body: JSON.stringify({ error: 'boom' }) })
      } else {
        await route.fallback()
      }
    })

    await page.goto(`${UI_BASE}/admin/tenants/tenant_err/settings?guard-base-url=${encodeURIComponent('http://localhost:4173')}`)

    await expect(page.locator('[data-testid="settings-loading"]')).not.toBeVisible()

    // Trigger unsaved changes
    await expect(page.locator('[data-testid="access-token-ttl"]')).toBeVisible()
    await page.selectOption('[data-testid="access-token-ttl"]', '30m')
    await expect(page.locator('[data-testid="unsaved-changes"]')).toBeVisible()

    // Save and expect error toast
    await page.click('[data-testid="save-settings"]')
    await expect(page.getByTestId('settings-error-toast')).toBeVisible()
  })
})
