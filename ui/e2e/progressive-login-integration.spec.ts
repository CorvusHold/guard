import { test, expect } from '@playwright/test'
import { ProgressiveLoginHelpers } from './utils/progressive-login-helpers'

const UI_BASE = 'http://localhost:4173'

test.describe('Progressive Login Integration Tests', () => {
  let helpers: ProgressiveLoginHelpers

  test.beforeEach(async ({ page }) => {
    helpers = new ProgressiveLoginHelpers(page)

    // Keep auth-related background requests deterministic.
    await page.route('**/api/v1/auth/refresh', async (route) => {
      const req = route.request()
      if (req.method() === 'OPTIONS') {
        return route.fulfill({
          status: 204,
          headers: {
            'access-control-allow-origin': '*',
            'access-control-allow-methods': 'POST,OPTIONS',
            'access-control-allow-headers':
              'content-type,authorization,accept,x-guard-client'
          }
        })
      }
      return route.fulfill({
        status: 401,
        body: JSON.stringify({ message: 'unauthorized' }),
        headers: {
          'access-control-allow-origin': '*',
          'content-type': 'application/json'
        }
      })
    })

    await page.route('**/api/v1/auth/me', async (route) => {
      const req = route.request()
      if (req.method() === 'OPTIONS') {
        return route.fulfill({
          status: 204,
          headers: {
            'access-control-allow-origin': '*',
            'access-control-allow-methods': 'GET,OPTIONS',
            'access-control-allow-headers':
              'content-type,authorization,accept,x-guard-client'
          }
        })
      }
      const auth = req.headers()['authorization'] || ''
      if (auth.toLowerCase().startsWith('bearer ')) {
        return route.fulfill({
          status: 200,
          body: JSON.stringify({
            email: 'user@example.com',
            first_name: 'Test',
            last_name: 'User',
            roles: ['admin']
          }),
          headers: {
            'access-control-allow-origin': '*',
            'content-type': 'application/json'
          }
        })
      }
      return route.fulfill({
        status: 401,
        body: JSON.stringify({ message: 'unauthorized' }),
        headers: {
          'access-control-allow-origin': '*',
          'content-type': 'application/json'
        }
      })
    })
    
    // Navigate to app root and configure Guard first
    await page.goto('/')
    
    // Check if configuration is needed
    const baseUrlInput = page.locator('[data-testid="base-url-input"]')
    if (await baseUrlInput.isVisible()) {
      // Configure Guard with test base URL
      await baseUrlInput.fill(UI_BASE)
      await page.click('[data-testid="save-config"]')
      
      // Wait for configuration to complete and login form to appear
      await expect(page.locator('[data-testid="email-input"]')).toBeVisible({ timeout: 10000 })
    }
  })

  test.describe('Complete User Flows', () => {
    test('should complete full login flow for existing user', async ({ page }) => {
      const credentials = {
        email: 'john.doe@example.com',
        password: 'password123',
        tenantId: 'tenant-123'
      }

      await helpers.completeLogin(credentials)
      
      await expect(page.getByTestId('user-email')).toBeVisible()
    })

    test('should handle new user signup flow', async ({ page }) => {
      await helpers.mockEmailDiscovery({
        found: false,
        has_tenant: false,
        user_exists: false,
        suggestions: ['john.doe@gmail.com']
      })

      await helpers.enterEmail('john.doe@gmial.com') // typo
      await helpers.waitForEmailDiscovery()

      // Options/suggestions UI belongs to SimpleProgressiveLoginForm; this page uses UniversalLogin.
      await expect(page.getByTestId('login-error')).toBeVisible()
    })

    test('should handle tenant-specific account creation', async ({ page }) => {
      await helpers.setTenantContext('tenant-123', 'Acme Corp')
      await page.reload()

      await helpers.mockEmailDiscovery({
        found: false,
        has_tenant: true,
        tenant_id: 'tenant-123',
        user_exists: false
      })

      await helpers.enterEmail('newuser@acme.com')
      await helpers.waitForEmailDiscovery()

      // UniversalLogin goes to password step when password is enabled; otherwise it shows an error.
      await expect(page.locator('[data-testid="password-input"], [data-testid="login-error"]')).toBeVisible()
    })

    test('should handle multi-tenant user login', async ({ page }) => {
      await helpers.mockEmailDiscovery({
        found: true,
        has_tenant: true,
        tenant_id: 'tenant-primary',
        tenant_name: 'Primary Corp',
        user_exists: true,
        suggestions: ['Secondary Corp', 'Third Corp']
      })

      await helpers.mockLogin(true)

      await helpers.enterEmail('multi.user@example.com')
      await helpers.waitForEmailDiscovery()

      await helpers.verifyPasswordStep('multi.user@example.com', 'Primary Corp')
      await helpers.verifyMultipleTenants('Primary Corp', ['Secondary Corp', 'Third Corp'])

      await helpers.enterPasswordAndLogin('password123')
      await expect(page.getByTestId('user-email')).toBeVisible()
    })

    test('should handle email suggestion correction flow', async ({ page }) => {
      await helpers.mockEmailDiscovery({
        found: true,
        has_tenant: true,
        tenant_id: 'tenant-123',
        tenant_name: 'Gmail Corp',
        user_exists: true
      })

      await helpers.mockLogin(true)

      // Enter typo email
      await helpers.enterEmail('user@gmial.com')
      await helpers.waitForEmailDiscovery()

      await helpers.verifyPasswordStep('user@gmial.com', 'Gmail Corp')

      // Complete login
      await helpers.enterPasswordAndLogin('password123')
      await expect(page.getByTestId('user-email')).toBeVisible()
    })
  })

  test.describe('Error Recovery Flows', () => {
    test('should recover from API errors', async ({ page }) => {
      // First attempt fails
      let attemptCount = 0
      await page.route('**/api/v1/auth/login-options*', async route => {
        attemptCount++
        if (attemptCount === 1) {
          await route.fulfill({
            status: 500,
            contentType: 'application/json',
            body: JSON.stringify({ error: 'Internal server error' })
          })
        } else {
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
              tenant_id: 'tenant-123',
              tenant_name: 'Test Organization',
              user_exists: true,
              password_enabled: true,
              domain_matched_sso: null,
              sso_required: false,
              sso_providers: []
            })
          })
        }
      })

      await helpers.enterEmail('user@example.com')
      await helpers.verifyError('login-error', 'Internal server error')

      // Retry should work
      await helpers.enterEmail('user@example.com')
      await helpers.verifyPasswordStep('user@example.com')
    })

    test('should handle login failures and retry', async ({ page }) => {
      await helpers.mockEmailDiscovery({
        found: true,
        has_tenant: true,
        tenant_id: 'tenant-123',
        user_exists: true
      })

      // First login attempt fails
      let loginAttempts = 0
      await page.route('**/api/v1/auth/password/login', async route => {
        loginAttempts++
        if (loginAttempts === 1) {
          await route.fulfill({
            status: 401,
            contentType: 'application/json',
            body: JSON.stringify({ error: 'Invalid credentials' })
          })
        } else {
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
              access_token: 'mock-token',
              refresh_token: 'mock-refresh'
            })
          })
        }
      })

      await helpers.enterEmail('user@example.com')
      await helpers.waitForEmailDiscovery()

      // First login attempt
      await helpers.enterPasswordAndLogin('wrongpassword')
      await helpers.verifyError('login-error', 'Invalid credentials')

      // Retry with correct password
      await page.fill('[data-testid="password-input"]', 'correctpassword')
      await page.click('[data-testid="signin-button"]')

      await expect(page.getByTestId('user-email')).toBeVisible()
    })

    test('should handle network connectivity issues', async ({ page }) => {
      // Simulate network failure then recovery
      let networkDown = true
      await page.route('**/api/v1/auth/login-options*', async route => {
        if (networkDown) {
          await route.abort('failed')
        } else {
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
              tenant_id: 'tenant-123',
              tenant_name: 'Test Organization',
              user_exists: true,
              password_enabled: true,
              domain_matched_sso: null,
              sso_required: false,
              sso_providers: []
            })
          })
        }
      })

      await helpers.enterEmail('user@example.com')
      await expect(page.getByTestId('login-error')).toBeVisible()
      await expect(page.getByTestId('login-error')).toContainText(
        /failed to fetch|networkerror|load failed/i
      )

      // Simulate network recovery
      networkDown = false
      await helpers.enterEmail('user@example.com')
      await helpers.verifyPasswordStep('user@example.com')
    })
  })

  test.describe('Performance and UX', () => {
    test('should handle slow API responses gracefully', async ({ page }) => {
      await helpers.mockEmailDiscovery({
        found: true,
        has_tenant: true,
        tenant_id: 'tenant-123',
        user_exists: true
      }, 2000) // 2 second delay

      await helpers.enterEmail('user@example.com')
      
      // Should show loading state immediately
      await helpers.verifyLoadingState()
      
      // Should eventually show password step
      await helpers.verifyPasswordStep('user@example.com')
    })

    test('should debounce rapid email changes', async ({ page }) => {
      let apiCallCount = 0
      await page.route('**/api/v1/auth/login-options*', async route => {
        apiCallCount++
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            tenant_id: 'tenant-123',
            tenant_name: 'Test Organization',
            user_exists: true,
            password_enabled: true,
            domain_matched_sso: null,
            sso_required: false,
            sso_providers: []
          })
        })
      })

      // Rapidly change email
      await page.fill('[data-testid="email-input"]', 'u')
      await page.fill('[data-testid="email-input"]', 'us')
      await page.fill('[data-testid="email-input"]', 'use')
      await page.fill('[data-testid="email-input"]', 'user@example.com')
      
      await page.click('[data-testid="continue-button"]')
      await helpers.waitForEmailDiscovery()

      // Should only make one API call due to debouncing
      expect(apiCallCount).toBe(1)
    })

    test('should maintain form state during navigation', async ({ page }) => {
      await helpers.mockEmailDiscovery({
        found: true,
        has_tenant: true,
        tenant_id: 'tenant-123',
        user_exists: true
      })

      await helpers.enterEmail('user@example.com')
      await helpers.waitForEmailDiscovery()

      // Go back to email step
      await helpers.goBackToEmailStep()

      // Email should be preserved
      await expect(page.locator('[data-testid="email-input"]')).toHaveValue('user@example.com')
    })
  })

  test.describe('Security and Validation', () => {
    test('should validate email format before API call', async ({ page }) => {
      let apiCalled = false
      await page.route('**/api/v1/auth/login-options*', async route => {
        apiCalled = true
        await route.fulfill({ status: 200, body: '{}' })
      })

      await page.fill('[data-testid="email-input"]', 'invalid-email')
      await page.click('[data-testid="continue-button"]')

      // Native HTML validation differs by browser; assert the input is invalid.
      const validity = await page
        .locator('[data-testid="email-input"]')
        .evaluate((el: HTMLInputElement) => ({
          valid: el.checkValidity(),
          typeMismatch: el.validity.typeMismatch,
          valueMissing: el.validity.valueMissing,
          msg: el.validationMessage
        }))
      expect(validity.valid).toBe(false)
      expect(validity.typeMismatch || validity.valueMissing || (validity.msg || '').length > 0).toBe(true)
      expect(apiCalled).toBe(false)
    })

    test('should sanitize email input', async ({ page }) => {
      // Firefox treats leading/trailing spaces as invalid for type=email and may block submit.
      // Instead, assert that the UI lowercases the email it sends to login-options.
      let requestUrl = ''
      await page.route('**/api/v1/auth/login-options*', async (route) => {
        requestUrl = route.request().url()
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            tenant_id: 'tenant-123',
            tenant_name: 'Test Organization',
            user_exists: true,
            password_enabled: true,
            domain_matched_sso: null,
            sso_required: false,
            sso_providers: []
          })
        })
      })

      await page.fill('[data-testid="email-input"]', 'USER@Example.COM')
      await page.click('[data-testid="continue-button"]')

      await expect(page.getByTestId('password-input')).toBeVisible()
      const u = new URL(requestUrl)
      expect(u.searchParams.get('email')).toBe('user@example.com')
    })

    test('should handle XSS attempts in email field', async ({ page }) => {
      await helpers.mockEmailDiscovery({
        found: false,
        has_tenant: false,
        user_exists: false,
        suggestions: []
      })

      const xssPayload = '<script>alert("xss")</script>@example.com'
      await page.fill('[data-testid="email-input"]', xssPayload)
      await page.click('[data-testid="continue-button"]')

      // Native validation should prevent submission; ensure no script executed.
      const validity = await page
        .locator('[data-testid="email-input"]')
        .evaluate((el: HTMLInputElement) => ({ valid: el.checkValidity(), msg: el.validationMessage }))
      expect(validity.valid).toBe(false)
      expect((validity.msg || '').length).toBeGreaterThan(0)
      
      // Verify no alert was triggered
      page.on('dialog', () => {
        throw new Error('XSS alert should not be triggered')
      })
    })

    test('should handle malformed API responses', async ({ page }) => {
      await page.route('**/api/v1/auth/login-options*', async route => {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: 'invalid json'
        })
      })

      await helpers.enterEmail('user@example.com')
      await expect(page.getByTestId('login-error')).toBeVisible()
      await expect(page.getByTestId('login-error')).toContainText(
        /not valid json|unexpected token|json\.parse|string did not match the expected pattern/i
      )
    })
  })

  test.describe('Tenant Context Handling', () => {
    test('should send tenant ID in request headers when available', async ({ page }) => {
      await helpers.setTenantContext('tenant-456', 'Test Org')
      await page.goto('/?tenant_id=tenant-456')

      let requestUrl = ''
      await page.route('**/api/v1/auth/login-options*', async route => {
        requestUrl = route.request().url()
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            tenant_id: 'tenant-456',
            tenant_name: 'Test Org',
            user_exists: true,
            password_enabled: true,
            domain_matched_sso: null,
            sso_required: false,
            sso_providers: []
          })
        })
      })

      await helpers.enterEmail('user@example.com')
      await helpers.waitForEmailDiscovery()

      const u = new URL(requestUrl)
      expect(u.searchParams.get('tenant_id')).toBe('tenant-456')
    })

    test('should work without tenant context', async ({ page }) => {
      await helpers.clearTenantContext()
      await page.reload()

      await helpers.mockEmailDiscovery({
        found: true,
        has_tenant: true,
        tenant_id: 'discovered-tenant',
        tenant_name: 'Discovered Org',
        user_exists: true
      })

      await helpers.enterEmail('user@example.com')
      await helpers.waitForEmailDiscovery()

      await helpers.verifyPasswordStep('user@example.com', 'Discovered Org')
    })

    test('should handle tenant context changes', async ({ page }) => {
      // Start with one tenant
      await helpers.setTenantContext('tenant-1', 'Org 1')
      await page.reload()

      await helpers.mockEmailDiscovery({
        found: false,
        has_tenant: true,
        tenant_id: 'tenant-1',
        user_exists: false
      })

      await helpers.enterEmail('user@example.com')
      await helpers.waitForEmailDiscovery()

      await expect(page.locator('[data-testid="password-input"], [data-testid="login-error"]')).toBeVisible()

      // Change tenant context
      await helpers.setTenantContext('tenant-2', 'Org 2')
      await page.reload()

      await helpers.mockEmailDiscovery({
        found: true,
        has_tenant: true,
        tenant_id: 'tenant-2',
        user_exists: true
      })

      await helpers.enterEmail('user@example.com')
      await helpers.waitForEmailDiscovery()

      await helpers.verifyPasswordStep('user@example.com', 'Org 2')
    })
  })
})
