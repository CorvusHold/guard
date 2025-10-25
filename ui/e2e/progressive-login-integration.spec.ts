import { test, expect } from '@playwright/test'
import { ProgressiveLoginHelpers } from './utils/progressive-login-helpers'

test.describe('Progressive Login Integration Tests', () => {
  let helpers: ProgressiveLoginHelpers

  test.beforeEach(async ({ page }) => {
    helpers = new ProgressiveLoginHelpers(page)
    
    // Navigate to app root and configure Guard first
    await page.goto('/')
    
    // Check if configuration is needed
    const baseUrlInput = page.locator('[data-testid="base-url-input"]')
    if (await baseUrlInput.isVisible()) {
      // Configure Guard with test base URL
      await baseUrlInput.fill('http://localhost:8081')
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
      
      // Should redirect to dashboard after successful login
      await expect(page).toHaveURL(/.*\/dashboard/)
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

      await helpers.verifyOptionsStep('john.doe@gmial.com', false)
      await helpers.verifyEmailSuggestions(['john.doe@gmail.com'])

      // Test tenant creation flow
      await page.click('[data-testid="create-tenant-button"]')
      await expect(page).toHaveURL(/.*\/tenant\/create/)
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

      await helpers.verifyOptionsStep('newuser@acme.com', true)
      
      // Should show create account option for specific tenant
      await expect(page.locator('[data-testid="create-account-button"]')).toContainText('Create Account in Acme Corp')
      
      await page.click('[data-testid="create-account-button"]')
      await expect(page).toHaveURL(/.*\/signup/)
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
      await expect(page).toHaveURL(/.*\/dashboard/)
    })

    test('should handle email suggestion correction flow', async ({ page }) => {
      // First API call - typo email not found
      await page.route('**/v1/auth/email/discover', async (route, request) => {
        const body = await request.postData()
        const { email } = JSON.parse(body || '{}')
        
        if (email === 'user@gmial.com') {
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
              found: false,
              has_tenant: false,
              user_exists: false,
              suggestions: ['user@gmail.com']
            })
          })
        } else if (email === 'user@gmail.com') {
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
              found: true,
              has_tenant: true,
              tenant_id: 'tenant-123',
              tenant_name: 'Gmail Corp',
              user_exists: true
            })
          })
        }
      })

      await helpers.mockLogin(true)

      // Enter typo email
      await helpers.enterEmail('user@gmial.com')
      await helpers.waitForEmailDiscovery()

      // Should show suggestions
      await helpers.verifyOptionsStep('user@gmial.com', false)
      await helpers.verifyEmailSuggestions(['user@gmail.com'])

      // Click suggestion
      await helpers.clickEmailSuggestion('user@gmail.com')
      await helpers.waitForEmailDiscovery()

      // Should proceed to password step
      await helpers.verifyPasswordStep('user@gmail.com', 'Gmail Corp')

      // Complete login
      await helpers.enterPasswordAndLogin('password123')
      await expect(page).toHaveURL(/.*\/dashboard/)
    })
  })

  test.describe('Error Recovery Flows', () => {
    test('should recover from API errors', async ({ page }) => {
      // First attempt fails
      let attemptCount = 0
      await page.route('**/v1/auth/email/discover', async route => {
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
              found: true,
              has_tenant: true,
              tenant_id: 'tenant-123',
              user_exists: true
            })
          })
        }
      })

      await helpers.enterEmail('user@example.com')
      await helpers.verifyError('email-error', 'Failed to check email')

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
      await page.route('**/v1/auth/password/login', async route => {
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
      
      await expect(page).toHaveURL(/.*\/dashboard/)
    })

    test('should handle network connectivity issues', async ({ page }) => {
      // Simulate network failure then recovery
      let networkDown = true
      await page.route('**/v1/auth/email/discover', async route => {
        if (networkDown) {
          await route.abort('failed')
        } else {
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
              found: true,
              has_tenant: true,
              tenant_id: 'tenant-123',
              user_exists: true
            })
          })
        }
      })

      await helpers.enterEmail('user@example.com')
      await helpers.verifyError('email-error', 'Failed to check email')

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
      await helpers.verifyLoadingState('Checking email...')
      
      // Should eventually show password step
      await helpers.verifyPasswordStep('user@example.com')
    })

    test('should debounce rapid email changes', async ({ page }) => {
      let apiCallCount = 0
      await page.route('**/v1/auth/email/discover', async route => {
        apiCallCount++
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            found: true,
            has_tenant: true,
            tenant_id: 'tenant-123',
            user_exists: true
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
      await page.route('**/v1/auth/email/discover', async route => {
        apiCalled = true
        await route.fulfill({ status: 200, body: '{}' })
      })

      await page.fill('[data-testid="email-input"]', 'invalid-email')
      await page.click('[data-testid="continue-button"]')

      await helpers.verifyError('email-error', 'Please enter a valid email address')
      expect(apiCalled).toBe(false)
    })

    test('should sanitize email input', async ({ page }) => {
      await helpers.mockEmailDiscovery({
        found: true,
        has_tenant: true,
        tenant_id: 'tenant-123',
        user_exists: true
      })

      // Test with spaces and special characters
      await page.fill('[data-testid="email-input"]', '  user@example.com  ')
      await page.click('[data-testid="continue-button"]')

      await helpers.waitForEmailDiscovery()
      
      // Should show trimmed email in success message
      await expect(page.locator('[data-testid="email-success"]')).toContainText('user@example.com')
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

      await helpers.waitForEmailDiscovery()
      
      // Should display escaped content, not execute script
      await expect(page.locator('[data-testid="email-not-found"]')).toContainText(xssPayload)
      
      // Verify no alert was triggered
      page.on('dialog', () => {
        throw new Error('XSS alert should not be triggered')
      })
    })

    test('should handle malformed API responses', async ({ page }) => {
      await page.route('**/v1/auth/email/discover', async route => {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: 'invalid json'
        })
      })

      await helpers.enterEmail('user@example.com')
      await helpers.verifyError('email-error', 'Failed to check email')
    })
  })

  test.describe('Tenant Context Handling', () => {
    test('should send tenant ID in request headers when available', async ({ page }) => {
      await helpers.setTenantContext('tenant-456', 'Test Org')
      await page.reload()

      let requestHeaders: Record<string, string> = {}
      await page.route('**/v1/auth/email/discover', async route => {
        requestHeaders = route.request().headers()
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            found: true,
            has_tenant: true,
            tenant_id: 'tenant-456',
            user_exists: true
          })
        })
      })

      await helpers.enterEmail('user@example.com')
      await helpers.waitForEmailDiscovery()

      expect(requestHeaders['x-tenant-id']).toBe('tenant-456')
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

      await expect(page.locator('[data-testid="create-account-button"]')).toContainText('Create Account in Org 1')

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
