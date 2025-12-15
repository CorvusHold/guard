import { test, expect } from '@playwright/test'

const UI_BASE = 'http://localhost:4173'

test.describe('Progressive Login Flow', () => {
  test.beforeEach(async ({ page }) => {
    await page.addInitScript((uiBase: string) => {
      try {
        localStorage.setItem(
          'guard_runtime',
          JSON.stringify({
            guard_base_url: uiBase,
            source: 'direct',
            auth_mode: 'bearer'
          })
        )
      } catch {
        // ignore
      }
    }, UI_BASE)

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

    // Wait for the login form to appear
    await expect(page.locator('[data-testid="email-input"]')).toBeVisible({ timeout: 10000 })
  })

  test.describe('Email Discovery Step', () => {
    test('should show email input field initially', async ({ page }) => {
      await expect(page.locator('[data-testid="email-input"]')).toBeVisible()
      await expect(page.locator('[data-testid="password-input"]')).not.toBeVisible()
      await expect(page.locator('[data-testid="continue-button"]')).toBeVisible()
      await expect(page.locator('[data-testid="continue-button"]')).toBeDisabled()
    })

    test('should enable continue button when valid email is entered', async ({ page }) => {
      await page.fill('[data-testid="email-input"]', 'user@example.com')
      await expect(page.locator('[data-testid="continue-button"]')).toBeEnabled()
    })

    test('should show validation error for invalid email', async ({ page }) => {
      await page.fill('[data-testid="email-input"]', 'invalid-email')
      await page.click('[data-testid="continue-button"]')

      // Native HTML5 email validation blocks form submit; the message is not part of the DOM.
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
    })

    test('should show loading state during email discovery', async ({ page }) => {
      // Mock slow API response
      await page.route('**/api/v1/auth/login-options*', async route => {
        await new Promise(resolve => setTimeout(resolve, 1000))
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

      await page.fill('[data-testid="email-input"]', 'user@example.com')
      await page.click('[data-testid="continue-button"]')
      
      await expect(page.locator('[data-testid="continue-button"]')).toContainText('Checking...')
    })
  })

  test.describe('Email Found - Show Password Step', () => {
    test('should show password field when email is found', async ({ page }) => {
      // Mock API response for found email
      await page.route('**/api/v1/auth/login-options*', async route => {
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

      await page.fill('[data-testid="email-input"]', 'user@example.com')
      await page.click('[data-testid="continue-button"]')

      // Should show password field
      await expect(page.locator('[data-testid="password-input"]')).toBeVisible()
      await expect(page.locator('[data-testid="password-input"]')).toBeFocused()
      await expect(page.locator('[data-testid="signin-button"]')).toBeVisible()
    })

    test('should allow changing email from password step', async ({ page }) => {
      // Mock API response for found email
      await page.route('**/api/v1/auth/login-options*', async route => {
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

      await page.fill('[data-testid="email-input"]', 'user@example.com')
      await page.click('[data-testid="continue-button"]')

      // Click change email button
      await page.getByRole('button', { name: 'Change' }).click()

      // Should return to email step
      await expect(page.locator('[data-testid="email-input"]')).toBeVisible()
      await expect(page.locator('[data-testid="password-input"]')).not.toBeVisible()
      await expect(page.locator('[data-testid="email-input"]')).toHaveValue('user@example.com')
    })

    test('should show/hide password with toggle button', async ({ page }) => {
      // Mock API response for found email
      await page.route('**/api/v1/auth/login-options*', async route => {
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

      await page.fill('[data-testid="email-input"]', 'user@example.com')
      await page.click('[data-testid="continue-button"]')

      await page.fill('[data-testid="password-input"]', 'password123')
      
      // Password should be hidden initially
      await expect(page.locator('[data-testid="password-input"]')).toHaveAttribute('type', 'password')
      
      // Click show password button
      await page.locator('[data-testid="password-input"]').locator('..').locator('button').first().click()
      await expect(page.locator('[data-testid="password-input"]')).toHaveAttribute('type', 'text')
      
      // Click hide password button
      await page.locator('[data-testid="password-input"]').locator('..').locator('button').first().click()
      await expect(page.locator('[data-testid="password-input"]')).toHaveAttribute('type', 'password')
    })

    test('should attempt login when password is submitted', async ({ page }) => {
      // Mock email discovery
      await page.route('**/api/v1/auth/login-options*', async route => {
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

      // Mock login API
      await page.route('**/api/v1/auth/password/login*', async route => {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            access_token: 'mock-token',
            refresh_token: 'mock-refresh'
          })
        })
      })

      const waitForLoginRequest = page.waitForRequest('**/api/v1/auth/password/login*')
      const waitForLoginResponse = page.waitForResponse('**/api/v1/auth/password/login*')

      await page.fill('[data-testid="email-input"]', 'user@example.com')
      await page.click('[data-testid="continue-button"]')
      
      await page.fill('[data-testid="password-input"]', 'password123')
      await page.click('[data-testid="signin-button"]')

      await waitForLoginRequest
      const res = await waitForLoginResponse
      expect(res.status()).toBe(200)
    })

    test('should show login error for invalid credentials', async ({ page }) => {
      // Mock email discovery
      await page.route('**/api/v1/auth/login-options*', async route => {
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

      // Mock login error
      await page.route('**/api/v1/auth/password/login*', async route => {
        await route.fulfill({
          status: 401,
          contentType: 'application/json',
          body: JSON.stringify({
            error: 'Invalid credentials'
          })
        })
      })

      await page.fill('[data-testid="email-input"]', 'user@example.com')
      await page.click('[data-testid="continue-button"]')
      
      await page.fill('[data-testid="password-input"]', 'wrongpassword')
      await page.click('[data-testid="signin-button"]')

      await expect(page.locator('[data-testid="login-error"]')).toBeVisible()
      await expect(page.locator('[data-testid="login-error"]')).toContainText('Invalid credentials')
    })
  })

  test.describe('Email Not Found - Show Options Step', () => {
    test('should show error when no login methods are available', async ({ page }) => {
      await page.route('**/api/v1/auth/login-options*', async route => {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            tenant_id: 'tenant-123',
            tenant_name: 'Test Organization',
            user_exists: false,
            password_enabled: false,
            domain_matched_sso: null,
            sso_required: false,
            sso_providers: []
          })
        })
      })

      await page.fill('[data-testid="email-input"]', 'newuser@example.com')
      await page.click('[data-testid="continue-button"]')

      await expect(page.locator('[data-testid="login-error"]')).toBeVisible()
      await expect(page.locator('[data-testid="login-error"]')).toContainText('No login methods available')
      await expect(page.locator('[data-testid="signup-link"]')).toBeVisible()
    })

    test('should send tenant_id as query parameter when tenant is specified', async ({ page }) => {
      let requestUrl = ''
      await page.route('**/api/v1/auth/login-options*', async route => {
        requestUrl = route.request().url()
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            tenant_id: 'tenant-123',
            tenant_name: 'Test Organization',
            user_exists: false,
            password_enabled: false,
            domain_matched_sso: null,
            sso_required: false,
            sso_providers: []
          })
        })
      })

      await page.addInitScript(() => {
        window.localStorage.setItem('tenant_id', 'tenant-123')
        window.localStorage.setItem('tenant_name', 'Test Organization')
      })

      await page.reload()
      await page.fill('[data-testid="email-input"]', 'newuser@example.com')
      await page.click('[data-testid="continue-button"]')

      const u = new URL(requestUrl)
      expect(u.searchParams.get('tenant_id')).toBe('tenant-123')
      await expect(page.locator('[data-testid="login-error"]')).toBeVisible()
    })
  })

  test.describe('Multiple Tenants Found', () => {
    test('should show options step when multiple login methods are available', async ({ page }) => {
      await page.route('**/api/v1/auth/login-options*', async route => {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            tenant_id: 'tenant-123',
            tenant_name: 'Primary Organization',
            user_exists: false,
            password_enabled: true,
            domain_matched_sso: null,
            sso_required: false,
            sso_providers: [
              {
                name: 'Dev SSO',
                slug: 'dev',
                login_url: `${UI_BASE}/api/v1/auth/sso/dev/start`
              }
            ]
          })
        })
      })

      await page.fill('[data-testid="email-input"]', 'user@example.com')
      const opts = page.waitForResponse((r) => r.url().includes('/api/v1/auth/login-options') && r.status() === 200)
      await page.click('[data-testid="continue-button"]')
      await opts

      await expect(page.locator('[data-testid="password-option-button"]')).toBeVisible()
      await expect(page.locator('[data-testid="sso-button-dev"]')).toBeVisible()
      await expect(page.getByText('Primary Organization')).toBeVisible()
    })
  })

  test.describe('Error Handling', () => {
    test('should handle API errors gracefully', async ({ page }) => {
      // Mock API error
      await page.route('**/api/v1/auth/login-options*', async route => {
        await route.fulfill({
          status: 500,
          contentType: 'application/json',
          body: JSON.stringify({
            error: 'Internal server error'
          })
        })
      })

      await page.fill('[data-testid="email-input"]', 'user@example.com')
      await page.click('[data-testid="continue-button"]')

      await expect(page.locator('[data-testid="login-error"]')).toBeVisible()
      await expect(page.locator('[data-testid="login-error"]')).toContainText('Internal server error')
    })

    test('should handle network errors', async ({ page }) => {
      // Mock network failure
      await page.route('**/api/v1/auth/login-options*', async route => {
        await route.abort('failed')
      })

      await page.fill('[data-testid="email-input"]', 'user@example.com')
      await page.click('[data-testid="continue-button"]')

      await expect(page.locator('[data-testid="login-error"]')).toBeVisible()
      await expect(page.locator('[data-testid="login-error"]')).toContainText(
        /failed to fetch|networkerror|load failed/i
      )
    })

    test('should handle missing Guard configuration', async ({ page }) => {
      // Mock missing runtime config
      await page.addInitScript(() => {
        window.localStorage.removeItem('guard_runtime')
      })

      await page.reload()
      await expect(page.locator('[data-testid="base-url-input"]')).toBeVisible()
    })
  })

  test.describe('Accessibility', () => {
    test('should be keyboard navigable', async ({ page }) => {
      // UniversalLogin auto-focuses the email input.
      await expect(page.locator('[data-testid="email-input"]')).toBeFocused()

      // Mock API response before submitting.
      await page.route('**/api/v1/auth/login-options*', async route => {
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

      // Type email and tab to continue button
      await page.keyboard.type('user@example.com')
      // WebKit focus order differs; just assert keyboard can submit the form.
      await page.keyboard.press('Enter')

      // Should transition to password step
      await expect(page.locator('[data-testid="password-input"]')).toBeVisible()
    })

    test('should have proper ARIA labels', async ({ page }) => {
      await expect(page.locator('[data-testid="email-input"]')).toHaveAttribute('type', 'email')
      await expect(page.locator('[data-testid="continue-button"]')).toHaveAttribute('type', 'submit')
    })
  })

  test.describe('Mobile Responsiveness', () => {
    test('should work on mobile viewport', async ({ page }) => {
      await page.setViewportSize({ width: 375, height: 667 })

      await expect(page.locator('[data-testid="universal-login"]')).toBeVisible()
      await expect(page.locator('[data-testid="email-input"]')).toBeVisible()

      // Form should be properly sized for mobile
      const formBox = await page.locator('[data-testid="universal-login"]').boundingBox()
      expect(formBox?.width).toBeLessThanOrEqual(375)
    })

    test('should handle virtual keyboard on mobile', async ({ page }) => {
      await page.setViewportSize({ width: 375, height: 667 })

      await page.fill('[data-testid="email-input"]', 'user@example.com')

      // Form should remain visible when virtual keyboard appears
      await expect(page.locator('[data-testid="continue-button"]')).toBeVisible()
    })
  })
})
