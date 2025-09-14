import { test, expect } from '@playwright/test'

test.describe('Progressive Login Flow', () => {
  test.beforeEach(async ({ page }) => {
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
      await expect(page.locator('[data-testid="email-error"]')).toBeVisible()
      await expect(page.locator('[data-testid="email-error"]')).toContainText('Please enter a valid email address')
    })

    test('should show loading state during email discovery', async ({ page }) => {
      // Mock slow API response
      await page.route('**/v1/auth/email/discover', async route => {
        await new Promise(resolve => setTimeout(resolve, 1000))
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

      await page.fill('[data-testid="email-input"]', 'user@example.com')
      await page.click('[data-testid="continue-button"]')
      
      await expect(page.locator('[data-testid="continue-button"]')).toContainText('Checking email...')
      await expect(page.locator('[data-testid="loading-spinner"]')).toBeVisible()
    })
  })

  test.describe('Email Found - Show Password Step', () => {
    test('should show password field when email is found', async ({ page }) => {
      // Mock API response for found email
      await page.route('**/v1/auth/email/discover', async route => {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            found: true,
            has_tenant: true,
            tenant_id: 'tenant-123',
            tenant_name: 'Test Organization',
            user_exists: true
          })
        })
      })

      await page.fill('[data-testid="email-input"]', 'user@example.com')
      await page.click('[data-testid="continue-button"]')

      // Should show success message and password field
      await expect(page.locator('[data-testid="email-success"]')).toBeVisible()
      await expect(page.locator('[data-testid="email-success"]')).toContainText('✓ user@example.com')
      await expect(page.locator('[data-testid="tenant-info"]')).toContainText('Signing in to Test Organization')
      await expect(page.locator('[data-testid="password-input"]')).toBeVisible()
      await expect(page.locator('[data-testid="password-input"]')).toBeFocused()
      await expect(page.locator('[data-testid="signin-button"]')).toBeVisible()
    })

    test('should allow changing email from password step', async ({ page }) => {
      // Mock API response for found email
      await page.route('**/v1/auth/email/discover', async route => {
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

      await page.fill('[data-testid="email-input"]', 'user@example.com')
      await page.click('[data-testid="continue-button"]')

      // Click change email button
      await page.click('[data-testid="change-email-button"]')

      // Should return to email step
      await expect(page.locator('[data-testid="email-input"]')).toBeVisible()
      await expect(page.locator('[data-testid="password-input"]')).not.toBeVisible()
      await expect(page.locator('[data-testid="email-input"]')).toHaveValue('user@example.com')
    })

    test('should show/hide password with toggle button', async ({ page }) => {
      // Mock API response for found email
      await page.route('**/v1/auth/email/discover', async route => {
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

      await page.fill('[data-testid="email-input"]', 'user@example.com')
      await page.click('[data-testid="continue-button"]')

      await page.fill('[data-testid="password-input"]', 'password123')
      
      // Password should be hidden initially
      await expect(page.locator('[data-testid="password-input"]')).toHaveAttribute('type', 'password')
      
      // Click show password button
      await page.click('[data-testid="toggle-password-button"]')
      await expect(page.locator('[data-testid="password-input"]')).toHaveAttribute('type', 'text')
      
      // Click hide password button
      await page.click('[data-testid="toggle-password-button"]')
      await expect(page.locator('[data-testid="password-input"]')).toHaveAttribute('type', 'password')
    })

    test('should attempt login when password is submitted', async ({ page }) => {
      // Mock email discovery
      await page.route('**/v1/auth/email/discover', async route => {
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

      // Mock login API
      await page.route('**/v1/auth/password/login', async route => {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            access_token: 'mock-token',
            refresh_token: 'mock-refresh'
          })
        })
      })

      await page.fill('[data-testid="email-input"]', 'user@example.com')
      await page.click('[data-testid="continue-button"]')
      
      await page.fill('[data-testid="password-input"]', 'password123')
      await page.click('[data-testid="signin-button"]')

      // Should show loading state
      await expect(page.locator('[data-testid="signin-button"]')).toContainText('Signing in...')
    })

    test('should show login error for invalid credentials', async ({ page }) => {
      // Mock email discovery
      await page.route('**/v1/auth/email/discover', async route => {
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

      // Mock login error
      await page.route('**/v1/auth/password/login', async route => {
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
    test('should show tenant creation option when no tenant specified', async ({ page }) => {
      // Mock API response for email not found
      await page.route('**/v1/auth/email/discover', async route => {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            found: false,
            has_tenant: false,
            user_exists: false,
            suggestions: ['user@gmail.com', 'user@yahoo.com']
          })
        })
      })

      await page.fill('[data-testid="email-input"]', 'user@gmial.com') // typo
      await page.click('[data-testid="continue-button"]')

      // Should show not found message
      await expect(page.locator('[data-testid="email-not-found"]')).toBeVisible()
      await expect(page.locator('[data-testid="email-not-found"]')).toContainText('We couldn\'t find an account for user@gmial.com')

      // Should show email suggestions
      await expect(page.locator('[data-testid="email-suggestions"]')).toBeVisible()
      await expect(page.locator('[data-testid="suggestion-user@gmail.com"]')).toBeVisible()
      await expect(page.locator('[data-testid="suggestion-user@yahoo.com"]')).toBeVisible()

      // Should show create tenant option
      await expect(page.locator('[data-testid="create-tenant-button"]')).toBeVisible()
      await expect(page.locator('[data-testid="create-tenant-button"]')).toContainText('Create New Organization')

      // Should show join organization option
      await expect(page.locator('[data-testid="join-organization-button"]')).toBeVisible()
      await expect(page.locator('[data-testid="join-organization-button"]')).toContainText('Join Existing Organization')
    })

    test('should show account creation option when tenant is specified', async ({ page }) => {
      // Mock API response for email not found in specific tenant
      await page.route('**/v1/auth/email/discover', async route => {
        const request = route.request()
        const headers = request.headers()
        expect(headers['x-tenant-id']).toBe('tenant-123')
        
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            found: false,
            has_tenant: true,
            tenant_id: 'tenant-123',
            user_exists: false
          })
        })
      })

      // Set tenant context
      await page.addInitScript(() => {
        window.localStorage.setItem('tenant_id', 'tenant-123')
        window.localStorage.setItem('tenant_name', 'Test Organization')
      })

      await page.reload()
      await page.fill('[data-testid="email-input"]', 'newuser@example.com')
      await page.click('[data-testid="continue-button"]')

      // Should show create account option for specific tenant
      await expect(page.locator('[data-testid="create-account-button"]')).toBeVisible()
      await expect(page.locator('[data-testid="create-account-button"]')).toContainText('Create Account in Test Organization')
    })

    test('should use email suggestion when clicked', async ({ page }) => {
      // Mock API responses
      await page.route('**/v1/auth/email/discover', async route => {
        const requestBody = await route.request().postData()
        const { email } = JSON.parse(requestBody || '{}')
        
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
              user_exists: true
            })
          })
        }
      })

      await page.fill('[data-testid="email-input"]', 'user@gmial.com')
      await page.click('[data-testid="continue-button"]')

      // Click on suggestion
      await page.click('[data-testid="suggestion-user@gmail.com"]')

      // Should proceed to password step with corrected email
      await expect(page.locator('[data-testid="password-input"]')).toBeVisible()
      await expect(page.locator('[data-testid="email-success"]')).toContainText('user@gmail.com')
    })

    test('should handle create tenant flow', async ({ page }) => {
      // Mock API response for email not found
      await page.route('**/v1/auth/email/discover', async route => {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            found: false,
            has_tenant: false,
            user_exists: false
          })
        })
      })

      await page.fill('[data-testid="email-input"]', 'newuser@example.com')
      await page.click('[data-testid="continue-button"]')

      await page.click('[data-testid="create-tenant-button"]')

      // Should navigate to tenant creation flow
      await expect(page).toHaveURL(/.*\/tenant\/create/)
    })

    test('should handle join organization flow', async ({ page }) => {
      // Mock API response for email not found
      await page.route('**/v1/auth/email/discover', async route => {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            found: false,
            has_tenant: false,
            user_exists: false
          })
        })
      })

      await page.fill('[data-testid="email-input"]', 'newuser@example.com')
      await page.click('[data-testid="continue-button"]')

      await page.click('[data-testid="join-organization-button"]')

      // Should show toast message about contacting administrator
      await expect(page.locator('[data-testid="toast"]')).toBeVisible()
      await expect(page.locator('[data-testid="toast"]')).toContainText('Please contact your organization administrator for an invitation')
    })
  })

  test.describe('Multiple Tenants Found', () => {
    test('should show primary tenant with suggestions for multiple tenants', async ({ page }) => {
      // Mock API response for multiple tenants
      await page.route('**/v1/auth/email/discover', async route => {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            found: true,
            has_tenant: true,
            tenant_id: 'tenant-123',
            tenant_name: 'Primary Organization',
            user_exists: true,
            suggestions: ['Secondary Organization', 'Third Organization']
          })
        })
      })

      await page.fill('[data-testid="email-input"]', 'user@example.com')
      await page.click('[data-testid="continue-button"]')

      // Should show password step with primary tenant
      await expect(page.locator('[data-testid="password-input"]')).toBeVisible()
      await expect(page.locator('[data-testid="tenant-info"]')).toContainText('Signing in to Primary Organization')

      // Should show multiple organizations info
      await expect(page.locator('[data-testid="multiple-orgs-info"]')).toBeVisible()
      await expect(page.locator('[data-testid="multiple-orgs-info"]')).toContainText('Your email was found in multiple organizations')
      await expect(page.locator('[data-testid="multiple-orgs-info"]')).toContainText('Secondary Organization')
      await expect(page.locator('[data-testid="multiple-orgs-info"]')).toContainText('Third Organization')
    })
  })

  test.describe('Error Handling', () => {
    test('should handle API errors gracefully', async ({ page }) => {
      // Mock API error
      await page.route('**/v1/auth/email/discover', async route => {
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

      await expect(page.locator('[data-testid="email-error"]')).toBeVisible()
      await expect(page.locator('[data-testid="email-error"]')).toContainText('Failed to check email')
    })

    test('should handle network errors', async ({ page }) => {
      // Mock network failure
      await page.route('**/v1/auth/email/discover', async route => {
        await route.abort('failed')
      })

      await page.fill('[data-testid="email-input"]', 'user@example.com')
      await page.click('[data-testid="continue-button"]')

      await expect(page.locator('[data-testid="email-error"]')).toBeVisible()
    })

    test('should handle missing Guard configuration', async ({ page }) => {
      // Mock missing runtime config
      await page.addInitScript(() => {
        window.localStorage.removeItem('guard_config')
      })

      await page.reload()
      await page.fill('[data-testid="email-input"]', 'user@example.com')
      await page.click('[data-testid="continue-button"]')

      await expect(page.locator('[data-testid="email-error"]')).toBeVisible()
      await expect(page.locator('[data-testid="email-error"]')).toContainText('Guard configuration not found')
    })
  })

  test.describe('Accessibility', () => {
    test('should be keyboard navigable', async ({ page }) => {
      // Tab to email input
      await page.keyboard.press('Tab')
      await expect(page.locator('[data-testid="email-input"]')).toBeFocused()

      // Type email and tab to continue button
      await page.keyboard.type('user@example.com')
      await page.keyboard.press('Tab')
      await expect(page.locator('[data-testid="continue-button"]')).toBeFocused()

      // Mock API response
      await page.route('**/v1/auth/email/discover', async route => {
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

      // Press Enter to continue
      await page.keyboard.press('Enter')

      // Should focus password input
      await expect(page.locator('[data-testid="password-input"]')).toBeFocused()
    })

    test('should have proper ARIA labels', async ({ page }) => {
      await expect(page.locator('[data-testid="email-input"]')).toHaveAttribute('aria-label', 'Email Address')
      await expect(page.locator('[data-testid="continue-button"]')).toHaveAttribute('aria-label', 'Continue with email')
    })

    test('should announce status changes to screen readers', async ({ page }) => {
      // Mock API response
      await page.route('**/v1/auth/email/discover', async route => {
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

      await page.fill('[data-testid="email-input"]', 'user@example.com')
      await page.click('[data-testid="continue-button"]')

      // Should have live region for status updates
      await expect(page.locator('[data-testid="status-live-region"]')).toHaveAttribute('aria-live', 'polite')
      await expect(page.locator('[data-testid="status-live-region"]')).toContainText('Email verified. Please enter your password.')
    })
  })

  test.describe('Mobile Responsiveness', () => {
    test('should work on mobile viewport', async ({ page }) => {
      await page.setViewportSize({ width: 375, height: 667 })

      await expect(page.locator('[data-testid="login-form"]')).toBeVisible()
      await expect(page.locator('[data-testid="email-input"]')).toBeVisible()

      // Form should be properly sized for mobile
      const formBox = await page.locator('[data-testid="login-form"]').boundingBox()
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
