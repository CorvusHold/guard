import { Page, expect } from '@playwright/test'

export interface EmailDiscoveryResponse {
  found: boolean
  has_tenant: boolean
  tenant_id?: string
  tenant_name?: string
  user_exists: boolean
  suggestions?: string[]
}

export interface LoginCredentials {
  email: string
  password: string
  tenantId?: string
}

export class ProgressiveLoginHelpers {
  constructor(private page: Page) {}

  /**
   * Mock the email discovery API with a specific response
   */
  async mockEmailDiscovery(response: EmailDiscoveryResponse, delay = 0) {
    await this.page.route('**/v1/auth/email/discover', async route => {
      if (delay > 0) {
        await new Promise(resolve => setTimeout(resolve, delay))
      }
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(response)
      })
    })
  }

  /**
   * Mock the login API with success or error response
   */
  async mockLogin(success = true, errorMessage = 'Invalid credentials') {
    await this.page.route('**/v1/auth/password/login', async route => {
      if (success) {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            access_token: 'mock-access-token',
            refresh_token: 'mock-refresh-token'
          })
        })
      } else {
        await route.fulfill({
          status: 401,
          contentType: 'application/json',
          body: JSON.stringify({ error: errorMessage })
        })
      }
    })
  }

  /**
   * Mock API error responses
   */
  async mockApiError(endpoint: string, status = 500, message = 'Internal server error') {
    await this.page.route(`**${endpoint}`, async route => {
      await route.fulfill({
        status,
        contentType: 'application/json',
        body: JSON.stringify({ error: message })
      })
    })
  }

  /**
   * Mock network failure
   */
  async mockNetworkFailure(endpoint: string) {
    await this.page.route(`**${endpoint}`, async route => {
      await route.abort('failed')
    })
  }

  /**
   * Set tenant context in localStorage
   */
  async setTenantContext(tenantId: string, tenantName: string) {
    await this.page.addInitScript((data) => {
      window.localStorage.setItem('tenant_id', data.tenantId)
      window.localStorage.setItem('tenant_name', data.tenantName)
    }, { tenantId, tenantName })
  }

  /**
   * Clear tenant context
   */
  async clearTenantContext() {
    await this.page.addInitScript(() => {
      window.localStorage.removeItem('tenant_id')
      window.localStorage.removeItem('tenant_name')
    })
  }

  /**
   * Set Guard runtime configuration
   */
  async setGuardConfig(baseUrl = 'http://localhost:8080') {
    await this.page.addInitScript((url) => {
      window.localStorage.setItem('guard_config', JSON.stringify({
        guard_base_url: url
      }))
    }, baseUrl)
  }

  /**
   * Clear Guard configuration
   */
  async clearGuardConfig() {
    await this.page.addInitScript(() => {
      window.localStorage.removeItem('guard_config')
    })
  }

  /**
   * Navigate to login page and wait for it to load
   */
  async navigateToLogin() {
    await this.page.goto('/login')
    await expect(this.page.locator('[data-testid="email-input"]')).toBeVisible()
  }

  /**
   * Fill email and proceed to next step
   */
  async enterEmail(email: string) {
    await this.page.fill('[data-testid="email-input"]', email)
    await this.page.click('[data-testid="continue-button"]')
  }

  /**
   * Wait for email discovery to complete
   */
  async waitForEmailDiscovery() {
    await this.page.waitForResponse('**/v1/auth/email/discover')
  }

  /**
   * Enter password and submit login
   */
  async enterPasswordAndLogin(password: string) {
    await expect(this.page.locator('[data-testid="password-input"]')).toBeVisible()
    await this.page.fill('[data-testid="password-input"]', password)
    await this.page.click('[data-testid="signin-button"]')
  }

  /**
   * Complete full login flow
   */
  async completeLogin(credentials: LoginCredentials) {
    if (credentials.tenantId) {
      await this.setTenantContext(credentials.tenantId, 'Test Organization')
    }

    await this.mockEmailDiscovery({
      found: true,
      has_tenant: true,
      tenant_id: credentials.tenantId || 'tenant-123',
      tenant_name: 'Test Organization',
      user_exists: true
    })

    await this.mockLogin(true)
    await this.enterEmail(credentials.email)
    await this.waitForEmailDiscovery()
    await this.enterPasswordAndLogin(credentials.password)
  }

  /**
   * Verify email step is visible
   */
  async verifyEmailStep() {
    await expect(this.page.locator('[data-testid="email-input"]')).toBeVisible()
    await expect(this.page.locator('[data-testid="password-input"]')).not.toBeVisible()
    await expect(this.page.locator('[data-testid="continue-button"]')).toBeVisible()
  }

  /**
   * Verify password step is visible
   */
  async verifyPasswordStep(email: string, tenantName?: string) {
    await expect(this.page.locator('[data-testid="password-input"]')).toBeVisible()
    await expect(this.page.locator('[data-testid="email-success"]')).toContainText(email)
    
    if (tenantName) {
      await expect(this.page.locator('[data-testid="tenant-info"]')).toContainText(tenantName)
    }
  }

  /**
   * Verify options step is visible (email not found)
   */
  async verifyOptionsStep(email: string, hasTenant = false) {
    await expect(this.page.locator('[data-testid="email-not-found"]')).toBeVisible()
    await expect(this.page.locator('[data-testid="email-not-found"]')).toContainText(email)

    if (hasTenant) {
      await expect(this.page.locator('[data-testid="create-account-button"]')).toBeVisible()
    } else {
      await expect(this.page.locator('[data-testid="create-tenant-button"]')).toBeVisible()
      await expect(this.page.locator('[data-testid="join-organization-button"]')).toBeVisible()
    }
  }

  /**
   * Verify email suggestions are shown
   */
  async verifyEmailSuggestions(suggestions: string[]) {
    await expect(this.page.locator('[data-testid="email-suggestions"]')).toBeVisible()
    
    for (const suggestion of suggestions) {
      await expect(this.page.locator(`[data-testid="suggestion-${suggestion}"]`)).toBeVisible()
    }
  }

  /**
   * Click on an email suggestion
   */
  async clickEmailSuggestion(suggestion: string) {
    await this.page.click(`[data-testid="suggestion-${suggestion}"]`)
  }

  /**
   * Verify loading state
   */
  async verifyLoadingState(buttonText = 'Checking email...') {
    await expect(this.page.locator('[data-testid="continue-button"]')).toContainText(buttonText)
    await expect(this.page.locator('[data-testid="loading-spinner"]')).toBeVisible()
  }

  /**
   * Verify error message
   */
  async verifyError(testId: string, message: string) {
    await expect(this.page.locator(`[data-testid="${testId}"]`)).toBeVisible()
    await expect(this.page.locator(`[data-testid="${testId}"]`)).toContainText(message)
  }

  /**
   * Verify toast message
   */
  async verifyToast(message: string) {
    await expect(this.page.locator('[data-testid="toast"]')).toBeVisible()
    await expect(this.page.locator('[data-testid="toast"]')).toContainText(message)
  }

  /**
   * Toggle password visibility
   */
  async togglePasswordVisibility() {
    await this.page.click('[data-testid="toggle-password-button"]')
  }

  /**
   * Go back to email step from password step
   */
  async goBackToEmailStep() {
    await this.page.click('[data-testid="change-email-button"]')
    await this.verifyEmailStep()
  }

  /**
   * Verify multiple tenants scenario
   */
  async verifyMultipleTenants(primaryTenant: string, suggestions: string[]) {
    await expect(this.page.locator('[data-testid="tenant-info"]')).toContainText(primaryTenant)
    await expect(this.page.locator('[data-testid="multiple-orgs-info"]')).toBeVisible()
    
    for (const suggestion of suggestions) {
      await expect(this.page.locator('[data-testid="multiple-orgs-info"]')).toContainText(suggestion)
    }
  }

  /**
   * Test keyboard navigation
   */
  async testKeyboardNavigation() {
    // Tab to email input
    await this.page.keyboard.press('Tab')
    await expect(this.page.locator('[data-testid="email-input"]')).toBeFocused()

    // Tab to continue button
    await this.page.keyboard.press('Tab')
    await expect(this.page.locator('[data-testid="continue-button"]')).toBeFocused()
  }

  /**
   * Verify accessibility attributes
   */
  async verifyAccessibility() {
    await expect(this.page.locator('[data-testid="email-input"]')).toHaveAttribute('aria-label')
    await expect(this.page.locator('[data-testid="continue-button"]')).toHaveAttribute('aria-label')
    await expect(this.page.locator('[data-testid="status-live-region"]')).toHaveAttribute('aria-live', 'polite')
  }

  /**
   * Set mobile viewport
   */
  async setMobileViewport() {
    await this.page.setViewportSize({ width: 375, height: 667 })
  }

  /**
   * Verify mobile responsiveness
   */
  async verifyMobileLayout() {
    const formBox = await this.page.locator('[data-testid="login-form"]').boundingBox()
    expect(formBox?.width).toBeLessThanOrEqual(375)
    await expect(this.page.locator('[data-testid="login-form"]')).toBeVisible()
  }
}
