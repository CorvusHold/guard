import { FormEvent, useEffect, useMemo, useState } from 'react'
import { GuardClient } from '../../../sdk/ts/src/client'
import { WebLocalStorage } from '../../../sdk/ts/src/storage/webLocalStorage'
import { createPKCE, randomString } from './oauth'
import {
  clearPending,
  clearSession,
  loadConfig,
  loadPending,
  loadSession,
  saveConfig,
  savePending,
  saveSession,
} from './storage'
import type { OAuthPending, OAuthSession, POCConfig, UserInfo } from './types'

const DEFAULT_CONFIG: POCConfig = {
  guardBaseUrl: (import.meta.env.VITE_GUARD_BASE_URL as string) || 'http://localhost:8080',
  clientId: (import.meta.env.VITE_OAUTH_CLIENT_ID as string) || '',
  redirectUri: (import.meta.env.VITE_REDIRECT_URI as string) || `${window.location.origin}/callback`,
  scope: (import.meta.env.VITE_OAUTH_SCOPE as string) || 'openid profile email offline_access',
  tenantId: (import.meta.env.VITE_TENANT_ID as string) || '',
}

export default function App() {
  const [config, setConfig] = useState<POCConfig>(loadConfig() ?? DEFAULT_CONFIG)
  const [session, setSession] = useState<OAuthSession | null>(loadSession())
  const [pending, setPending] = useState<OAuthPending | null>(loadPending())
  const [user, setUser] = useState<UserInfo | null>(null)
  const [configSaved, setConfigSaved] = useState(Boolean(loadConfig()))
  const [loading, setLoading] = useState(false)
  const [signupLoading, setSignupLoading] = useState(false)
  const [message, setMessage] = useState<string>('')
  const [error, setError] = useState<string>('')

  const [signupEmail, setSignupEmail] = useState('')
  const [signupPassword, setSignupPassword] = useState('Password123!')
  const [signupFirstName, setSignupFirstName] = useState('')
  const [signupLastName, setSignupLastName] = useState('')

  const sdkStorage = useMemo(() => new WebLocalStorage('guard_oauth2_poc'), [])

  const sdk = useMemo(() => {
    return new GuardClient({
      baseUrl: config.guardBaseUrl,
      tenantId: config.tenantId || undefined,
      storage: sdkStorage,
    })
  }, [config.guardBaseUrl, config.tenantId, sdkStorage])

  const callbackURL = useMemo(() => new URL(window.location.href), [])
  const isCallback = callbackURL.pathname === '/callback'

  useEffect(() => {
    if (!session?.accessToken || !config.guardBaseUrl) return
    sdk.me()
      .then((res) => {
        if (res.meta.status >= 200 && res.meta.status < 300 && res.data) {
          setUser(res.data as UserInfo)
          return
        }
        throw new Error(`Failed to fetch user profile: status ${res.meta.status}`)
      })
      .catch((err: Error) => {
        setError(err.message)
      })
  }, [config.guardBaseUrl, session?.accessToken, sdk])

  useEffect(() => {
    if (!isCallback) return

    const code = callbackURL.searchParams.get('code')
    const state = callbackURL.searchParams.get('state')
    const oauthError = callbackURL.searchParams.get('error')
    const oauthErrorDesc = callbackURL.searchParams.get('error_description')

    if (oauthError) {
      setError(`OAuth error: ${oauthError}${oauthErrorDesc ? ` - ${oauthErrorDesc}` : ''}`)
      return
    }

    if (!code) {
      setError('Missing authorization code in callback URL')
      return
    }

    if (!pending) {
      setError('Missing local OAuth state. Start login again.')
      return
    }

    if (!state || state !== pending.state) {
      setError('State mismatch detected. Potential CSRF or stale callback.')
      clearPending()
      setPending(null)
      return
    }

    setLoading(true)
    const exchange = async () => {
      const response = await sdk.exchangeOAuth2Code({
        code,
        client_id: config.clientId,
        redirect_uri: config.redirectUri,
        code_verifier: pending.codeVerifier,
      })

      if (response.meta.status < 200 || response.meta.status >= 300 || !response.data?.access_token) {
        throw new Error(`Token exchange failed with status ${response.meta.status}`)
      }

      const tokens = response.data

      const nextSession: OAuthSession = {
        accessToken: tokens.access_token ?? '',
        refreshToken: tokens.refresh_token ?? undefined,
        idToken: tokens.id_token ?? undefined,
        tokenType: tokens.token_type ?? undefined,
        expiresIn: tokens.expires_in,
        scope: tokens.scope ?? undefined,
        createdAt: Date.now(),
      }

      saveSession(nextSession)
      clearPending()
      setSession(nextSession)
      setPending(null)
      setMessage('OAuth callback completed successfully.')
      setError('')

      const profile = await sdk.me()
      if (profile.meta.status >= 200 && profile.meta.status < 300 && profile.data) {
        setUser(profile.data as UserInfo)
      }

      window.history.replaceState({}, document.title, '/')
    }

    exchange()
      .catch((err: Error) => {
        setError(err.message)
      })
      .finally(() => {
        setLoading(false)
      })
  }, [callbackURL, config.clientId, config.redirectUri, isCallback, pending, sdk])

  function updateConfigField<K extends keyof POCConfig>(key: K, value: POCConfig[K]) {
    setConfig((prev) => ({ ...prev, [key]: value }))
  }

  function savePOCConfig(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    saveConfig(config)
    setConfigSaved(true)
    setMessage('POC configuration saved.')
    setError('')
  }

  async function startLogin(loginHint?: string) {
    setLoading(true)
    setMessage('')
    setError('')

    try {
      if (!config.clientId.trim()) {
        throw new Error('client_id is required')
      }
      if (!config.guardBaseUrl.trim()) {
        throw new Error('Guard base URL is required')
      }

      const { codeVerifier, codeChallenge } = await createPKCE()
      const state = randomString(48)
      const nonce = randomString(48)

      const pendingFlow: OAuthPending = {
        state,
        nonce,
        codeVerifier,
        createdAt: Date.now(),
      }

      savePending(pendingFlow)
      setPending(pendingFlow)

      const authorizeUrl = sdk.buildOAuth2AuthorizeUrl({
        client_id: config.clientId.trim(),
        redirect_uri: config.redirectUri.trim(),
        scope: config.scope.trim(),
        state,
        nonce,
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
        login_hint: loginHint,
      })

      window.location.href = authorizeUrl
    } catch (err) {
      const e = err as Error
      setError(e.message)
      setLoading(false)
    }
  }

  async function signUpThenOAuth(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setSignupLoading(true)
    setMessage('')
    setError('')

    try {
      if (!config.tenantId.trim()) {
        throw new Error('tenant_id is required to sign up')
      }
      if (!signupEmail.trim() || !signupPassword.trim()) {
        throw new Error('Signup email and password are required')
      }

      const response = await sdk.passwordSignup({
        tenant_id: config.tenantId.trim(),
        email: signupEmail.trim().toLowerCase(),
        password: signupPassword,
        first_name: signupFirstName.trim() || undefined,
        last_name: signupLastName.trim() || undefined,
      })

      if (response.meta.status < 200 || response.meta.status >= 300) {
        throw new Error('Signup failed')
      }

      setMessage('Signup successful. Redirecting into OAuth login flow...')
      await startLogin(signupEmail.trim().toLowerCase())
    } catch (err) {
      const e = err as Error
      setError(e.message)
    } finally {
      setSignupLoading(false)
    }
  }

  async function logout() {
    if (!session?.refreshToken) {
      clearSession()
      setSession(null)
      setUser(null)
      setMessage('Local session cleared (no refresh token to revoke).')
      return
    }

    setLoading(true)
    setMessage('')
    setError('')

    try {
      await sdk.revokeOAuth2Token({
        token: session.refreshToken,
        token_type_hint: 'refresh_token',
      })

      sdkStorage.clear()
      clearSession()
      setSession(null)
      setUser(null)
      setMessage('Logged out and refresh token revoked.')
    } catch (err) {
      const e = err as Error
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <main className="page" data-testid="oauth2-poc-app">
      <section className="card">
        <h1>Guard OAuth2 SPA POC</h1>
        <p className="muted">
          OAuth2 Authorization Code + PKCE demo using Guard SDK URL builder, token exchange, profile fetch, and logout
          revocation.
        </p>

        <form className="grid" onSubmit={savePOCConfig}>
          <label>
            Guard Base URL
            <input
              data-testid="cfg-guard-base-url"
              type="url"
              value={config.guardBaseUrl}
              onChange={(event) => updateConfigField('guardBaseUrl', event.target.value)}
              required
            />
          </label>

          <label>
            OAuth Client ID
            <input
              data-testid="cfg-client-id"
              value={config.clientId}
              onChange={(event) => updateConfigField('clientId', event.target.value)}
              required
            />
          </label>

          <label>
            Redirect URI
            <input
              data-testid="cfg-redirect-uri"
              type="url"
              value={config.redirectUri}
              onChange={(event) => updateConfigField('redirectUri', event.target.value)}
              required
            />
          </label>

          <label>
            Tenant ID (required for signup helper)
            <input
              data-testid="cfg-tenant-id"
              value={config.tenantId}
              onChange={(event) => updateConfigField('tenantId', event.target.value)}
            />
          </label>

          <label>
            Scope
            <input
              data-testid="cfg-scope"
              value={config.scope}
              onChange={(event) => updateConfigField('scope', event.target.value)}
              required
            />
          </label>

          <button type="submit" data-testid="cfg-save-btn">Save config</button>
        </form>

        <div className="actions">
          <button type="button" onClick={() => void startLogin()} disabled={loading} data-testid="oauth-login-btn">
            {loading ? 'Working...' : 'Sign in with OAuth2'}
          </button>
          <button type="button" onClick={() => void logout()} disabled={loading} data-testid="oauth-logout-btn">
            Logout
          </button>
          <button
            type="button"
            className="secondary"
            onClick={() => {
              clearSession()
              clearPending()
              setSession(null)
              setPending(null)
              setUser(null)
            }}
            data-testid="oauth-clear-local-btn"
          >
            Clear local state
          </button>
        </div>

        {message && (
          <div className="notice success" data-testid="oauth-message">
            {message}
          </div>
        )}

        {error && (
          <div className="notice error" data-testid="oauth-error">
            {error}
          </div>
        )}

        <div className="debug" data-testid="oauth-debug-state">
          <h2>Debug state</h2>
          <pre>{JSON.stringify({ configSaved, isCallback, pending, session, user }, null, 2)}</pre>
        </div>
      </section>

      <section className="card">
        <h2>Signup helper (POC)</h2>
        <p className="muted">
          Creates a user via Guard signup endpoint, then starts OAuth2 login so the app uses Authorization Code flow.
        </p>

        <form className="grid" onSubmit={signUpThenOAuth}>
          <label>
            Email
            <input
              data-testid="signup-email"
              type="email"
              value={signupEmail}
              onChange={(event) => setSignupEmail(event.target.value)}
              required
            />
          </label>

          <label>
            Password
            <input
              data-testid="signup-password"
              type="password"
              value={signupPassword}
              onChange={(event) => setSignupPassword(event.target.value)}
              required
            />
          </label>

          <label>
            First name
            <input
              data-testid="signup-first-name"
              value={signupFirstName}
              onChange={(event) => setSignupFirstName(event.target.value)}
            />
          </label>

          <label>
            Last name
            <input
              data-testid="signup-last-name"
              value={signupLastName}
              onChange={(event) => setSignupLastName(event.target.value)}
            />
          </label>

          <button type="submit" disabled={signupLoading} data-testid="signup-submit-btn">
            {signupLoading ? 'Creating user...' : 'Sign up and continue with OAuth2'}
          </button>
        </form>
      </section>
    </main>
  )
}
