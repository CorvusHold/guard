import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { getClient } from '@/lib/sdk'
import SimpleProgressiveLoginForm from './SimpleProgressiveLoginForm'

export default function Login() {
  const [loading, setLoading] = useState<'sso-dev' | 'sso-workos' | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [me, setMe] = useState<any | null>(null)

  async function startSso(provider: 'dev' | 'workos') {
    setError(null)
    setLoading(provider === 'dev' ? 'sso-dev' : 'sso-workos')
    try {
      const client = getClient()
      // Redirect back to dedicated callback handler with provider
      const origin = window.location.origin
      const qp = new URLSearchParams()
      qp.set('provider', provider)
      const redirect = `${origin}/auth/callback?${qp.toString()}`
      const res = await client.startSso(provider as any, {
        redirect_url: redirect
      })
      const url = res.data?.redirect_url
      if (url) window.location.href = url
    } catch (err: any) {
      setError(err?.message || String(err))
    } finally {
      setLoading(null)
    }
  }

  const handleLoginSuccess = (userData: any) => {
    setMe(userData)
  }

  return (
    <div className="w-full max-w-lg space-y-4 rounded-xl border p-6">
      <h2 className="text-lg font-semibold">Login</h2>
      {me ? (
        <div className="rounded-md border p-3 text-sm">
          <div className="font-medium">Logged in</div>
          <div>Email: {(me as any)?.email}</div>
          <div>
            Name: {(me as any)?.first_name} {(me as any)?.last_name}
          </div>
        </div>
      ) : (
        <SimpleProgressiveLoginForm onLoginSuccess={handleLoginSuccess} />
      )}

      {!me && (
        <div className="space-y-2 pt-2">
          <div className="text-xs uppercase tracking-wide text-muted-foreground">
            or
          </div>
          <div className="flex flex-wrap gap-2">
            <Button
              data-testid="login-sso-dev"
              variant="secondary"
              disabled={loading !== null}
              onClick={() => startSso('dev')}
            >
              {loading === 'sso-dev'
                ? 'Starting Dev SSO...'
                : 'Continue with Dev SSO'}
            </Button>
            <Button
              data-testid="login-sso-workos"
              variant="secondary"
              disabled={loading !== null}
              onClick={() => startSso('workos')}
            >
              {loading === 'sso-workos'
                ? 'Starting WorkOS SSO...'
                : 'Continue with WorkOS SSO'}
            </Button>
          </div>
          {error && (
            <div className="rounded-md border border-red-200 bg-red-50 p-2 text-sm text-red-700">
              {error}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
