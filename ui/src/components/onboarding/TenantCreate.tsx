import { useEffect, useMemo, useState } from 'react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { getClient } from '@/lib/sdk'
import { useTenant } from '@/lib/tenant'

export default function TenantCreate() {
  const { setTenantId } = useTenant()
  const [orgName, setOrgName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [firstName, setFirstName] = useState('')
  const [lastName, setLastName] = useState('')
  const [loading, setLoading] = useState<null | 'create'> (null)
  const [error, setError] = useState<string | null>(null)
  const [tenantCreatedId, setTenantCreatedId] = useState<string | null>(null)

  useEffect(() => {
    try {
      const usp = new URLSearchParams(window.location.search)
      const e = usp.get('email') || ''
      const name = usp.get('name') || ''
      if (e) setEmail(e)
      if (name) setOrgName(name)
    } catch {}
  }, [])

  const canSubmit = useMemo(() => {
    return orgName.trim().length > 0 && email.trim().length > 0 && password.trim().length >= 8
  }, [orgName, email, password])

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!canSubmit) return
    setError(null)
    setLoading('create')
    try {
      // 1) Create tenant via SDK
      const client = getClient()
      const cres = await client.createTenant({ name: orgName.trim() })
      if (!(cres.meta.status >= 200 && cres.meta.status < 300)) throw new Error('Failed to create tenant')
      const t = cres.data as any
      const tenant_id = t?.id as string
      if (!tenant_id) throw new Error('Invalid tenant response')
      setTenantCreatedId(tenant_id)

      // 2) Create initial admin user via password signup
      const signup = await client.passwordSignup({
        tenant_id,
        email: email.trim(),
        password: password.trim(),
        first_name: firstName.trim() || undefined,
        last_name: lastName.trim() || undefined
      })
      if (!(signup.meta.status >= 200 && signup.meta.status < 300)) {
        throw new Error('Failed to create initial admin user')
      }

      // 3) Perform a login to persist tokens/cookies (server may not issue tokens on signup)
      try {
        await client.passwordLogin({
          email: email.trim(),
          password: password.trim(),
          tenant_id
        })
      } catch (_) {
        // non-fatal; continue
      }

      // 4) Optionally pre-configure SSO dev defaults for a ready-to-test experience
      try {
        const origin = window.location.origin
        await client.updateTenantSettings(tenant_id, {
          sso_provider: 'dev',
          sso_redirect_allowlist: `${origin}/auth/callback`
        } as any)
      } catch (_) {
        // non-fatal; ignore
      }

      // 5) Persist tenant in context and redirect to Admin
      setTenantId(tenant_id)
      try {
        window.location.href = '/admin?source=settings'
      } catch {}
    } catch (e: any) {
      setError(e?.message || String(e))
    } finally {
      setLoading(null)
    }
  }

  return (
    <div className="flex min-h-svh flex-col items-center justify-center p-6">
      <div className="w-full max-w-xl space-y-4 rounded-xl border p-6">
        <h1 className="text-xl font-semibold">Create your organization</h1>
        <div className="text-sm text-muted-foreground">
          We'll set up a new tenant and your admin account.
        </div>
        {error && (
          <div className="rounded-md border border-red-200 bg-red-50 p-2 text-sm text-red-700" data-testid="tenant-create-error">
            {error}
          </div>
        )}
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="org">Organization name</Label>
            <Input
              id="org"
              data-testid="tenant-create-org"
              value={orgName}
              onChange={(e) => setOrgName(e.target.value)}
              placeholder="acme-corp"
              required
            />
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div className="space-y-2">
              <Label htmlFor="first">First name</Label>
              <Input id="first" data-testid="tenant-create-first" value={firstName} onChange={(e) => setFirstName(e.target.value)} />
            </div>
            <div className="space-y-2">
              <Label htmlFor="last">Last name</Label>
              <Input id="last" data-testid="tenant-create-last" value={lastName} onChange={(e) => setLastName(e.target.value)} />
            </div>
          </div>
          <div className="space-y-2">
            <Label htmlFor="email">Work email</Label>
            <Input id="email" data-testid="tenant-create-email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
          </div>
          <div className="space-y-2">
            <Label htmlFor="pw">Password</Label>
            <Input id="pw" data-testid="tenant-create-password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} required />
            <div className="text-xs text-muted-foreground">Minimum 8 characters</div>
          </div>
          <div className="flex gap-2">
            <Button type="submit" data-testid="tenant-create-submit" disabled={!canSubmit || loading !== null}>
              {loading === 'create' ? 'Creating...' : 'Create organization'}
            </Button>
            <Button
              type="button"
              variant="secondary"
              data-testid="tenant-create-back"
              onClick={() => { try { window.location.href = '/' } catch {} }}
            >
              Back
            </Button>
          </div>
        </form>
        {tenantCreatedId && (
          <div className="rounded-md border p-2 text-xs text-muted-foreground" data-testid="tenant-created-id">
            Tenant ID: <code>{tenantCreatedId}</code>
          </div>
        )}
      </div>
    </div>
  )
}
