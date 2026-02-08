import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { Input } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import { getClient } from '@/lib/sdk'
import { useToast } from '@/lib/toast'
import { formatRateLimitError } from '@/lib/rateLimit'
import { UserPlus, Check } from 'lucide-react'

interface CreateUserPanelProps {
  tenantId: string
  onUserCreated?: () => void
}

export default function CreateUserPanel({
  tenantId,
  onUserCreated
}: CreateUserPanelProps): React.JSX.Element {
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const { show } = useToast()
  
  // Form state
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [firstName, setFirstName] = useState('')
  const [lastName, setLastName] = useState('')
  const [roles, setRoles] = useState('')
  const [emailVerified, setEmailVerified] = useState(false)
  const [creating, setCreating] = useState(false)

  async function createUser() {
    if (!email.trim()) {
      show({ variant: 'error', title: 'Email is required' })
      return
    }
    if (!password || password.length < 8) {
      show({ variant: 'error', title: 'Password must be at least 8 characters' })
      return
    }
    
    setCreating(true)
    setError(null)
    setSuccess(null)
    
    try {
      const c = getClient()
      const rolesArray = roles.split(',').map(r => r.trim()).filter(r => r)
      
      const res = await c.adminCreateUser({
        tenant_id: tenantId,
        email: email.trim(),
        password: password,
        first_name: firstName.trim() || undefined,
        last_name: lastName.trim() || undefined,
        roles: rolesArray.length > 0 ? rolesArray : undefined,
        email_verified: emailVerified
      })
      
      if (res.meta.status >= 200 && res.meta.status < 300) {
        show({ variant: 'success', title: 'User created successfully' })
        setSuccess(`User ${email} created successfully`)
        // Reset form
        setEmail('')
        setPassword('')
        setFirstName('')
        setLastName('')
        setRoles('')
        setEmailVerified(false)
        // Notify parent
        onUserCreated?.()
      } else {
        const errMsg = (res.data as any)?.error || 'Failed to create user'
        setError(errMsg)
        show({ variant: 'error', title: 'Failed to create user', description: errMsg })
      }
    } catch (e: any) {
      const rlMsg = formatRateLimitError(e, 'while creating user')
      if (rlMsg) {
        setError(rlMsg)
        show({ variant: 'error', title: 'Too Many Requests', description: rlMsg })
      } else {
        const msg = e?.message || String(e)
        setError(msg)
        show({
          variant: 'error',
          title: 'Error',
          description: msg
        })
      }
    } finally {
      setCreating(false)
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <UserPlus className="h-5 w-5" />
        <h3 className="text-sm font-medium">Create User</h3>
      </div>
      
      <p className="text-xs text-muted-foreground">
        Create a new user directly in this tenant. The user will be able to log in immediately with the provided credentials.
      </p>

      {error && (
        <div
          className="rounded-md border border-red-200 bg-red-50 p-2 text-sm text-red-700"
          data-testid="create-user-error"
        >
          {error}
        </div>
      )}
      
      {success && (
        <div
          className="rounded-md border border-green-200 bg-green-50 p-2 text-sm text-green-700 flex items-center gap-2"
          data-testid="create-user-success"
        >
          <Check className="h-4 w-4" />
          {success}
        </div>
      )}

      <div className="grid gap-4 md:grid-cols-2">
        <div className="space-y-2">
          <Label htmlFor="create-email">Email Address *</Label>
          <Input
            id="create-email"
            type="email"
            placeholder="user@example.com"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            data-testid="create-user-email"
          />
        </div>
        
        <div className="space-y-2">
          <Label htmlFor="create-password">Password *</Label>
          <Input
            id="create-password"
            type="password"
            placeholder="Minimum 8 characters"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            data-testid="create-user-password"
          />
        </div>
        
        <div className="space-y-2">
          <Label htmlFor="create-first-name">First Name</Label>
          <Input
            id="create-first-name"
            type="text"
            placeholder="John"
            value={firstName}
            onChange={(e) => setFirstName(e.target.value)}
            data-testid="create-user-first-name"
          />
        </div>
        
        <div className="space-y-2">
          <Label htmlFor="create-last-name">Last Name</Label>
          <Input
            id="create-last-name"
            type="text"
            placeholder="Doe"
            value={lastName}
            onChange={(e) => setLastName(e.target.value)}
            data-testid="create-user-last-name"
          />
        </div>
        
        <div className="space-y-2">
          <Label htmlFor="create-roles">Roles</Label>
          <Input
            id="create-roles"
            type="text"
            placeholder="admin, member (comma-separated)"
            value={roles}
            onChange={(e) => setRoles(e.target.value)}
            data-testid="create-user-roles"
          />
          <p className="text-xs text-muted-foreground">
            Comma-separated list of roles to assign
          </p>
        </div>
        
        <div className="space-y-2">
          <Label>Email Verified</Label>
          <div className="flex items-center gap-2">
            <Switch
              checked={emailVerified}
              onCheckedChange={setEmailVerified}
              data-testid="create-user-email-verified"
            />
            <span className="text-sm text-muted-foreground">
              {emailVerified ? 'Yes' : 'No'}
            </span>
          </div>
          <p className="text-xs text-muted-foreground">
            Mark the user's email as verified
          </p>
        </div>
      </div>

      <div className="flex justify-end">
        <Button
          onClick={createUser}
          disabled={creating || !email.trim() || !password || password.length < 8}
          data-testid="create-user-submit"
        >
          {creating ? 'Creating...' : 'Create User'}
        </Button>
      </div>
    </div>
  )
}
