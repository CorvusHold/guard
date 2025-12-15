import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Separator } from '@/components/ui/separator'
import { useAuth } from '@/lib/auth'
import { getRuntimeConfig } from '@/lib/runtime'
import { getClient } from '@/lib/sdk'
import { useToast } from '@/lib/toast'

interface TenantCreationForm {
  // Tenant details
  tenantName: string
  enableMFA: boolean
  
  // Admin user details
  adminEmail: string
  adminPassword: string
  adminFirstName: string
  adminLastName: string
}

interface TenantCreationPanelProps {
  onTenantCreated?: (tenantId: string, tenantName: string) => void
}

export default function TenantCreationPanel({ onTenantCreated }: TenantCreationPanelProps) {
  const { user } = useAuth()
  const { show: showToast } = useToast()
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [createdTenantId, setCreatedTenantId] = useState<string | null>(null)
  const [createdTenantName, setCreatedTenantName] = useState<string | null>(null)
  const [form, setForm] = useState<TenantCreationForm>({
    tenantName: '',
    enableMFA: false,
    adminEmail: '',
    adminPassword: '',
    adminFirstName: '',
    adminLastName: ''
  })

  const updateForm = (field: keyof TenantCreationForm, value: string) => {
    setForm(prev => ({ ...prev, [field]: value }))
    if (error) setError(null)
  }

  const validateForm = (): string | null => {
    if (!form.tenantName.trim()) return 'Tenant name is required'
    if (!form.adminEmail.trim()) return 'Admin email is required'
    if (!form.adminPassword.trim()) return 'Admin password is required'
    if (!form.adminFirstName.trim()) return 'Admin first name is required'
    if (!form.adminLastName.trim()) return 'Admin last name is required'
    
    // Email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    if (!emailRegex.test(form.adminEmail)) return 'Invalid email format'
    
    // Password validation (basic)
    if (form.adminPassword.length < 8) return 'Password must be at least 8 characters'
    
    return null
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    
    const validationError = validateForm()
    if (validationError) {
      setError(validationError)
      return
    }

    setLoading(true)
    setError(null)
    setCreatedTenantId(null)
    setCreatedTenantName(null)

    try {
      const config = getRuntimeConfig()
      if (!config) {
        throw new Error('Guard configuration not found')
      }
      const client = getClient()

      // Step 1: Create tenant via SDK
      const tRes = await client.createTenant({ name: form.tenantName.trim() })
      if (!(tRes.meta.status >= 200 && tRes.meta.status < 300)) {
        throw new Error('Failed to create tenant')
      }
      const tenantId = (tRes.data as any).id as string

      // Step 2: Create admin user via SDK
      const sRes = await client.passwordSignup({
        tenant_id: tenantId,
        email: form.adminEmail.trim(),
        password: form.adminPassword,
        first_name: form.adminFirstName.trim(),
        last_name: form.adminLastName.trim()
      })
      if (!(sRes.meta.status >= 200 && sRes.meta.status < 300)) {
        throw new Error('Failed to create admin user')
      }

      console.log('Tenant and admin user created successfully.')

      showToast({ description: 'Tenant created successfully!', variant: 'success' })

      setCreatedTenantId(tenantId)
      setCreatedTenantName(form.tenantName)
      
      // Reset form
      setForm({
        tenantName: '',
        enableMFA: false,
        adminEmail: '',
        adminPassword: '',
        adminFirstName: '',
        adminLastName: ''
      })

      // Notify parent component
      onTenantCreated?.(tenantId, form.tenantName)

    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to create tenant'
      setError(message)
      showToast({ description: message, variant: 'error' })
    } finally {
      setLoading(false)
    }
  }

  return (
    <Card className="w-full max-w-2xl mx-auto">
      <CardHeader>
        <CardTitle>Create New Tenant</CardTitle>
        <CardDescription>
          Create a new tenant with an admin user account
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={handleSubmit} className="space-y-6">
          {/* Tenant Details */}
          <div className="space-y-4">
            <h3 className="text-lg font-medium">Tenant Details</h3>
            <div className="space-y-2">
              <Label htmlFor="tenantName">Tenant Name</Label>
              <Input
                id="tenantName"
                type="text"
                data-testid="tenant-name"
                value={form.tenantName}
                onChange={(e) => updateForm('tenantName', e.target.value)}
                placeholder="Enter tenant name"
                disabled={loading}
                required
              />
            </div>
          </div>

          <Separator />

          {/* Admin User Details */}
          <div className="space-y-4">
            <h3 className="text-lg font-medium">Admin User Details</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="adminFirstName">First Name</Label>
                <Input
                  id="adminFirstName"
                  type="text"
                  data-testid="admin-first-name"
                  value={form.adminFirstName}
                  onChange={(e) => updateForm('adminFirstName', e.target.value)}
                  placeholder="Enter first name"
                  disabled={loading}
                  required
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="adminLastName">Last Name</Label>
                <Input
                  id="adminLastName"
                  type="text"
                  data-testid="admin-last-name"
                  value={form.adminLastName}
                  onChange={(e) => updateForm('adminLastName', e.target.value)}
                  placeholder="Enter last name"
                  disabled={loading}
                  required
                />
              </div>
            </div>
            <div className="space-y-2">
              <Label htmlFor="adminEmail">Email</Label>
              <Input
                id="adminEmail"
                type="email"
                data-testid="admin-email"
                value={form.adminEmail}
                onChange={(e) => updateForm('adminEmail', e.target.value)}
                placeholder="Enter admin email"
                disabled={loading}
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="adminPassword">Password</Label>
              <Input
                id="adminPassword"
                type="password"
                data-testid="admin-password"
                value={form.adminPassword}
                onChange={(e) => updateForm('adminPassword', e.target.value)}
                placeholder="Enter admin password"
                disabled={loading}
                required
                minLength={8}
              />
              <p className="text-sm text-muted-foreground">
                Password must be at least 8 characters long
              </p>
            </div>

            <div className="space-y-2">
              <Label htmlFor="enableMFA">Enable MFA</Label>
              <Input
                id="enableMFA"
                type="checkbox"
                data-testid="enable-mfa"
                checked={form.enableMFA}
                onChange={(e) => updateForm('enableMFA', e.target.checked ? 'true' : '')}
                disabled={loading}
              />
            </div>
          </div>

          {error && (
            <div className="p-3 text-sm text-red-600 bg-red-50 border border-red-200 rounded-md" data-testid="error-message">
              {error}
            </div>
          )}

          {createdTenantId && createdTenantName && (
            <div className="p-3 text-sm text-green-700 bg-green-50 border border-green-200 rounded-md" data-testid="creation-success">
              <div>
                Created tenant: <span className="font-medium" data-testid="created-tenant-name">{createdTenantName}</span>
              </div>
            </div>
          )}

          <div className="flex justify-end space-x-3">
            <Button
              type="button"
              variant="outline"
              onClick={() => {
                setForm({
                  tenantName: '',
                  enableMFA: false,
                  adminEmail: '',
                  adminPassword: '',
                  adminFirstName: '',
                  adminLastName: ''
                })
                setError(null)
                setCreatedTenantId(null)
                setCreatedTenantName(null)
              }}
              disabled={loading}
            >
              Reset
            </Button>
            <Button type="submit" disabled={loading} data-testid="create-tenant">
              {loading ? 'Creating...' : 'Create Tenant'}
            </Button>
          </div>
        </form>
      </CardContent>
    </Card>
  )
}
