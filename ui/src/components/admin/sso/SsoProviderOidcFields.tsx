import { useState } from 'react'
import type { CreateSsoProviderReq } from '@/lib/sdk'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Button } from '@/components/ui/button'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'

export interface SsoProviderOidcFieldsProps {
  form: Partial<CreateSsoProviderReq>
  updateForm: (key: keyof CreateSsoProviderReq, value: any) => void
  isEditing: boolean
}

export default function SsoProviderOidcFields({
  form,
  updateForm,
  isEditing
}: SsoProviderOidcFieldsProps) {
  const [scopeInput, setScopeInput] = useState('')
  const [configMode, setConfigMode] = useState<'auto' | 'manual'>('auto')

  function addScope() {
    if (scopeInput.trim()) {
      const scopes = [...(form.scopes || []), scopeInput.trim()]
      updateForm('scopes', scopes)
      setScopeInput('')
    }
  }

  function removeScope(scope: string) {
    const scopes = (form.scopes || []).filter(s => s !== scope)
    updateForm('scopes', scopes)
  }

  return (
    <div className="space-y-4">
      <h4 className="text-sm font-medium">OIDC Configuration</h4>

      {/* Configuration Mode */}
      <div className="space-y-2">
        <Label>Configuration Method</Label>
        <div className="flex gap-2">
          <Button
            type="button"
            variant={configMode === 'auto' ? 'default' : 'outline'}
            size="sm"
            onClick={() => setConfigMode('auto')}
          >
            Automatic (Discovery)
          </Button>
          <Button
            type="button"
            variant={configMode === 'manual' ? 'default' : 'outline'}
            size="sm"
            onClick={() => setConfigMode('manual')}
          >
            Manual Configuration
          </Button>
        </div>
      </div>

      {configMode === 'auto' ? (
        <>
          {/* Issuer (Discovery) */}
          <div className="space-y-2">
            <Label htmlFor="issuer">Issuer URL *</Label>
            <Input
              id="issuer"
              type="url"
              value={form.issuer || ''}
              onChange={e => updateForm('issuer', e.target.value)}
              placeholder="https://accounts.google.com"
              required
            />
            <p className="text-xs text-muted-foreground">
              OIDC discovery will be performed using /.well-known/openid-configuration
            </p>
          </div>
        </>
      ) : (
        <>
          {/* Manual Endpoints */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label htmlFor="issuer">Issuer *</Label>
              <Input
                id="issuer"
                value={form.issuer || ''}
                onChange={e => updateForm('issuer', e.target.value)}
                placeholder="https://accounts.google.com"
                required
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="authorization_endpoint">Authorization Endpoint *</Label>
              <Input
                id="authorization_endpoint"
                type="url"
                value={form.authorization_endpoint || ''}
                onChange={e => updateForm('authorization_endpoint', e.target.value)}
                placeholder="https://accounts.google.com/o/oauth2/v2/auth"
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="token_endpoint">Token Endpoint *</Label>
              <Input
                id="token_endpoint"
                type="url"
                value={form.token_endpoint || ''}
                onChange={e => updateForm('token_endpoint', e.target.value)}
                placeholder="https://oauth2.googleapis.com/token"
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="userinfo_endpoint">Userinfo Endpoint</Label>
              <Input
                id="userinfo_endpoint"
                type="url"
                value={form.userinfo_endpoint || ''}
                onChange={e => updateForm('userinfo_endpoint', e.target.value)}
                placeholder="https://openidconnect.googleapis.com/v1/userinfo"
              />
            </div>

            <div className="space-y-2 md:col-span-2">
              <Label htmlFor="jwks_uri">JWKS URI *</Label>
              <Input
                id="jwks_uri"
                type="url"
                value={form.jwks_uri || ''}
                onChange={e => updateForm('jwks_uri', e.target.value)}
                placeholder="https://www.googleapis.com/oauth2/v3/certs"
              />
            </div>
          </div>
        </>
      )}

      {/* Client Credentials */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="space-y-2">
          <Label htmlFor="client_id">Client ID *</Label>
          <Input
            id="client_id"
            value={form.client_id || ''}
            onChange={e => updateForm('client_id', e.target.value)}
            placeholder="123456789.apps.googleusercontent.com"
            required
          />
        </div>

        <div className="space-y-2">
          <Label htmlFor="client_secret">
            Client Secret {!isEditing && '*'}
          </Label>
          <Input
            id="client_secret"
            type="password"
            value={form.client_secret || ''}
            onChange={e => updateForm('client_secret', e.target.value)}
            placeholder={isEditing ? '(unchanged if empty)' : 'Enter client secret'}
            required={!isEditing}
          />
          {isEditing && (
            <p className="text-xs text-muted-foreground">
              Leave empty to keep existing secret
            </p>
          )}
        </div>
      </div>

      {/* Scopes */}
      <div className="space-y-2">
        <Label>Scopes</Label>
        <div className="flex gap-2">
          <Input
            value={scopeInput}
            onChange={e => setScopeInput(e.target.value)}
            placeholder="email"
            onKeyDown={e => {
              if (e.key === 'Enter') {
                e.preventDefault()
                addScope()
              }
            }}
          />
          <Button type="button" onClick={addScope} variant="outline">
            Add
          </Button>
        </div>
        {form.scopes && form.scopes.length > 0 && (
          <div className="flex flex-wrap gap-2 mt-2">
            {form.scopes.map(scope => (
              <span
                key={scope}
                className="inline-flex items-center gap-1 px-2 py-1 rounded-md bg-muted text-sm"
              >
                {scope}
                <button
                  type="button"
                  onClick={() => removeScope(scope)}
                  className="text-muted-foreground hover:text-foreground"
                >
                  ×
                </button>
              </span>
            ))}
          </div>
        )}
        <p className="text-xs text-muted-foreground">
          Default: openid, profile, email
        </p>
      </div>

      {/* Advanced Options */}
      <details className="space-y-3">
        <summary className="text-sm font-medium cursor-pointer">
          Advanced Options
        </summary>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-3">
          <div className="space-y-2">
            <Label htmlFor="response_type">Response Type</Label>
            <Select
              value={form.response_type || 'code'}
              onValueChange={value => updateForm('response_type', value)}
            >
              <SelectTrigger id="response_type">
                <SelectValue placeholder="code" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="code">code</SelectItem>
                <SelectItem value="id_token">id_token</SelectItem>
                <SelectItem value="token">token</SelectItem>
                <SelectItem value="code id_token">code id_token</SelectItem>
                <SelectItem value="code token">code token</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-2">
            <Label htmlFor="response_mode">Response Mode</Label>
            <Select
              value={form.response_mode || 'query'}
              onValueChange={value => updateForm('response_mode', value)}
            >
              <SelectTrigger id="response_mode">
                <SelectValue placeholder="query" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="query">query</SelectItem>
                <SelectItem value="fragment">fragment</SelectItem>
                <SelectItem value="form_post">form_post</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>
      </details>
    </div>
  )
}
