import { useCallback, useState } from 'react'
import type { CreateSsoProviderReq } from '@/lib/sdk'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Button } from '@/components/ui/button'
import { Textarea } from '@/components/ui/textarea'
import { Switch } from '@/components/ui/switch'
import { Alert, AlertDescription } from '@/components/ui/alert'

export interface SsoProviderSamlFieldsProps {
  form: Partial<CreateSsoProviderReq>
  updateForm: (key: keyof CreateSsoProviderReq, value: any) => void
  isEditing: boolean
}

export default function SsoProviderSamlFields({
  form,
  updateForm,
  isEditing
}: SsoProviderSamlFieldsProps) {
  const [configMode, setConfigMode] = useState<'url' | 'xml' | 'manual'>('url')

  const CopyableValue = useCallback(
    ({ label, value, description, optional }: { label: string; value?: string; description?: string; optional?: boolean }) => {
      const [copied, setCopied] = useState(false)

      const handleCopy = useCallback(async () => {
        if (!value) return
        try {
          await navigator.clipboard.writeText(value)
          setCopied(true)
          setTimeout(() => setCopied(false), 2000)
        } catch (err) {
          console.error('Failed to copy:', err)
        }
      }, [value])

      return (
        <div className="space-y-1.5" data-testid={`sp-field-${label.toLowerCase().replace(/\s+/g, '-')}`}>
          <div className="flex items-center gap-2">
            <label className="text-sm font-medium text-foreground">
              {label}
              {optional && <span className="text-muted-foreground ml-1">(Optional)</span>}
            </label>
          </div>
          {description && <p className="text-xs text-muted-foreground">{description}</p>}
          <div className="flex items-center gap-2">
            <code className="flex-1 px-3 py-2 text-sm bg-muted rounded-md font-mono break-all">{value || 'Generated after save'}</code>
            <Button
              type="button"
              variant="outline"
              size="sm"
              disabled={!value}
              onClick={handleCopy}
              className="shrink-0"
              data-testid={`copy-${label.toLowerCase().replace(/\s+/g, '-')}`}
            >
              {copied ? 'Copied!' : 'Copy'}
            </Button>
          </div>
        </div>
      )
    },
    []
  )

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-2">
        <h4 className="text-sm font-medium">SAML Configuration</h4>
        {!isEditing && (
          <span className="text-[11px] text-muted-foreground">
            SP URLs live in the checklist above once slug is set
          </span>
        )}
      </div>

      {/* IdP Metadata Method */}
      <div className="space-y-2">
        <Label>IdP Metadata Method</Label>
        <div className="flex gap-2 flex-wrap">
          <Button
            type="button"
            variant={configMode === 'url' ? 'default' : 'outline'}
            size="sm"
            onClick={() => setConfigMode('url')}
          >
            Metadata URL
          </Button>
          <Button
            type="button"
            variant={configMode === 'xml' ? 'default' : 'outline'}
            size="sm"
            onClick={() => setConfigMode('xml')}
          >
            Metadata XML
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

      {/* Metadata URL */}
      {configMode === 'url' && (
        <div className="space-y-2">
          <Label htmlFor="idp_metadata_url">IdP Metadata URL *</Label>
          <Input
            id="idp_metadata_url"
            type="url"
            value={form.idp_metadata_url || ''}
            onChange={e => updateForm('idp_metadata_url', e.target.value)}
            placeholder="https://example.okta.com/app/xxx/sso/saml/metadata"
            required
          />
          <p className="text-xs text-muted-foreground">
            The IdP metadata will be fetched and parsed automatically
          </p>
        </div>
      )}

      {/* Metadata XML */}
      {configMode === 'xml' && (
        <div className="space-y-2">
          <Label htmlFor="idp_metadata_xml">IdP Metadata XML *</Label>
          <Textarea
            id="idp_metadata_xml"
            value={form.idp_metadata_xml || ''}
            onChange={e => updateForm('idp_metadata_xml', e.target.value)}
            placeholder="Paste the IdP metadata XML here..."
            rows={8}
            required
          />
          <p className="text-xs text-muted-foreground">
            Paste the complete SAML metadata XML from your IdP
          </p>
        </div>
      )}

      {/* Manual Configuration */}
      {configMode === 'manual' && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-2 md:col-span-2">
              <Label htmlFor="idp_entity_id">IdP Entity ID *</Label>
              <Input
                id="idp_entity_id"
                value={form.idp_entity_id || ''}
                onChange={e => updateForm('idp_entity_id', e.target.value)}
                placeholder="http://www.okta.com/exk..."
                required
              />
            </div>

            <div className="space-y-2 md:col-span-2">
              <Label htmlFor="idp_sso_url">IdP SSO URL *</Label>
              <Input
                id="idp_sso_url"
                type="url"
                value={form.idp_sso_url || ''}
                onChange={e => updateForm('idp_sso_url', e.target.value)}
                placeholder="https://example.okta.com/app/xxx/sso/saml"
                required
              />
            </div>

            <div className="space-y-2 md:col-span-2">
              <Label htmlFor="idp_slo_url">IdP SLO URL (Optional)</Label>
              <Input
                id="idp_slo_url"
                type="url"
                value={form.idp_slo_url || ''}
                onChange={e => updateForm('idp_slo_url', e.target.value)}
                placeholder="https://example.okta.com/app/xxx/slo/saml"
              />
            </div>

            <div className="space-y-2 md:col-span-2">
              <Label htmlFor="idp_certificate">IdP Certificate (PEM format) *</Label>
              <Textarea
                id="idp_certificate"
                value={form.idp_certificate || ''}
                onChange={e => updateForm('idp_certificate', e.target.value)}
                placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"
                rows={5}
                required
              />
              <p className="text-xs text-muted-foreground">
                X.509 certificate in PEM format for verifying IdP signatures
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Service Provider Configuration - hide in create mode */}
      {isEditing && (
        <div className="space-y-4 pt-4 border-t">
          <div className="flex items-start justify-between gap-3">
            <div>
              <h5 className="text-sm font-medium">Service Provider Configuration</h5>
              <p className="text-xs text-muted-foreground">
                These URLs are generated from the slug & tenant. Copy them into your IdP; editing is not required.
              </p>
            </div>
          </div>

          <div className="space-y-3">
            <CopyableValue
              label="SP Entity ID"
              value={form.entity_id}
              description="Also called Identifier or Audience URI"
            />
            <CopyableValue
              label="ACS URL"
              value={form.acs_url}
              description="Assertion Consumer Service URL (Reply URL)"
            />
            <CopyableValue
              label="SLO URL"
              value={form.slo_url}
              description="Single Logout URL"
              optional
            />
          </div>
        </div>
      )}

      {/* Security Options */}
      <div className="space-y-3 pt-4 border-t">
        <h5 className="text-sm font-medium">Security Options</h5>

        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <div className="space-y-0.5">
              <Label htmlFor="want_assertions_signed">Require Signed Assertions</Label>
              <p className="text-xs text-muted-foreground">
                Require the IdP to sign SAML assertions
              </p>
            </div>
            <Switch
              id="want_assertions_signed"
              checked={form.want_assertions_signed ?? true}
              onCheckedChange={checked => updateForm('want_assertions_signed', checked)}
            />
          </div>

          <div className="flex items-center justify-between">
            <div className="space-y-0.5">
              <Label htmlFor="want_response_signed">Require Signed Response</Label>
              <p className="text-xs text-muted-foreground">
                Require the IdP to sign the SAML response
              </p>
            </div>
            <Switch
              id="want_response_signed"
              checked={form.want_response_signed ?? false}
              onCheckedChange={checked => updateForm('want_response_signed', checked)}
            />
          </div>

          <div className="flex items-center justify-between">
            <div className="space-y-0.5">
              <Label htmlFor="sign_requests">Sign Authentication Requests</Label>
              <p className="text-xs text-muted-foreground">
                Sign outgoing SAML authentication requests
              </p>
            </div>
            <Switch
              id="sign_requests"
              checked={form.sign_requests ?? false}
              onCheckedChange={checked => updateForm('sign_requests', checked)}
            />
          </div>

          <div className="flex items-center justify-between">
            <div className="space-y-0.5">
              <Label htmlFor="force_authn">Force Re-authentication</Label>
              <p className="text-xs text-muted-foreground">
                Require users to re-authenticate on each login
              </p>
            </div>
            <Switch
              id="force_authn"
              checked={form.force_authn ?? false}
              onCheckedChange={checked => updateForm('force_authn', checked)}
            />
          </div>
        </div>
      </div>

      {/* SP Signing Certificates (if sign_requests is enabled) */}
      {form.sign_requests && (
        <div className="space-y-4 pt-4 border-t">
          <h5 className="text-sm font-medium">Signing Certificates</h5>

          <div className="space-y-2">
            <Label htmlFor="sp_certificate">SP Certificate (PEM format)</Label>
            <Textarea
              id="sp_certificate"
              value={form.sp_certificate || ''}
              onChange={e => updateForm('sp_certificate', e.target.value)}
              placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"
              rows={5}
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="sp_private_key">
              SP Private Key (PEM format) {!isEditing && form.sign_requests && '*'}
            </Label>
            <Textarea
              id="sp_private_key"
              value={form.sp_private_key || ''}
              onChange={e => updateForm('sp_private_key', e.target.value)}
              placeholder={isEditing ? '(unchanged if empty)' : '-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----'}
              rows={5}
              required={!isEditing && form.sign_requests}
            />
            {isEditing && (
              <p className="text-xs text-muted-foreground">
                Leave empty to keep existing private key
              </p>
            )}
          </div>

          <p className="text-xs text-muted-foreground">
            Warning: Store private keys securely. Never expose them in logs or client-side code.
          </p>
        </div>
      )}
    </div>
  )
}
