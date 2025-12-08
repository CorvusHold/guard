import { useState, useEffect, useCallback } from 'react'
import { getClient } from '@/lib/sdk'
import type { SsoSPInfoResp } from '@/lib/sdk'
import { Button } from '@/components/ui/button'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'

export interface SsoSetupChecklistProps {
  slug: string
  tenantId: string
  isSaml: boolean
  onReady?: () => void
  className?: string
}

interface CopyableFieldProps {
  label: string
  value: string
  description?: string
  optional?: boolean
}

function CopyableField({ label, value, description, optional }: CopyableFieldProps) {
  const [copied, setCopied] = useState(false)

  const handleCopy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(value)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch (err) {
      console.error('Failed to copy:', err)
    }
  }, [value])

  const testId = 'sp-field-' + label.toLowerCase().replace(/\s+/g, '-')
  const copyTestId = 'copy-' + label.toLowerCase().replace(/\s+/g, '-')

  return (
    <div className="space-y-1.5" data-testid={testId}>
      <div className="flex items-center gap-2">
        <label className="text-sm font-medium text-foreground">
          {label}
          {optional && <span className="text-muted-foreground ml-1">(Optional)</span>}
        </label>
      </div>
      {description && (
        <p className="text-xs text-muted-foreground">{description}</p>
      )}
      <div className="flex items-center gap-2">
        <code className="flex-1 px-3 py-2 text-sm bg-muted rounded-md font-mono break-all">
          {value}
        </code>
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={handleCopy}
          className="shrink-0"
          data-testid={copyTestId}
        >
          {copied ? 'Copied!' : 'Copy'}
        </Button>
      </div>
    </div>
  )
}

interface ChecklistItemProps {
  checked: boolean
  onToggle: () => void
  children: React.ReactNode
}

function ChecklistItem({ checked, onToggle, children }: ChecklistItemProps) {
  return (
    <label className="flex items-start gap-3 cursor-pointer group">
      <input
        type="checkbox"
        checked={checked}
        onChange={onToggle}
        className="mt-0.5 h-4 w-4 rounded border-gray-300 text-primary focus:ring-primary"
      />
      <span className={'text-sm ' + (checked ? 'text-muted-foreground line-through' : 'text-foreground')}>
        {children}
      </span>
    </label>
  )
}

export default function SsoSetupChecklist({
  slug,
  tenantId,
  isSaml,
  onReady,
  className
}: SsoSetupChecklistProps) {
  const [spInfo, setSpInfo] = useState<SsoSPInfoResp | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  
  const [hasIdpAccess, setHasIdpAccess] = useState(false)
  const [knowsConfigMethod, setKnowsConfigMethod] = useState(false)
  const [hasIdpDetails, setHasIdpDetails] = useState(false)

  useEffect(() => {
    if (!slug || !isSaml || !tenantId) {
      setSpInfo(null)
      return
    }

    const fetchSpInfo = async () => {
      setLoading(true)
      setError(null)
      try {
        const res = await getClient().ssoGetSPInfo(slug, tenantId)
        if (res.meta.status >= 200 && res.meta.status < 300) {
          setSpInfo(res.data)
        } else {
          const errData = res.data as unknown as { error?: string }
          setError(errData?.error || 'Failed to load SP configuration')
        }
      } catch (e: unknown) {
        const err = e as Error
        setError(err?.message || String(e))
      } finally {
        setLoading(false)
      }
    }

    fetchSpInfo()
  }, [slug, tenantId, isSaml])

  const allChecked = hasIdpAccess && knowsConfigMethod && hasIdpDetails

  if (!isSaml) {
    return null
  }

  return (
    <div className={className} data-testid="sso-setup-checklist">
      <Card className="mb-4">
        <CardHeader className="pb-3">
          <CardTitle className="text-base">Before You Begin</CardTitle>
          <CardDescription>
            Complete these steps before configuring your SAML provider
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <ChecklistItem checked={hasIdpAccess} onToggle={() => setHasIdpAccess(!hasIdpAccess)}>
            <span>
              I have <strong>admin access</strong> to my Identity Provider
            </span>
          </ChecklistItem>
          
          <ChecklistItem checked={knowsConfigMethod} onToggle={() => setKnowsConfigMethod(!knowsConfigMethod)}>
            <span>
              I know my configuration method (metadata URL, XML, or manual)
            </span>
          </ChecklistItem>
          
          <ChecklistItem checked={hasIdpDetails} onToggle={() => setHasIdpDetails(!hasIdpDetails)}>
            <span>
              I have my IdP Entity ID, SSO URL, and X.509 certificate
            </span>
          </ChecklistItem>

          {allChecked && (
            <Alert className="mt-4 border-green-200 bg-green-50">
              <AlertTitle className="text-green-800">Ready to proceed</AlertTitle>
              <AlertDescription className="text-green-700">
                Configure your IdP with the SP URLs below, then complete the form.
              </AlertDescription>
            </Alert>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">Service Provider (SP) Configuration</CardTitle>
          <CardDescription>
            Copy these URLs into your Identity Provider SAML settings
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {loading && (
            <div className="text-sm text-muted-foreground" data-testid="sp-info-loading">
              Loading SP configuration...
            </div>
          )}

          {error && (
            <Alert variant="destructive" data-testid="sp-info-error">
              <AlertTitle>Configuration Error</AlertTitle>
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}

          {spInfo && !loading && !error && (
            <div data-testid="sp-info-urls">
              <CopyableField
                label="SP Entity ID"
                value={spInfo.entity_id}
                description="Also called Identifier or Audience URI"
              />

              <CopyableField
                label="ACS URL"
                value={spInfo.acs_url}
                description="Assertion Consumer Service URL (Reply URL)"
              />

              <CopyableField
                label="SLO URL"
                value={spInfo.slo_url || ''}
                description="Single Logout URL (optional)"
                optional
              />

              <CopyableField
                label="Metadata URL"
                value={spInfo.metadata_url}
                description="SP Metadata for auto-configuration"
              />
            </div>
          )}

          {!slug && (
            <Alert data-testid="sp-info-no-slug">
              <AlertDescription>
                Enter a provider slug above to see the SP configuration URLs.
              </AlertDescription>
            </Alert>
          )}

          {slug && !tenantId && (
            <Alert variant="destructive" data-testid="sp-info-no-tenant">
              <AlertDescription>
                Tenant ID is required to generate SP URLs.
              </AlertDescription>
            </Alert>
          )}
        </CardContent>
      </Card>

      {onReady && allChecked && spInfo && (
        <div className="mt-4 flex justify-end">
          <Button onClick={onReady} data-testid="sso-checklist-ready">
            Continue
          </Button>
        </div>
      )}
    </div>
  )
}
