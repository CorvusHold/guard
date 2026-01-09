import type { PropsWithChildren } from 'react'
import { createContext, useContext, useEffect, useMemo, useState, useCallback } from 'react'
import { getClient } from './sdk'

export interface TenantContextValue {
  tenantId: string
  tenantName?: string
  setTenantId: (id: string) => void
  setTenantName: (name: string) => void
  setTenant: (id: string, name: string) => void
}

const TenantCtx = createContext<TenantContextValue | null>(null)
const LS_ID = 'guard_ui:tenant_id'
const LS_NAME = 'guard_ui:tenant_name'
// Legacy keys used by tests/helpers
const LEGACY_ID = 'tenant_id'
const LEGACY_NAME = 'tenant_name'

export function TenantProvider({
  children
}: PropsWithChildren): React.JSX.Element {
  const [tenantId, setTenantIdState] = useState<string>('')
  const [tenantName, setTenantNameState] = useState<string>('')

  // Fetch tenant name from API if we have ID but no name
  const fetchTenantName = useCallback(async (id: string) => {
    try {
      const client = getClient()
      const res = await client.getTenant(id)
      if (res.meta.status >= 200 && res.meta.status < 300 && res.data) {
        const name = (res.data as any).name
        if (name) {
          setTenantNameState(name)
          localStorage.setItem(LS_NAME, name)
          localStorage.setItem(LEGACY_NAME, name)
        }
      }
    } catch {
      // Ignore errors - name will remain as ID
    }
  }, [])

  useEffect(() => {
    try {
      // Prefer guard_ui keys; fall back to legacy keys used by tests
      const id = localStorage.getItem(LS_ID) || localStorage.getItem(LEGACY_ID)
      const name = localStorage.getItem(LS_NAME) || localStorage.getItem(LEGACY_NAME)
      if (id) setTenantIdState(id)
      if (name) {
        setTenantNameState(name)
      } else if (id) {
        // Fetch name from API if we have ID but no name
        fetchTenantName(id)
      }
    } catch {}
  }, [fetchTenantName])

  const setTenantId = (id: string) => {
    setTenantIdState(id)
    try {
      localStorage.setItem(LS_ID, id || '')
      localStorage.setItem(LEGACY_ID, id || '')
    } catch {}
  }

  const setTenantName = (name: string) => {
    setTenantNameState(name)
    try {
      localStorage.setItem(LS_NAME, name || '')
      localStorage.setItem(LEGACY_NAME, name || '')
    } catch {}
  }

  const setTenant = (id: string, name: string) => {
    setTenantId(id)
    setTenantName(name)
  }

  const value = useMemo<TenantContextValue>(
    () => ({ tenantId, tenantName, setTenantId, setTenantName, setTenant }),
    [tenantId, tenantName]
  )
  return <TenantCtx.Provider value={value}>{children}</TenantCtx.Provider>
}

export function useTenant(): TenantContextValue {
  const ctx = useContext(TenantCtx)
  if (!ctx) throw new Error('useTenant must be used within <TenantProvider>')
  return ctx
}
