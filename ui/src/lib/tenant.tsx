import type { PropsWithChildren } from 'react'
import { createContext, useContext, useEffect, useMemo, useState } from 'react'

export interface TenantContextValue {
  tenantId: string
  tenantName?: string
  setTenantId: (id: string) => void
  setTenantName: (name: string) => void
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

  useEffect(() => {
    try {
      // Prefer guard_ui keys; fall back to legacy keys used by tests
      const id = localStorage.getItem(LS_ID) || localStorage.getItem(LEGACY_ID)
      const name = localStorage.getItem(LS_NAME) || localStorage.getItem(LEGACY_NAME)
      if (id) setTenantIdState(id)
      if (name) setTenantNameState(name)
    } catch {}
  }, [])

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

  const value = useMemo<TenantContextValue>(
    () => ({ tenantId, tenantName, setTenantId, setTenantName }),
    [tenantId, tenantName]
  )
  return <TenantCtx.Provider value={value}>{children}</TenantCtx.Provider>
}

export function useTenant(): TenantContextValue {
  const ctx = useContext(TenantCtx)
  if (!ctx) throw new Error('useTenant must be used within <TenantProvider>')
  return ctx
}
