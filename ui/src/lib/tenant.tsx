import type { PropsWithChildren } from 'react'
import { createContext, useContext, useEffect, useMemo, useState } from 'react'

export interface TenantContextValue {
  tenantId: string
  setTenantId: (id: string) => void
}

const TenantCtx = createContext<TenantContextValue | null>(null)
const LS_KEY = 'guard_ui:tenant_id'

export function TenantProvider({
  children
}: PropsWithChildren): React.JSX.Element {
  const [tenantId, setTenantIdState] = useState<string>('')

  useEffect(() => {
    try {
      const v = localStorage.getItem(LS_KEY)
      if (v) setTenantIdState(v)
    } catch {}
  }, [])

  const setTenantId = (id: string) => {
    setTenantIdState(id)
    try {
      localStorage.setItem(LS_KEY, id || '')
    } catch {}
  }

  const value = useMemo<TenantContextValue>(
    () => ({ tenantId, setTenantId }),
    [tenantId]
  )
  return <TenantCtx.Provider value={value}>{children}</TenantCtx.Provider>
}

export function useTenant(): TenantContextValue {
  const ctx = useContext(TenantCtx)
  if (!ctx) throw new Error('useTenant must be used within <TenantProvider>')
  return ctx
}
