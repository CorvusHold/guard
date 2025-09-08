import { createContext, useContext, useEffect, useMemo, useState } from 'react';
import type { PropsWithChildren } from 'react';
import { getClient } from '@/lib/sdk';
import { getRuntimeConfig } from '@/lib/runtime';

export type AuthStatus = 'idle' | 'loading' | 'authenticated' | 'unauthenticated';

export interface AuthContextValue {
  status: AuthStatus;
  user: any | null;
  refresh: () => Promise<void>;
  logout: () => Promise<void>;
}

const AuthCtx = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: PropsWithChildren): React.JSX.Element {
  const [status, setStatus] = useState<AuthStatus>('idle');
  const [user, setUser] = useState<any | null>(null);
  const cfg = getRuntimeConfig();

  const isCookieMode = cfg?.auth_mode === 'cookie';

  const refresh = async () => {
    if (!isCookieMode) {
      // In bearer mode we don't require an initial me() fetch for now
      setStatus('authenticated');
      setUser(null);
      return;
    }
    setStatus('loading');
    try {
      const c = getClient();
      const me = await c.me();
      if (me.meta.status === 200) {
        setUser(me.data as any);
        setStatus('authenticated');
      } else {
        setUser(null);
        setStatus('unauthenticated');
      }
    } catch {
      setUser(null);
      setStatus('unauthenticated');
    }
  };

  const logout = async () => {
    try { await getClient().logout(); } catch {}
    try {
      // Clear bearer storage keys in case current mode is bearer
      localStorage.removeItem('guard_ui:guard_access_token');
      localStorage.removeItem('guard_ui:guard_refresh_token');
    } catch {}
    setUser(null);
    setStatus('unauthenticated');
  };

  useEffect(() => {
    void refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isCookieMode]);

  const value = useMemo<AuthContextValue>(() => ({ status, user, refresh, logout }), [status, user]);
  return <AuthCtx.Provider value={value}>{children}</AuthCtx.Provider>;
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthCtx);
  if (!ctx) throw new Error('useAuth must be used within <AuthProvider>');
  return ctx;
}

export function RequireAuth({ children }: PropsWithChildren): React.JSX.Element | null {
  const { status } = useAuth();
  const cfg = getRuntimeConfig();
  const isCookieMode = cfg?.auth_mode === 'cookie';

  useEffect(() => {
    if (!isCookieMode) return; // no-op in bearer mode
    if (status === 'unauthenticated') {
      try { window.location.href = '/'; } catch {}
    }
  }, [status, isCookieMode]);

  if (!isCookieMode) return children as React.JSX.Element;
  if (status === 'loading' || status === 'idle') return <div className="p-6 text-sm text-muted-foreground">Checking session...</div>;
  if (status === 'unauthenticated') return null;
  return children as React.JSX.Element;
}
