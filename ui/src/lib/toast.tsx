import { createContext, useCallback, useContext, useMemo, useState } from 'react';
import type { PropsWithChildren } from 'react';

export type ToastVariant = 'default' | 'success' | 'error';
export interface ToastItem { id: string; title?: string; description?: string; variant?: ToastVariant; }

interface ToastContextValue {
  show: (t: Omit<ToastItem, 'id'>) => void;
}

const ToastCtx = createContext<ToastContextValue | null>(null);

export function ToastProvider({ children }: PropsWithChildren): React.JSX.Element {
  const [items, setItems] = useState<ToastItem[]>([]);

  const show = useCallback((t: Omit<ToastItem, 'id'>) => {
    const id = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const it: ToastItem = { id, ...t };
    setItems((prev) => [...prev, it]);
    // Auto-dismiss after 3s
    window.setTimeout(() => setItems((prev) => prev.filter((x) => x.id !== id)), 3000);
  }, []);

  const value = useMemo<ToastContextValue>(() => ({ show }), [show]);

  return (
    <ToastCtx.Provider value={value}>
      {children}
      {/* Toast container */}
      <div className="fixed z-50 right-3 bottom-3 flex flex-col gap-2">
        {items.map((t) => (
          <div
            key={t.id}
            className={
              'min-w-64 max-w-sm rounded-md border px-3 py-2 text-sm shadow-sm ' +
              (t.variant === 'success'
                ? 'border-green-200 bg-green-50 text-green-800'
                : t.variant === 'error'
                ? 'border-red-200 bg-red-50 text-red-700'
                : 'border-muted bg-background')
            }
          >
            {t.title && <div className="font-medium">{t.title}</div>}
            {t.description && <div className="mt-0.5 opacity-90">{t.description}</div>}
          </div>
        ))}
      </div>
    </ToastCtx.Provider>
  );
}

export function useToast(): ToastContextValue {
  const ctx = useContext(ToastCtx);
  if (!ctx) throw new Error('useToast must be used within <ToastProvider>');
  return ctx;
}
