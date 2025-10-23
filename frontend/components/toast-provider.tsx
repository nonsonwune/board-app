'use client';

import { createContext, useCallback, useContext, useMemo, useState, ReactNode } from 'react';

type Toast = {
  id: number;
  title: string;
  description?: string;
};

type ToastContextValue = {
  addToast: (toast: Omit<Toast, 'id'>) => void;
};

const ToastContext = createContext<ToastContextValue | undefined>(undefined);

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);

  const removeToast = useCallback((id: number) => {
    setToasts(prev => prev.filter(toast => toast.id !== id));
  }, []);

  const addToast = useCallback(
    (toast: Omit<Toast, 'id'>) => {
      const id = Date.now();
      setToasts(prev => [...prev, { ...toast, id }]);
      window.setTimeout(() => removeToast(id), 5000);
    },
    [removeToast]
  );

  const value = useMemo<ToastContextValue>(() => ({ addToast }), [addToast]);

  return (
    <ToastContext.Provider value={value}>
      {children}
      <div className="pointer-events-none fixed bottom-4 right-4 z-50 flex w-80 flex-col gap-2">
        {toasts.map(toast => (
          <div
            key={toast.id}
            className="pointer-events-auto rounded-lg border border-slate-700 bg-slate-900/90 px-4 py-3 text-sm text-slate-100 shadow-lg shadow-slate-950/50"
          >
            <div className="flex items-start gap-3">
              <div className="flex-1">
                <p className="font-semibold text-slate-100">{toast.title}</p>
                {toast.description && <p className="mt-1 text-xs text-slate-400">{toast.description}</p>}
              </div>
              <button
                type="button"
                aria-label="Dismiss"
                onClick={() => removeToast(toast.id)}
                className="rounded border border-slate-700 px-2 py-1 text-[10px] uppercase tracking-[2px] text-slate-400 transition hover:border-slate-500 hover:text-slate-200"
              >
                Close
              </button>
            </div>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast(): ToastContextValue {
  const context = useContext(ToastContext);
  if (!context) {
    throw new Error('useToast must be used within a ToastProvider');
  }
  return context;
}
