'use client';

import { ReactNode } from 'react';
import { IdentityProvider } from '../context/identity-context';
import { ToastProvider } from './toast-provider';

export default function Providers({ children }: { children: ReactNode }) {
  return (
    <ToastProvider>
      <IdentityProvider>{children}</IdentityProvider>
    </ToastProvider>
  );
}
