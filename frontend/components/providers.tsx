'use client';

import { ReactNode } from 'react';
import { IdentityProvider } from '../context/identity-context';
import { AppChromeProvider } from '../context/app-chrome-context';
import { ToastProvider } from './toast-provider';

export default function Providers({ children }: { children: ReactNode }) {
  return (
    <AppChromeProvider>
      <ToastProvider>
        <IdentityProvider>{children}</IdentityProvider>
      </ToastProvider>
    </AppChromeProvider>
  );
}
