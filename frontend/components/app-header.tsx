'use client';

import { useState } from 'react';
import NextLink from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import { Menu, X } from 'lucide-react';
import { useIdentityContext } from '../context/identity-context';

export default function AppHeader() {
  const pathname = usePathname();
  const router = useRouter();
  const { identity, hydrated, setIdentity, setSession } = useIdentityContext();
  const [menuOpen, setMenuOpen] = useState(false);

  const navItems = [
    { href: '/', label: 'Boards' },
    { href: '/profile', label: 'Profile' },
    { href: '/admin/phase', label: 'Phase Controls' }
  ];

  const renderLink = (item: (typeof navItems)[number]) => {
    const active = pathname === item.href || (item.href !== '/' && pathname?.startsWith(item.href));
    const baseClasses =
      'rounded-md px-3 py-2 text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/60';
    const activeClasses = 'bg-primary/15 text-primary';
    const inactiveClasses = 'text-text-secondary hover:text-text-primary hover:bg-surface-raised/60';
    return (
      <NextLink
        key={item.href}
        href={item.href}
        onClick={() => setMenuOpen(false)}
        className={`${baseClasses} ${active ? activeClasses : inactiveClasses}`}
      >
        {item.label}
      </NextLink>
    );
  };

  return (
    <header className="border-b border-border/60 bg-surface/80 backdrop-blur supports-[backdrop-filter]:bg-surface/60">
      <div className="mx-auto flex max-w-6xl items-center justify-between gap-4 px-4 py-4 text-text-secondary sm:px-6">
        <NextLink href="/" className="flex items-center gap-3 text-text-primary">
          <span className="inline-flex h-10 w-10 items-center justify-center rounded-full bg-primary/15 text-lg font-semibold text-primary">BR</span>
          <span className="flex flex-col">
            <span className="text-base font-semibold leading-tight text-text-primary sm:text-lg">Board Rooms</span>
            <span className="text-[11px] uppercase tracking-[3px] text-text-tertiary">Realtime campus boards</span>
          </span>
        </NextLink>
        <nav className="hidden items-center gap-2 md:flex">{navItems.map(renderLink)}</nav>
        <div className="hidden text-right text-xs text-text-secondary md:block">
          {!hydrated && <span className="text-text-tertiary">Loading identity…</span>}
          {hydrated && identity && (
            <div className="flex flex-col items-end gap-1">
              <p className="font-medium text-text-primary">{identity.pseudonym}</p>
              <p className="font-mono text-[11px] text-text-tertiary">{identity.id}</p>
              <button
                type="button"
                onClick={() => {
                  setIdentity(null);
                  setSession(null);
                  router.push('/profile');
                }}
                className="rounded-md border border-danger/30 px-3 py-1 text-[11px] uppercase tracking-[2px] text-danger transition-colors hover:border-danger/60 hover:text-danger/80"
              >
                Log out
              </button>
            </div>
          )}
          {hydrated && !identity && (
            <NextLink
              href="/profile"
              className="rounded-md border border-border/60 px-3 py-1 text-text-secondary transition-colors hover:border-primary/60 hover:text-primary"
            >
              Register identity →
            </NextLink>
          )}
        </div>
        <button
          type="button"
          className="inline-flex items-center justify-center rounded-md border border-border/60 p-2 text-text-secondary transition-colors hover:border-primary/50 hover:text-primary md:hidden"
          onClick={() => setMenuOpen(prev => !prev)}
          aria-label="Toggle navigation"
        >
          {menuOpen ? <X size={18} /> : <Menu size={18} />}
        </button>
      </div>
      {menuOpen && (
        <div className="border-t border-border/60 bg-surface/95 px-4 pb-4 text-sm text-text-primary md:hidden">
          <div className="flex flex-col gap-2 py-3">{navItems.map(renderLink)}</div>
          <div className="rounded-lg border border-border/60 bg-surface-raised/70 p-3 text-xs text-text-secondary">
            {!hydrated && <span className="text-text-tertiary">Loading identity…</span>}
            {hydrated && identity && (
              <div className="flex flex-col gap-1">
                <p className="font-medium text-text-primary">{identity.pseudonym}</p>
                <p className="font-mono text-[11px] text-text-tertiary">{identity.id}</p>
                <button
                  type="button"
                  onClick={() => {
                    setIdentity(null);
                    setSession(null);
                    setMenuOpen(false);
                    router.push('/profile');
                  }}
                  className="rounded-md border border-danger/30 px-2 py-1 text-[11px] uppercase tracking-[2px] text-danger transition-colors hover:border-danger/60 hover:text-danger/80"
                >
                  Log out
                </button>
              </div>
            )}
            {hydrated && !identity && (
              <NextLink
                href="/profile"
                onClick={() => setMenuOpen(false)}
                className="text-text-secondary underline-offset-4 transition-colors hover:text-primary hover:underline"
              >
                Register identity to manage aliases
              </NextLink>
            )}
          </div>
        </div>
      )}
    </header>
  );
}
