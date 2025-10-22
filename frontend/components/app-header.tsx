'use client';

import { useState } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { Menu, X } from 'lucide-react';
import { useIdentityContext } from '../context/identity-context';

export default function AppHeader() {
  const pathname = usePathname();
  const { identity } = useIdentityContext();
  const [menuOpen, setMenuOpen] = useState(false);

  const navItems = [
    { href: '/', label: 'Boards' },
    { href: '/profile', label: 'Profile' }
  ];

  const renderLink = (item: (typeof navItems)[number]) => {
    const active = pathname === item.href || (item.href !== '/' && pathname?.startsWith(item.href));
    return (
      <Link
        key={item.href}
        href={item.href}
        onClick={() => setMenuOpen(false)}
        className={`rounded-md px-3 py-1 transition ${active ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/80'}`}
      >
        {item.label}
      </Link>
    );
  };

  return (
    <header className="border-b border-slate-800 bg-slate-950/80 backdrop-blur supports-[backdrop-filter]:bg-slate-950/60">
      <div className="mx-auto flex max-w-5xl items-center justify-between gap-4 px-4 py-4 text-slate-200 sm:px-6">
        <Link href="/" className="text-lg font-semibold text-white">
          Board Rooms
        </Link>
        <nav className="hidden items-center gap-4 text-sm md:flex">{navItems.map(renderLink)}</nav>
        <div className="hidden text-right text-xs text-slate-400 md:block">
          {identity ? (
            <>
              <p className="font-medium text-slate-200">{identity.pseudonym}</p>
              <p className="font-mono text-[11px] text-slate-500">{identity.id}</p>
            </>
          ) : (
            <Link
              href="/profile"
              className="rounded-md border border-slate-700 px-3 py-1 text-slate-300 transition hover:border-sky-500 hover:text-sky-300"
            >
              Register identity →
            </Link>
          )}
        </div>
        <button
          type="button"
          className="inline-flex items-center justify-center rounded-md border border-slate-700 p-2 text-slate-300 transition hover:border-sky-500 hover:text-sky-300 md:hidden"
          onClick={() => setMenuOpen(prev => !prev)}
          aria-label="Toggle navigation"
        >
          {menuOpen ? <X size={18} /> : <Menu size={18} />}
        </button>
      </div>
      {menuOpen && (
        <div className="border-t border-slate-800 bg-slate-950/95 px-4 pb-4 text-sm text-slate-200 md:hidden">
          <div className="flex flex-col gap-2 py-3">{navItems.map(renderLink)}</div>
          <div className="rounded-lg border border-slate-800 bg-slate-900/70 p-3 text-xs text-slate-400">
            {identity ? (
              <>
                <p className="font-medium text-slate-200">{identity.pseudonym}</p>
                <p className="font-mono text-[11px] text-slate-500">{identity.id}</p>
              </>
            ) : (
              <Link
                href="/profile"
                onClick={() => setMenuOpen(false)}
                className="text-slate-300 underline-offset-4 hover:text-sky-300 hover:underline"
              >
                Register identity to manage aliases
              </Link>
            )}
          </div>
        </div>
      )}
    </header>
  );
}
