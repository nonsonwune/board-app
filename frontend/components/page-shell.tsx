
import { ReactNode } from 'react';

interface PageShellProps {
  children: ReactNode;
  className?: string;
}

export function PageShell({ children, className }: PageShellProps) {
  return (
    <main className={`min-h-screen bg-surface text-text-primary transition-colors ${className ?? ''}`}>
      <div className="mx-auto w-full max-w-6xl px-4 py-12 lg:px-8 lg:py-16">{children}</div>
    </main>
  );
}

interface PageHeaderProps {
  title: string;
  eyebrow?: string;
  description?: string;
  actions?: ReactNode;
  badges?: ReactNode;
}

export function PageHeader({ title, eyebrow, description, actions, badges }: PageHeaderProps) {
  return (
    <header className="rounded-2xl border border-border bg-surface-raised/95 p-6 shadow-lg">
      <div className="flex flex-wrap items-start justify-between gap-6">
        <div className="space-y-3">
          {eyebrow && <p className="text-xs uppercase tracking-[4px] text-text-tertiary">{eyebrow}</p>}
          <div className="flex flex-wrap items-center gap-3">
            <h1 className="text-3xl font-semibold text-text-primary sm:text-4xl">{title}</h1>
            {badges}
          </div>
          {description && <p className="max-w-2xl text-sm text-text-secondary">{description}</p>}
        </div>
        {actions && <div className="flex flex-col items-end gap-3 text-sm text-text-secondary">{actions}</div>}
      </div>
    </header>
  );
}
