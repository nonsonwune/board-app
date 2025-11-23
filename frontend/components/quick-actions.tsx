'use client';

import Link from 'next/link';
import { ReactNode } from 'react';
import { ArrowRight, PenSquare, MapPin, Bell } from 'lucide-react';

interface QuickAction {
  title: string;
  description: string;
  href: string;
  icon: ReactNode;
  cta: string;
}

const quickActions: QuickAction[] = [
  {
    title: 'Post Something',
    description: 'Share a campus update, promote a meetup, or ask for study buddies.',
    href: '#boards',
    icon: <PenSquare size={18} />, 
    cta: 'Jump to boards'
  },
  {
    title: 'Pin Your Alias',
    description: 'Set aliases for each board so friends recognize you locally.',
    href: '/profile#aliases',
    icon: <MapPin size={18} />, 
    cta: 'Manage aliases'
  },
  {
    title: 'Enable Notifications',
    description: 'Get notified when classmates reply or hot posts appear nearby.',
    href: '/profile#notifications',
    icon: <Bell size={18} />, 
    cta: 'Update preferences'
  }
];

export default function QuickActions() {
  return (
    <section className="mt-12 grid gap-4 rounded-xl border border-border bg-surface p-6 text-text-secondary sm:grid-cols-3">
      {quickActions.map(action => (
        <Link
          key={action.title}
          href={action.href}
          className="group flex h-full flex-col justify-between rounded-lg border border-border bg-background px-4 py-5 transition hover:border-primary hover:bg-surface"
        >
          <div className="space-y-3">
            <div className="flex items-center gap-3 text-primary">
              <span className="inline-flex h-9 w-9 items-center justify-center rounded-full border border-primary/40 bg-primary/10 text-primary">
                {action.icon}
              </span>
              <h3 className="text-base font-semibold text-text-primary">{action.title}</h3>
            </div>
            <p className="text-sm leading-6 text-text-secondary">{action.description}</p>
          </div>
          <span className="mt-6 inline-flex items-center gap-1 text-sm font-medium text-primary transition group-hover:translate-x-1">
            {action.cta}
            <ArrowRight size={16} />
          </span>
        </Link>
      ))}
    </section>
  );
}
