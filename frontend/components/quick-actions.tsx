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
    <section className="mt-12 grid gap-4 rounded-2xl border border-border bg-surface-raised/80 p-6 text-text-secondary sm:grid-cols-3">
      {quickActions.map(action => (
        <Link
          key={action.title}
          href={action.href}
          className="group flex h-full flex-col justify-between rounded-xl border border-border/60 bg-surface p-4 transition hover:border-primary/40 hover:bg-surface-raised"
        >
          <div>
            <div className="flex items-center gap-3 text-primary">
              <span className="rounded-full border border-primary/30 bg-primary/10 p-2">{action.icon}</span>
              <h3 className="text-base font-semibold text-text-primary">{action.title}</h3>
            </div>
            <p className="mt-3 text-sm text-text-secondary">{action.description}</p>
          </div>
          <span className="mt-4 inline-flex items-center gap-1 text-sm font-medium text-primary transition group-hover:text-primary-dark">
            {action.cta}
            <ArrowRight size={16} />
          </span>
        </Link>
      ))}
    </section>
  );
}
