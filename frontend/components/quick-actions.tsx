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
    href: '/boards',
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
    <section className="mt-12 grid gap-4 rounded-xl border border-slate-800 bg-slate-900/40 p-6 text-slate-300 sm:grid-cols-3">
      {quickActions.map(action => (
        <Link
          key={action.title}
          href={action.href}
          className="group flex h-full flex-col justify-between rounded-lg border border-slate-800 bg-slate-950/40 p-4 transition hover:border-sky-500/40 hover:bg-slate-900"
        >
          <div>
            <div className="flex items-center gap-3 text-sky-300">
              <span className="rounded-full border border-sky-500/30 bg-sky-500/10 p-2">{action.icon}</span>
              <h3 className="text-base font-semibold text-slate-100">{action.title}</h3>
            </div>
            <p className="mt-3 text-sm text-slate-400">{action.description}</p>
          </div>
          <span className="mt-4 inline-flex items-center gap-1 text-sm font-medium text-sky-300 transition group-hover:text-sky-100">
            {action.cta}
            <ArrowRight size={16} />
          </span>
        </Link>
      ))}
    </section>
  );
}
