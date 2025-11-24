'use client';

import { useEffect, useMemo, useState } from 'react';
import Link from 'next/link';
import { Check } from 'lucide-react';
import { useIdentityContext } from '../context/identity-context';
import { ONBOARDING_JOINED_EVENT, readBoardJoinedFlag, readSnoozeFlag, setSnoozeFlag } from '../lib/onboarding';

interface ChecklistTask {
  id: 'verify' | 'alias' | 'board';
  label: string;
  description: string;
  href: string;
  complete: boolean;
}

export default function OnboardingChecklist() {
  const { identity, aliasMap, session, hydrated } = useIdentityContext();
  const [open, setOpen] = useState(false);
  const [joinedBoard, setJoinedBoard] = useState(false);
  const [snoozed, setSnoozed] = useState(false);

  const aliasCount = useMemo(
    () => Object.values(aliasMap).filter(Boolean).length,
    [aliasMap]
  );

  useEffect(() => {
    if (typeof window === 'undefined') {
      return;
    }
    setJoinedBoard(readBoardJoinedFlag());
    setSnoozed(readSnoozeFlag());

    const handleJoined = () => setJoinedBoard(true);
    window.addEventListener(ONBOARDING_JOINED_EVENT, handleJoined);

    return () => {
      window.removeEventListener(ONBOARDING_JOINED_EVENT, handleJoined);
    };
  }, []);

  const verifyComplete = Boolean(identity?.id && session?.token);
  const aliasComplete = aliasCount > 0;
  const boardComplete = joinedBoard && verifyComplete;
  const allComplete = verifyComplete && aliasComplete && boardComplete;

  useEffect(() => {
    if (!hydrated) {
      return;
    }
    if (allComplete) {
      setOpen(false);
      setSnoozeFlag(false);
      return;
    }
    if (snoozed) {
      setOpen(false);
      return;
    }
    setOpen(true);
  }, [hydrated, allComplete, snoozed]);

  const progress = useMemo(() => {
    const completedCount = [verifyComplete, aliasComplete, boardComplete].filter(Boolean).length;
    return completedCount / 3;
  }, [verifyComplete, aliasComplete, boardComplete]);

  const tasks: ChecklistTask[] = useMemo(
    () => [
      {
        id: 'verify',
        label: 'Create your identity',
        description: verifyComplete
          ? '✓ Done! You can now post and react on all boards.'
          : 'Choose a pseudonym to join your campus community. (30 seconds)',
        href: '/profile#identity',
        complete: verifyComplete
      },
      {
        id: 'alias',
        label: 'Set your board nickname',
        description: aliasComplete
          ? `✓ Nice! Set on ${aliasCount} board${aliasCount === 1 ? '' : 's'}.`
          : 'Optional: Add a nickname for each board you join.',
        href: '/profile#aliases',
        complete: aliasComplete
      },
      {
        id: 'board',
        label: 'Join a board',
        description: boardComplete
          ? '✓ You\u0027re in! Start posting and reacting to classmates.'
          : 'Browse boards and join one near you to see what\u0027s happening.',
        href: '/#boards',
        complete: boardComplete
      }
    ],
    [verifyComplete, aliasComplete, boardComplete, aliasCount]
  );

  if (!open) {
    if (snoozed && !allComplete) {
      return (
        <div className="fixed bottom-20 right-4 z-40 md:bottom-6">
          <button
            type="button"
            onClick={() => {
              setSnoozeFlag(false);
              setSnoozed(false);
              setOpen(true);
            }}
            className="flex items-center gap-2 rounded-full border border-primary/20 bg-surface-raised px-4 py-2 shadow-lg transition hover:border-primary hover:text-primary"
          >
            <div className="relative h-3 w-3">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-primary opacity-75" />
              <span className="relative inline-flex h-3 w-3 rounded-full bg-primary" />
            </div>
            <span className="text-xs font-semibold uppercase tracking-[1.5px] text-text-secondary">Finish Setup</span>
          </button>
        </div>
      );
    }
    return null;
  }

  return (
    <div className="fixed inset-x-0 bottom-20 z-40 flex justify-center px-4 md:bottom-6">
      <div className="w-full max-w-xl rounded-2xl border border-border bg-background p-6 shadow-xl">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="space-y-2">
            <p className="text-xs uppercase tracking-[3px] text-text-tertiary">Getting started</p>
            <h2 className="text-2xl font-semibold text-text-primary">Get the most out of Board Rooms</h2>
            <p className="text-sm text-text-secondary">
              Complete these quick steps to start connecting with your campus.
            </p>
          </div>
          <button
            type="button"
            onClick={() => {
              setSnoozeFlag(true);
              setSnoozed(true);
              setOpen(false);
            }}
            className="rounded-full border border-border px-3 py-1 text-xs uppercase tracking-[2px] text-text-secondary transition hover:border-primary hover:text-primary"
          >
            Minimize
          </button>
        </div>

        <div className="mt-6">
          <div className="h-1.5 w-full rounded-full bg-border/60">
            <div
              className="h-full rounded-full bg-primary transition-all"
              style={{ width: `${Math.max(progress * 100, 4)}%` }}
            />
          </div>
        </div>

        <ul className="mt-6 space-y-4">
          {tasks.map(task => (
            <li key={task.id} className="flex items-start gap-4">
              <span
                className={`mt-1 flex h-6 w-6 items-center justify-center rounded-full border text-sm font-semibold ${task.complete ? 'border-primary bg-primary text-text-inverse' : 'border-border text-text-tertiary'
                  }`}
                aria-hidden
              >
                {task.complete ? <Check size={16} /> : tasks.findIndex(t => t.id === task.id) + 1}
              </span>
              <div className="flex-1 space-y-1">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <p className="text-sm font-semibold text-text-primary">{task.label}</p>
                  {!task.complete && (
                    <Link
                      href={task.href}
                      className="text-xs uppercase tracking-[2px] text-primary transition hover:text-primary/80"
                    >
                      Go
                    </Link>
                  )}
                </div>
                <p className="text-sm text-text-secondary">{task.description}</p>
              </div>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
