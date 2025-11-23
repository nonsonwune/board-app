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
  const boardComplete = joinedBoard;
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
        label: 'Confirm your profile',
        description: verifyComplete
          ? 'Identity confirmed. You can post across campus boards.'
          : 'Confirm your profile to unlock the student-only space.',
        href: '/profile',
        complete: verifyComplete
      },
      {
        id: 'alias',
        label: 'Choose an on-campus alias',
        description: aliasComplete
          ? 'Alias ready. Classmates will recognize you on each board.'
          : 'Pick an alias so classmates know it is really you.',
        href: '/profile#aliases',
        complete: aliasComplete
      },
      {
        id: 'board',
        label: 'Join your first board',
        description: boardComplete
          ? 'Board joined. You are tuned into live campus drops.'
          : 'Jump into a board feed to see live updates from students.',
        href: '/#boards',
        complete: boardComplete
      }
    ],
    [verifyComplete, aliasComplete, boardComplete]
  );

  if (!open) {
    return null;
  }

  return (
    <div className="fixed inset-x-0 bottom-6 z-40 flex justify-center px-4">
      <div className="w-full max-w-xl rounded-2xl border border-border bg-background p-6 shadow-xl">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="space-y-2">
            <p className="text-xs uppercase tracking-[3px] text-text-tertiary">Getting started</p>
            <h2 className="text-2xl font-semibold text-text-primary">Campus onboarding checklist</h2>
            <p className="text-sm text-text-secondary">
              Complete these steps to settle into the campus-only boards experience.
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
            Remind me later
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
                className={`mt-1 flex h-6 w-6 items-center justify-center rounded-full border text-sm font-semibold ${
                  task.complete ? 'border-primary bg-primary text-text-inverse' : 'border-border text-text-tertiary'
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
