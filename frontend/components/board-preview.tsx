'use client';

import { useEffect, useMemo, useState } from 'react';
import type { BoardCatalogResponse, BoardSummary } from '@board-app/shared';
import Link from 'next/link';
import { Check, Clock } from 'lucide-react';
import QuickActions from './quick-actions';
import { formatRelativeTime } from '../lib/date';
import { useIdentityContext } from '../context/identity-context';
import { ONBOARDING_JOINED_EVENT, readBoardJoinedFlag } from '../lib/onboarding';

type BoardCard = {
  id: string;
  name: string;
  description: string;
  badges: string[];
  activeConnections?: number;
  postsLastHour?: number;
  postsLastDay?: number;
  lastPostAt?: number | null;
  postsTrend24Hr?: number | null;
  radiusLabel?: string | null;
  latitude?: number | null;
  longitude?: number | null;
};

const BOARD_NEW_WINDOW_MS = 7 * 24 * 60 * 60 * 1000;
const BOARD_CATALOG_LIMIT = 12;
const FALLBACK_BOARDS: BoardCard[] = [
  {
    id: 'demo-board',
    name: 'Demo Board',
    description: 'Kick the tires with simulated posts and reactions.',
    badges: ['Featured']
  },
  {
    id: 'campus-north',
    name: 'Campus North',
    description: 'Dorm shout-outs, lost & found, and late-night plans.',
    badges: ['North quad']
  },
  {
    id: 'smoke-board',
    name: 'Smoke Test Board',
    description: 'Internal QA board used for staging rollouts.',
    badges: ['Internal']
  }
];

const WORKER_BASE_URL = (process.env.NEXT_PUBLIC_WORKER_BASE_URL ?? 'http://localhost:8788').replace(/\/$/, '');

function summaryToCard(summary: BoardSummary, now: number): BoardCard {
  const badges = new Set<string>();
  if (summary.phaseMode === 'phase1') {
    badges.add('Phase 1');
  }
  if (summary.textOnly) {
    badges.add('Text only');
  }
  if (summary.radiusMeters) {
    const meters = Math.round(summary.radiusMeters);
    if (meters > 0) {
      badges.add(`${meters.toLocaleString()} m radius`);
    }
  }
  if (now - summary.createdAt < BOARD_NEW_WINDOW_MS) {
    badges.add('New');
  }

  return {
    id: summary.id,
    name: summary.displayName,
    description: summary.description ?? 'Stay updated on events and drop-ins happening nearby.',
    badges: Array.from(badges),
    activeConnections: summary.activeConnections,
    postsLastHour: summary.postsLastHour,
    postsLastDay: summary.postsLastDay,
    postsTrend24Hr: summary.postsTrend24Hr ?? null,
    radiusLabel: summary.radiusLabel ?? null,
    lastPostAt: summary.lastPostAt ?? null
  };
}

export default function BoardPreview() {
  const [boards, setBoards] = useState<BoardCard[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const { identity, aliasMap, session, hydrated } = useIdentityContext();
  const [joinedBoard, setJoinedBoard] = useState(false);

  useEffect(() => {
    const controller = new AbortController();

    async function loadBoards() {
      try {
        setLoading(true);
        const response = await fetch(`${WORKER_BASE_URL}/boards/catalog?limit=${BOARD_CATALOG_LIMIT}`, {
          signal: controller.signal
        });

        if (!response.ok) {
          throw new Error(`catalog request failed (${response.status})`);
        }

        const payload = (await response.json()) as BoardCatalogResponse;
        if (!payload.ok) {
          throw new Error('catalog response not ok');
        }

        const now = Date.now();
        const mapped = (payload.boards ?? []).map(summary => summaryToCard(summary, now));

        if (mapped.length === 0) {
          setBoards(FALLBACK_BOARDS);
          setError('No live boards yet. Showing sample boards while we warm things up.');
        } else {
          setBoards(mapped);
          setError(null);
        }
      } catch (err) {
        if (controller.signal.aborted) {
          return;
        }
        console.warn('[ui] failed to load board catalog', err);
        setBoards(FALLBACK_BOARDS);
        setError('Unable to reach the board service. Showing sample boards for now.');
      } finally {
        if (!controller.signal.aborted) {
          setLoading(false);
        }
      }
    }

    loadBoards();
    return () => controller.abort();
  }, []);

  useEffect(() => {
    setJoinedBoard(readBoardJoinedFlag());
    const handleJoined = () => setJoinedBoard(true);
    if (typeof window !== 'undefined') {
      window.addEventListener(ONBOARDING_JOINED_EVENT, handleJoined);
    }
    return () => {
      if (typeof window !== 'undefined') {
        window.removeEventListener(ONBOARDING_JOINED_EVENT, handleJoined);
      }
    };
  }, []);

  const aliasCount = useMemo(
    () => Object.values(aliasMap).filter(Boolean).length,
    [aliasMap]
  );
  const hasIdentity = Boolean(identity?.id);
  const signedIn = Boolean(session?.token);
  const verifyComplete = Boolean(identity?.id && session?.token);
  const aliasComplete = aliasCount > 0;
  const boardComplete = joinedBoard;
  const onboardingComplete = verifyComplete && aliasComplete && boardComplete;
  const showSignedInHero = hydrated && (hasIdentity || signedIn);

  const primaryCta = useMemo(() => {
    if (!verifyComplete) {
      return {
        href: '/profile',
        label: hasIdentity ? 'Resume verification' : 'Complete verification'
      };
    }
    if (!boardComplete) {
      return { href: '#boards', label: 'Explore campus boards' };
    }
    return { href: '/following', label: 'Open your feed' };
  }, [boardComplete, hasIdentity, verifyComplete]);

  const secondaryCta = useMemo(() => {
    if (verifyComplete && !aliasComplete) {
      return { href: '/profile#aliases', label: 'Lock in your alias' };
    }
    if (verifyComplete && aliasComplete && !boardComplete) {
      return { href: '#boards', label: 'Join your first board' };
    }
    if (onboardingComplete) {
      return { href: '/search', label: 'Search posts' };
    }
    return null;
  }, [aliasComplete, boardComplete, onboardingComplete, verifyComplete]);

  const progressCards = useMemo(
    () => [
      {
        id: 'verify',
        label: 'Profile verification',
        description: verifyComplete
          ? 'Identity confirmed. You can post across campus boards.'
          : hasIdentity
            ? 'Refresh your session to stay connected across boards.'
            : 'Verify once to unlock the student-only space.',
        complete: verifyComplete,
        href: '/profile'
      },
      {
        id: 'alias',
        label: 'Board aliases',
        description: aliasComplete
          ? `Aliases set for ${aliasCount} board${aliasCount === 1 ? '' : 's'}.`
          : 'Choose aliases so classmates recognize you.',
        complete: aliasComplete,
        href: '/profile#aliases'
      },
      {
        id: 'board',
        label: 'Boards joined',
        description: boardComplete
          ? 'You are tuned into live campus updates.'
          : 'Jump into a board feed to see live updates.',
        complete: boardComplete,
        href: '#boards'
      }
    ],
    [aliasComplete, aliasCount, boardComplete, hasIdentity, verifyComplete]
  );

  const skeletons = loading && boards.length === 0 ? [0, 1, 2, 3] : [];
  const boardCards = boards.length > 0 ? boards : FALLBACK_BOARDS;

  return (
    <div className="min-h-screen bg-background text-text-primary">
      {showSignedInHero ? (
        <section className="border-b border-border/60 bg-surface text-text-primary">
          <div className="mx-auto flex max-w-5xl flex-col gap-10 px-6 py-16 sm:py-20">
            <div className="space-y-6">
              <span className="inline-flex items-center gap-2 text-xs uppercase tracking-[3px] text-primary/80">
                {identity?.pseudonym ? `Welcome back, ${identity.pseudonym}` : 'Signed in'}
              </span>
              <h1 className="text-4xl font-semibold leading-tight sm:text-5xl">
                {identity?.pseudonym
                  ? 'Pick up where you left off on campus boards.'
                  : 'Finish getting ready to post with your campus identity.'}
              </h1>
              <p className="max-w-2xl text-lg text-text-secondary">
                {identity?.pseudonym
                  ? 'Dive into the boards you follow, keep your alias current, and track what’s trending right now.'
                  : 'Complete verification, set aliases, and join a board to see what classmates are talking about in real time.'}
              </p>
              <div className="flex flex-wrap gap-3">
                <Link
                  href={primaryCta.href}
                  className="inline-flex items-center justify-center gap-2 rounded-full bg-primary px-6 py-2 text-sm font-semibold uppercase tracking-[2px] text-text-inverse transition hover:bg-primary-dark"
                >
                  {primaryCta.label}
                </Link>
                {secondaryCta && (
                  <Link
                    href={secondaryCta.href}
                    className="inline-flex items-center justify-center gap-2 rounded-full border border-text-secondary/40 px-6 py-2 text-sm font-semibold uppercase tracking-[2px] text-text-primary transition hover:border-primary hover:text-primary"
                  >
                    {secondaryCta.label}
                  </Link>
                )}
              </div>
            </div>

            <div className="grid gap-4 border-t border-border/60 pt-6 text-sm text-text-secondary sm:grid-cols-3">
              {progressCards.map(card => (
                <Link
                  key={card.id}
                  href={card.href}
                  className="group flex h-full flex-col gap-3 rounded-xl border border-border bg-background p-5 transition hover:border-primary hover:bg-surface"
                >
                  <span className="inline-flex h-9 w-9 items-center justify-center rounded-full border border-border bg-surface text-primary">
                    {card.complete ? <Check size={18} /> : <Clock size={18} />}
                  </span>
                  <div className="space-y-1">
                    <p className="text-sm font-semibold text-text-primary">{card.label}</p>
                    <p>{card.description}</p>
                  </div>
                  <span className="text-xs uppercase tracking-[2px] text-primary opacity-0 transition group-hover:opacity-100">
                    {card.complete ? (card.id === 'board' && onboardingComplete ? 'See live boards' : 'Review') : 'Complete'}
                  </span>
                </Link>
              ))}
            </div>
          </div>
        </section>
      ) : (
        <section className="bg-ink text-text-inverse">
          <div className="mx-auto flex max-w-5xl flex-col gap-10 px-6 py-20 sm:py-24">
            <div className="space-y-6">
              <span className="inline-flex items-center gap-2 text-xs uppercase tracking-[3px] text-text-inverse/70">
                Verified campus-only network
              </span>
              <h1 className="text-4xl font-semibold leading-tight sm:text-5xl">
                Campus Boards, Closed to Everyone Else.
              </h1>
              <p className="max-w-2xl text-lg text-text-inverse/80">
                Verified students share updates, organize projects, and stay in the loop without outside noise. Every board uses lightweight identity checks and real-time moderation.
              </p>
              <div className="flex flex-wrap gap-3">
                <Link
                  href="/profile"
                  className="inline-flex items-center justify-center gap-2 rounded-full bg-primary px-6 py-2 text-sm font-semibold uppercase tracking-[2px] text-text-inverse transition hover:bg-primary-dark"
                >
                  Create your profile
                </Link>
                <Link
                  href="#boards"
                  className="inline-flex items-center justify-center gap-2 rounded-full border border-text-inverse/40 px-6 py-2 text-sm font-semibold uppercase tracking-[2px] text-text-inverse transition hover:bg-text-inverse hover:text-ink"
                >
                  Browse live boards
                </Link>
              </div>
            </div>

            <dl className="grid gap-6 border-t border-text-inverse/20 pt-8 text-sm text-text-inverse/80 sm:grid-cols-3">
              <div className="space-y-2">
                <dt className="uppercase tracking-[2px] text-text-inverse">Verify</dt>
                <dd>Confirm your profile to enter a campus-only board. No outside accounts or anonymous drop-ins.</dd>
              </div>
              <div className="space-y-2">
                <dt className="uppercase tracking-[2px] text-text-inverse">Choose Your Alias</dt>
                <dd>Pick a trusted alias per board so classmates know it’s really you without exposing identity.</dd>
              </div>
              <div className="space-y-2">
                <dt className="uppercase tracking-[2px] text-text-inverse">Stay Live</dt>
                <dd>Session refresh keeps you connected through the semester with realtime alerts and posts.</dd>
              </div>
            </dl>
          </div>
        </section>
      )}

      <section className="border-b border-border/60 bg-background">
        <div className="mx-auto flex max-w-5xl flex-col gap-6 px-6 py-12 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h2 className="text-xl font-semibold">Onboarding nudges keep new students on track.</h2>
            <p className="mt-2 max-w-xl text-sm text-text-secondary">
              We guide first-time signups to verify, set their campus alias, and join a board in under a minute. Subtle prompts disappear once the checklist is complete.
            </p>
          </div>
          <ul className="flex flex-col gap-2 text-sm text-text-secondary">
            <li className="flex items-center gap-2">
              <span className="inline-flex h-6 w-6 items-center justify-center rounded-full border border-primary text-primary">1</span>
              Confirm your profile
            </li>
            <li className="flex items-center gap-2">
              <span className="inline-flex h-6 w-6 items-center justify-center rounded-full border border-primary text-primary">2</span>
              Choose an on-campus alias
            </li>
            <li className="flex items-center gap-2">
              <span className="inline-flex h-6 w-6 items-center justify-center rounded-full border border-primary text-primary">3</span>
              Join your first board
            </li>
          </ul>
        </div>
      </section>

      <div className="mx-auto max-w-5xl px-6 pb-20 pt-12">
        <QuickActions />

        {error && (
          <div className="mt-12 rounded-xl border border-primary/40 bg-primary/10 p-4 text-sm text-primary">
            {error}
          </div>
        )}

        <div id="boards" className="mt-12 grid gap-6 sm:grid-cols-2">
          {boardCards.map(board => {
            const activeConnections = typeof board.activeConnections === 'number' ? board.activeConnections : null;
            const postsLastHour = typeof board.postsLastHour === 'number' ? board.postsLastHour : null;
            const postsLastDay = typeof board.postsLastDay === 'number' ? board.postsLastDay : null;
            const lastPostLabel = typeof board.lastPostAt === 'number' ? formatRelativeTime(board.lastPostAt) : null;
            const postsLabel = postsLastHour && postsLastHour > 0
              ? `${postsLastHour} in the last hour`
              : postsLastDay && postsLastDay > 0
                ? `${postsLastDay} today`
                : null;
            const postsLabelParts = postsLabel ? postsLabel.split(' ') : [];
            const postsCountLabel = postsLabelParts.shift();
            const postsSuffix = postsLabelParts.join(' ');
            const trend = typeof board.postsTrend24Hr === 'number' ? board.postsTrend24Hr : null;
            const trendLabel = trend !== null
              ? `${trend > 0 ? '+' : ''}${trend.toFixed(0)}% in 24h`
              : null;

            return (
              <Link
                key={board.id}
                href={`/boards/${board.id}`}
                className="group flex h-full flex-col justify-between rounded-xl border border-border bg-surface p-6 transition hover:border-primary hover:bg-surface-raised"
              >
                <div className="space-y-4">
                  <div className="space-y-2">
                    <p className="text-xs uppercase tracking-[2px] text-text-tertiary">Board</p>
                    <h3 className="text-2xl font-semibold text-text-primary">{board.name}</h3>
                    <p className="text-sm text-text-secondary">{board.description}</p>
                  </div>
                  {board.badges.length > 0 && (
                    <div className="flex flex-wrap gap-2 text-xs uppercase tracking-[2px] text-text-tertiary">
                      {board.badges.map(badge => (
                        <span key={badge} className="rounded-full border border-border bg-background px-3 py-0.5">
                          {badge}
                        </span>
                      ))}
                    </div>
                  )}
                </div>

                {(postsLabel || (activeConnections && activeConnections > 0) || lastPostLabel || board.radiusLabel) && (
                  <div className="mt-6 space-y-2 text-xs text-text-secondary">
                    {postsLabel && (
                      <p>
                        <span className="font-semibold text-text-primary">{postsCountLabel}</span>{' '}
                        {postsSuffix}
                      </p>
                    )}
                    {trendLabel && (
                      <p className="text-primary">{trendLabel}</p>
                    )}
                    {activeConnections !== null && activeConnections > 0 && (
                      <p className="text-primary">
                        <span className="font-semibold">{activeConnections}</span> students live now
                      </p>
                    )}
                    {lastPostLabel && <p>Last post {lastPostLabel}</p>}
                    {board.radiusLabel && <p>{board.radiusLabel}</p>}
                  </div>
                )}

                <span className="mt-6 inline-flex items-center gap-2 text-sm font-medium text-primary transition group-hover:translate-x-1">
                  Join live<span aria-hidden>→</span>
                </span>
              </Link>
            );
          })}

          {skeletons.map(value => (
            <div
              key={`skeleton-${value}`}
              className="h-48 rounded-xl border border-border bg-surface animate-pulse"
            />
          ))}
        </div>
      </div>
    </div>
  );
}
