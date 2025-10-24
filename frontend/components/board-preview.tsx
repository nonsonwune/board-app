'use client';

import { useEffect, useState } from 'react';
import type { BoardCatalogResponse, BoardSummary } from '@board-app/shared';
import Link from 'next/link';
import QuickActions from './quick-actions';
import { formatRelativeTime } from '../lib/date';

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

  const skeletons = loading && boards.length === 0 ? [0, 1, 2, 3] : [];
  const boardCards = boards.length > 0 ? boards : FALLBACK_BOARDS;

  return (
    <div className="min-h-screen bg-surface text-text-primary py-16">
      <div className="mx-auto max-w-5xl px-6">
        <header className="text-center space-y-4">
          <p className="text-sm uppercase tracking-[3px] text-text-tertiary">Realtime beta</p>
          <h1 className="text-4xl font-semibold sm:text-5xl">Board Rooms</h1>
          <p className="mx-auto max-w-2xl text-base text-text-secondary">
            Choose a nearby board to watch live updates from classmates. We replay the recent conversation and stream new events as they happen.
          </p>
          <div className="flex flex-wrap justify-center gap-3">
            <Link
              href="/profile"
              className="inline-flex items-center gap-2 rounded-full bg-primary px-5 py-2 text-xs font-semibold uppercase tracking-[2px] text-white transition hover:bg-primary-dark"
            >
              Set up identity
            </Link>
            <Link
              href="/search"
              className="inline-flex items-center gap-2 rounded-full border border-border/70 px-5 py-2 text-xs font-semibold uppercase tracking-[2px] text-text-secondary transition hover:border-primary/50 hover:text-primary"
            >
              Browse posts
            </Link>
          </div>
        </header>

        <QuickActions />

        {error && (
          <div className="mt-12 rounded-2xl border border-amber-500/40 bg-amber-500/10 p-4 text-sm text-amber-200">
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
            const trendClass = trend !== null
              ? trend > 0
                ? 'text-success'
                : trend < 0
                  ? 'text-danger'
                  : 'text-text-secondary'
              : undefined;

            return (
              <Link
                key={board.id}
                href={`/boards/${board.id}`}
                className="group rounded-2xl border border-border/70 bg-surface-raised/80 p-6 transition hover:border-primary/40 hover:bg-surface-raised"
              >
                <p className="text-xs uppercase tracking-[2px] text-text-tertiary">Board</p>
                <p className="mt-2 text-2xl font-semibold text-text-primary">{board.name}</p>
                <p className="mt-4 text-sm text-text-secondary">{board.description}</p>
                {board.badges.length > 0 && (
                  <div className="mt-4 flex flex-wrap gap-2 text-xs uppercase tracking-[2px] text-text-tertiary">
                    {board.badges.map(badge => (
                      <span key={badge} className="rounded-full border border-border/60 bg-surface px-3 py-0.5">
                        {badge}
                      </span>
                    ))}
                  </div>
                )}

                {(postsLabel || (activeConnections && activeConnections > 0) || lastPostLabel) && (
                  <div className="mt-5 space-y-1 text-xs text-text-secondary">
                    {postsLabel && (
                      <p className="flex items-center gap-2">
                        <span aria-hidden>📝</span>
                        <span>
                          <span className="font-semibold text-text-primary">{postsCountLabel}</span>{' '}
                          {postsSuffix}
                        </span>
                      </p>
                    )}
                    {trendLabel && (
                      <p className={`flex items-center gap-2 ${trendClass ?? ''}`}>
                        <span aria-hidden>📈</span>
                        <span>{trendLabel}</span>
                      </p>
                    )}
                    {activeConnections !== null && activeConnections > 0 && (
                      <p className="flex items-center gap-2 text-danger">
                        <span aria-hidden>🔴</span>
                        <span>
                          <span className="font-semibold">{activeConnections}</span> live now
                        </span>
                      </p>
                    )}
                    {lastPostLabel && (
                      <p className="flex items-center gap-2">
                        <span aria-hidden>⏱️</span>
                        <span>Last post {lastPostLabel}</span>
                      </p>
                    )}
                    {board.radiusLabel && (
                      <p className="flex items-center gap-2">
                        <span aria-hidden>📍</span>
                        <span>{board.radiusLabel}</span>
                      </p>
                    )}
                  </div>
                )}

                <span className="mt-6 inline-flex items-center gap-2 text-sm font-medium text-primary transition group-hover:text-primary-dark">
                  Join live<span aria-hidden>→</span>
                </span>
              </Link>
            );
          })}

          {skeletons.map(value => (
            <div
              key={`skeleton-${value}`}
              className="h-48 rounded-2xl border border-border/60 bg-surface/60 animate-pulse"
            />
          ))}
        </div>
      </div>
    </div>
  );
}
