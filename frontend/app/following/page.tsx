'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import type { BoardPost, FollowingFeedResponse } from '@board-app/shared';
import { statusMessages } from '@board-app/shared';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { Loader2, RefreshCcw } from 'lucide-react';
import { PageShell, PageHeader } from '../../components/page-shell';
import PostCard from '../../components/feed/post-card';
import { useIdentityContext } from '../../context/identity-context';
import { formatBoardName } from '../../lib/board';

const PAGE_SIZE = 10;

type HttpError = Error & { status?: number };

function createHttpError(message: string, status?: number): HttpError {
  const error = new Error(message) as HttpError;
  error.status = status;
  return error;
}

export default function FollowingPage() {
  const [workerBaseUrl] = useState(() => process.env.NEXT_PUBLIC_WORKER_BASE_URL ?? 'http://localhost:8788');
  const { identity, session, refreshSession, setSession } = useIdentityContext();
  const router = useRouter();
  const sessionCopy = statusMessages.session;

  const [posts, setPosts] = useState<BoardPost[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [hasMore, setHasMore] = useState(false);
  const [initialized, setInitialized] = useState(false);
  const cursorRef = useRef<string | null>(null);

  const buildHeaders = useCallback(() => {
    const headers = new Headers();
    if (session?.token) {
      headers.set('Authorization', `Bearer ${session.token}`);
    }
    return headers;
  }, [session?.token]);

  const loadFeed = useCallback(
    async ({ reset = false, cursorOverride = null, retryCount = 0 }: { reset?: boolean; cursorOverride?: string | null; retryCount?: number } = {}) => {
      if (!session?.token) {
        setError('Register an identity to curate your following feed.');
        setInitialized(true);
        return;
      }

      setLoading(true);
      try {
        const url = new URL('/following/feed', workerBaseUrl);
        const cursorToUse = reset ? null : cursorOverride ?? cursorRef.current;
        if (cursorToUse) {
          url.searchParams.set('cursor', cursorToUse);
        }
        url.searchParams.set('limit', String(PAGE_SIZE));

        const res = await fetch(url.toString(), {
          method: 'GET',
          headers: buildHeaders()
        });

        if (res.status === 401 && retryCount < 1) {
          const refreshed = await refreshSession(workerBaseUrl);
          if (refreshed) {
            cursorRef.current = cursorToUse;
            return loadFeed({ reset, cursorOverride: cursorToUse, retryCount: retryCount + 1 });
          }
          setSession(null);
          throw createHttpError(sessionCopy.expired, 401);
        }

        const payload = (await res.json().catch(() => ({}))) as FollowingFeedResponse & { error?: string };
        if (!res.ok || !payload?.ok) {
          throw createHttpError(payload?.error ?? `Failed to load following feed (${res.status})`, res.status);
        }

        setPosts(prev => {
          const base = reset ? payload.posts ?? [] : [...prev, ...(payload.posts ?? [])];
          const map = new Map<string, BoardPost>();
          for (const item of base) {
            map.set(item.id, item);
          }
          return Array.from(map.values());
        });
        setHasMore(payload.hasMore);
        cursorRef.current = payload.cursor ?? null;
        setError(null);
      } catch (err) {
        const message = (err as Error).message ?? 'Unable to load following feed.';
        setError(message);
        if (reset) {
          setPosts([]);
        }
      } finally {
        setLoading(false);
        setInitialized(true);
      }
    },
    [buildHeaders, refreshSession, session?.token, setSession, workerBaseUrl, sessionCopy]
  );

  useEffect(() => {
    if (!identity?.id || !session?.token) {
      setPosts([]);
      cursorRef.current = null;
      setHasMore(false);
      if (!identity?.id) {
        setInitialized(false);
      }
      return;
    }
    loadFeed({ reset: true, cursorOverride: null });
  }, [identity?.id, session?.token, loadFeed]);

  const handleRefresh = useCallback(() => {
    cursorRef.current = null;
    loadFeed({ reset: true, cursorOverride: null });
  }, [loadFeed]);

  const handleLoadMore = useCallback(() => {
    if (!hasMore || loading) return;
    loadFeed({ cursorOverride: cursorRef.current ?? null });
  }, [hasMore, loading, loadFeed]);

  const canViewFeed = Boolean(identity && session?.token);

  return (
    <PageShell>
      <div className="space-y-8">
        <PageHeader
          eyebrow="Following"
          title="Voices you follow"
          description="Cross-board feed pulling in the latest posts from identities you trust."
          actions={
            canViewFeed ? (
              <button
                type="button"
                onClick={handleRefresh}
                className="inline-flex items-center gap-2 rounded-full border border-border/60 px-3 py-1.5 text-xs font-semibold uppercase tracking-[2px] text-text-secondary transition hover:border-primary/50 hover:text-text-primary"
                disabled={loading}
              >
                <RefreshCcw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
                Refresh
              </button>
            ) : null
          }
        />

        {!canViewFeed ? (
          <div className="rounded-2xl border border-border/70 bg-surface-raised/80 p-6 text-sm text-text-secondary">
            <p className="font-medium text-text-primary">Build your identity to follow others.</p>
            <p className="mt-2">Register a pseudonym first, then tap Follow on posts that resonate.</p>
            <Link
              href="/profile"
              className="mt-4 inline-flex items-center gap-2 text-xs uppercase tracking-[2px] text-primary hover:text-primary-light"
            >
              Manage identity →
            </Link>
          </div>
        ) : (
          <section className="space-y-6">
            {error && (
              <div className="rounded-2xl border border-primary/40 bg-primary/10 p-4 text-sm text-primary">
                <p>{error}</p>
                <button
                  type="button"
                  onClick={() => loadFeed({ reset: posts.length === 0, cursorOverride: posts.length === 0 ? null : cursorRef.current })}
                  className="mt-3 inline-flex items-center gap-1 rounded-full border border-primary/40 px-3 py-1 text-xs uppercase tracking-[2px] text-primary transition hover:border-primary hover:text-primary"
                >
                  Try again
                </button>
              </div>
            )}

            {posts.map(post => {
              const boardLabel = formatBoardName(post.boardId, post.boardName);
              return (
                <PostCard
                  key={post.id}
                  post={post}
                  boardName={boardLabel}
                  disabled
                  disabledReason="Open the board to react, reply, or share."
                  onOpen={() => router.push(`/boards/${post.boardId}`)}
                />
              );
            })}

            {loading && posts.length === 0 && (
              <div className="space-y-3">
                {[0, 1, 2].map(index => (
                  <div key={index} className="h-32 rounded-2xl border border-border/60 bg-surface animate-pulse" />
                ))}
              </div>
            )}

            {initialized && !loading && posts.length === 0 && !error && (
              <div className="rounded-2xl border border-border/70 bg-surface-raised/70 p-8 text-center">
                <p className="text-2xl">👥</p>
                <h3 className="mt-3 text-lg font-semibold text-text-primary">You’re not following anyone yet</h3>
                <p className="mt-2 text-sm text-text-secondary">
                  Tap Follow on posts to see updates from your favorite voices here.
                </p>
                <button
                  type="button"
                  onClick={() => router.push('/')}
                  className="mt-4 inline-flex items-center gap-2 rounded-full bg-primary px-4 py-2 text-xs font-semibold uppercase tracking-[2px] text-text-inverse transition hover:bg-primary-light"
                >
                  Discover boards
                </button>
              </div>
            )}

            {hasMore && (
              <div className="flex justify-center">
                <button
                  type="button"
                  onClick={handleLoadMore}
                  disabled={loading}
                  className="inline-flex items-center gap-2 rounded-full border border-border/60 px-4 py-2 text-xs font-semibold uppercase tracking-[2px] text-text-secondary transition hover:border-primary/40 hover:text-text-primary disabled:cursor-not-allowed disabled:opacity-60"
                >
                  {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
                  Load more
                </button>
              </div>
            )}
          </section>
        )}
      </div>
    </PageShell>
  );
}
