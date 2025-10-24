'use client';

import { FormEvent, useCallback, useEffect, useRef, useState } from 'react';
import type { BoardPost, SearchPostsResponse } from '@board-app/shared';
import { Loader2, Search as SearchIcon } from 'lucide-react';
import PostCard from '../../components/feed/post-card';
import { PageShell, PageHeader } from '../../components/page-shell';
import { useIdentityContext } from '../../context/identity-context';
import { formatBoardName } from '../../lib/board';
import { useRouter } from 'next/navigation';

const PAGE_SIZE = 12;
const WINDOW_OPTIONS = [
  { label: 'Last 7 days', value: 7 * 24 * 60 * 60 * 1000 },
  { label: 'Last 30 days', value: 30 * 24 * 60 * 60 * 1000 }
];

type HttpError = Error & { status?: number };

function createHttpError(message: string, status?: number): HttpError {
  const error = new Error(message) as HttpError;
  error.status = status;
  return error;
}

export default function SearchPage() {
  const [workerBaseUrl] = useState(() => process.env.NEXT_PUBLIC_WORKER_BASE_URL ?? 'http://localhost:8788');
  const { session } = useIdentityContext();
  const router = useRouter();

  const [query, setQuery] = useState('');
  const [boardId, setBoardId] = useState('');
  const [windowMs, setWindowMs] = useState(WINDOW_OPTIONS[0].value);
  const [results, setResults] = useState<BoardPost[]>([]);
  const [topics, setTopics] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [hasMore, setHasMore] = useState(false);
  const [initialized, setInitialized] = useState(false);
  const cursorRef = useRef<string | null>(null);
  const mountedRef = useRef(false);

  const buildHeaders = useCallback(() => {
    const headers = new Headers();
    if (session?.token) {
      headers.set('Authorization', `Bearer ${session.token}`);
    }
    return headers;
  }, [session?.token]);

  const executeSearch = useCallback(
    async ({
      reset = false,
      cursorOverride = null,
      queryOverride = null,
      boardOverride = null
    }: {
      reset?: boolean;
      cursorOverride?: string | null;
      queryOverride?: string | null;
      boardOverride?: string | null;
    } = {}) => {
      setLoading(true);
      try {
        const url = new URL('/search/posts', workerBaseUrl);
        const trimmedBoard = (boardOverride ?? boardId).trim();
        const trimmedQuery = (queryOverride ?? query).trim();
        if (trimmedBoard) {
          url.searchParams.set('boardId', trimmedBoard);
        }
        if (trimmedQuery) {
          url.searchParams.set('q', trimmedQuery);
        }
        url.searchParams.set('limit', String(PAGE_SIZE));
        url.searchParams.set('windowMs', String(windowMs));

        const cursorToUse = reset ? null : cursorOverride ?? cursorRef.current;
        if (cursorToUse) {
          url.searchParams.set('cursor', cursorToUse);
        }

        const res = await fetch(url.toString(), {
          method: 'GET',
          headers: buildHeaders()
        });

        const payload = (await res.json().catch(() => ({}))) as SearchPostsResponse & { error?: string };
        if (!res.ok || !payload?.ok) {
          throw createHttpError(payload?.error ?? `Search failed (${res.status})`, res.status);
        }

        setResults(prev => {
          const base = reset ? payload.posts ?? [] : [...prev, ...(payload.posts ?? [])];
          const map = new Map<string, BoardPost>();
          for (const item of base) {
            map.set(item.id, item);
          }
          return Array.from(map.values());
        });
        setTopics(payload.topics ?? []);
        setHasMore(payload.hasMore);
        cursorRef.current = payload.cursor ?? null;
        setError(null);
      } catch (err) {
        const message = (err as Error).message ?? 'Unable to search right now.';
        setError(message);
        if (reset) {
          setResults([]);
        }
      } finally {
        setLoading(false);
        setInitialized(true);
      }
    },
    [boardId, buildHeaders, query, windowMs, workerBaseUrl]
  );

  useEffect(() => {
    if (mountedRef.current) return;
    mountedRef.current = true;
    executeSearch({ reset: true, cursorOverride: null });
  }, [executeSearch]);

  const handleSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    cursorRef.current = null;
    executeSearch({ reset: true, cursorOverride: null });
  };

  const handleLoadMore = () => {
    if (!hasMore || loading) return;
    executeSearch({ cursorOverride: cursorRef.current ?? null });
  };

  const handleTopicSelect = (topic: string) => {
    setQuery(topic);
    cursorRef.current = null;
    executeSearch({ reset: true, cursorOverride: null, queryOverride: topic });
  };

  return (
    <PageShell>
      <div className="space-y-8">
        <PageHeader
          eyebrow="Discover"
          title="Search boards"
          description="Find posts, topics, and live threads across the boards you can access."
        />

        <section className="rounded-2xl border border-border/70 bg-surface-raised/80 p-6 shadow-sm">
          <form onSubmit={handleSubmit} className="grid gap-4 md:grid-cols-[1fr,220px,160px,auto] md:items-end">
            <label className="flex flex-col gap-2 text-xs uppercase tracking-[2px] text-text-tertiary">
              Query
              <div className="relative">
                <SearchIcon className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-text-tertiary" />
                <input
                  value={query}
                  onChange={event => setQuery(event.target.value)}
                  placeholder="Search posts or topics"
                  className="w-full rounded-xl border border-border/60 bg-surface px-9 py-2 text-sm text-text-primary placeholder:text-text-tertiary focus:border-primary focus:outline-none"
                />
              </div>
            </label>

            <label className="flex flex-col gap-2 text-xs uppercase tracking-[2px] text-text-tertiary">
              Board (optional)
              <input
                value={boardId}
                onChange={event => setBoardId(event.target.value)}
                placeholder="campus-quad"
                className="w-full rounded-xl border border-border/60 bg-surface px-3 py-2 text-sm text-text-primary placeholder:text-text-tertiary focus:border-primary focus:outline-none"
              />
            </label>

            <label className="flex flex-col gap-2 text-xs uppercase tracking-[2px] text-text-tertiary">
              Time window
              <select
                value={windowMs}
                onChange={event => setWindowMs(Number(event.target.value))}
                className="w-full rounded-xl border border-border/60 bg-surface px-3 py-2 text-sm text-text-primary focus:border-primary focus:outline-none"
              >
                {WINDOW_OPTIONS.map(option => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
            </label>

            <button
              type="submit"
              className="inline-flex items-center justify-center gap-2 rounded-full bg-primary px-4 py-2 text-xs font-semibold uppercase tracking-[2px] text-white transition hover:bg-primary-light disabled:cursor-not-allowed disabled:opacity-70"
              disabled={loading}
            >
              {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <SearchIcon className="h-4 w-4" />}
              Search
            </button>
          </form>

          {topics.length > 0 && (
            <div className="mt-6">
              <p className="text-xs uppercase tracking-[2px] text-text-tertiary">Trending topics</p>
              <div className="mt-3 flex flex-wrap gap-2">
                {topics.map(topic => (
                  <button
                    key={topic}
                    type="button"
                    onClick={() => handleTopicSelect(topic)}
                    className={`rounded-full border px-3 py-1 text-xs font-medium transition ${
                      query.trim().toLowerCase() === topic.toLowerCase()
                        ? 'border-primary bg-primary/10 text-primary'
                        : 'border-border/60 text-text-secondary hover:border-primary/40 hover:text-text-primary'
                    }`}
                  >
                    {topic}
                  </button>
                ))}
              </div>
            </div>
          )}
        </section>

        {error && (
          <div className="rounded-2xl border border-amber-500/40 bg-amber-500/10 p-4 text-sm text-amber-200">
            {error}
          </div>
        )}

        <section className="space-y-6">
          {results.map(post => (
            <PostCard
              key={post.id}
              post={post}
              boardName={formatBoardName(post.boardId, post.boardName)}
              disabled
              disabledReason="Open the board to react, reply, or share."
              onOpen={() => router.push(`/boards/${post.boardId}`)}
            />
          ))}

          {loading && results.length === 0 && (
            <div className="space-y-3">
              {[0, 1, 2].map(index => (
                <div key={index} className="h-32 rounded-2xl border border-border/60 bg-surface animate-pulse" />
              ))}
            </div>
          )}

          {initialized && !loading && results.length === 0 && !error && (
            <div className="rounded-2xl border border-border/70 bg-surface-raised/70 p-8 text-center text-sm text-text-secondary">
              <p className="text-2xl">🔍</p>
              <p className="mt-3 font-medium text-text-primary">No results yet</p>
              <p className="mt-1">Try adjusting your query, changing boards, or widening the time window.</p>
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
      </div>
    </PageShell>
  );
}
