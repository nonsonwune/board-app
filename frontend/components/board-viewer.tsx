'use client';

import { FormEvent, useCallback, useEffect, useMemo, useState } from 'react';
import { useBoardEvents } from '../hooks/use-board-events';
import type { BoardEventPayload, BoardFeedResponse, BoardPost, BoardSummary } from '@board-app/shared';

interface BoardViewerProps {
  boardId: string;
}

export default function BoardViewer({ boardId }: BoardViewerProps) {
  const [workerBaseUrl] = useState(() => process.env.NEXT_PUBLIC_WORKER_BASE_URL ?? 'http://localhost:8788');
  const { events, status, error } = useBoardEvents(boardId, { workerBaseUrl });
  const [boardMeta, setBoardMeta] = useState<BoardSummary | null>(null);
  const [posts, setPosts] = useState<BoardPost[]>([]);
  const [feedError, setFeedError] = useState<string | null>(null);
  const [feedLoading, setFeedLoading] = useState<boolean>(true);

  const statusLabel = useMemo(() => {
    if (status === 'connected') return 'Live';
    if (status === 'connecting') return 'Connecting…';
    if (status === 'error') return 'Retrying…';
    return 'Offline';
  }, [status]);

  const badgeTone = useMemo(() => {
    switch (status) {
      case 'connected':
        return 'bg-emerald-500/20 text-emerald-300';
      case 'connecting':
        return 'bg-sky-500/20 text-sky-200';
      case 'error':
        return 'bg-amber-500/20 text-amber-200';
      default:
        return 'bg-slate-700/40 text-slate-300';
    }
  }, [status]);

  const sortedEvents = useMemo(() => events.slice().sort((a, b) => a.timestamp - b.timestamp), [events]);

  const fetchFeed = useCallback(
    async (signal?: AbortSignal) => {
      setFeedLoading(true);
      try {
        const res = await fetch(`${workerBaseUrl}/boards/${encodeURIComponent(boardId)}/feed?limit=20`, {
          signal
        });
        if (!res.ok) {
          throw new Error(`Failed to load feed (${res.status})`);
        }
        const body: BoardFeedResponse = await res.json();
        if (signal?.aborted) return;
        setBoardMeta(body.board ?? null);
        setPosts(body.posts ?? []);
        setFeedError(null);
      } catch (err) {
        if (signal?.aborted) return;
        if (err instanceof DOMException && err.name === 'AbortError') {
          return;
        }
        setFeedError((err as Error).message ?? 'Failed to load feed');
      } finally {
        if (signal?.aborted) return;
        setFeedLoading(false);
      }
    },
    [boardId, workerBaseUrl]
  );

  useEffect(() => {
    const controller = new AbortController();
    fetchFeed(controller.signal);
    return () => controller.abort();
  }, [fetchFeed]);

  useEffect(() => {
    const latest = events.at(-1);
    if (!latest) return;
    if (latest.event === 'post.created' && latest.data) {
      const payload = latest.data as BoardPost;
      setPosts(prev => {
        const exists = prev.some(post => post.id === payload.id);
        if (exists) return prev;
        return [payload, ...prev].slice(0, 20);
      });
    }
  }, [events]);

  async function handleInject(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const formData = new FormData(form);
    const type = (formData.get('eventType') as string)?.trim() || 'note';
    const message = (formData.get('payload') as string)?.trim();

    const payload = message ? { body: message } : {};

    try {
      const res = await fetch(`${workerBaseUrl}/boards/${encodeURIComponent(boardId)}/events`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ event: type, data: payload })
      });
      if (!res.ok) {
        throw new Error(`Failed to send event (${res.status})`);
      }
      form.reset();
    } catch (error) {
      console.error('[ui] failed to inject event', error);
      alert('Failed to send event. See console for details.');
    }
  }

  async function handleCreatePost(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const formData = new FormData(form);
    const body = (formData.get('postBody') as string)?.trim();
    const author = (formData.get('postAuthor') as string)?.trim();

    if (!body) {
      alert('Post message cannot be empty.');
      return;
    }

    try {
      const res = await fetch(`${workerBaseUrl}/boards/${encodeURIComponent(boardId)}/posts`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ body, author: author || undefined })
      });
      if (!res.ok) {
        throw new Error(`Failed to create post (${res.status})`);
      }
      form.reset();
      await fetchFeed();
    } catch (err) {
      console.error('[ui] failed to create post', err);
      alert('Failed to create post. See console for details.');
    }
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 py-12">
      <div className="mx-auto max-w-4xl px-6">
        <header className="flex flex-col gap-3 border-b border-slate-800 pb-6">
          <div className="flex items-center gap-3 text-sm text-slate-400">
            <span className={`rounded-full px-2.5 py-1 text-xs font-semibold uppercase tracking-wide ${badgeTone}`}>
              {statusLabel}
            </span>
            <span className="text-xs uppercase tracking-[2px] text-slate-500">Board</span>
          </div>
          <h1 className="text-4xl font-semibold text-white">{boardMeta?.displayName ?? boardId}</h1>
          <p className="text-sm text-slate-400">
            Connected to <code className="rounded bg-slate-900 px-1">{workerBaseUrl}</code>
          </p>
          {boardMeta?.description && (
            <p className="text-sm text-slate-500">{boardMeta.description}</p>
          )}
        </header>

        {error && (
          <div className="mt-6 rounded-lg border border-rose-500/40 bg-rose-500/10 p-4 text-sm text-rose-200">
            {error}
          </div>
        )}

        <section className="mt-10">
          <form onSubmit={handleCreatePost} className="mb-8 rounded-xl border border-slate-800 bg-slate-900/40 p-4 shadow-sm shadow-slate-950/30">
            <h2 className="text-sm font-semibold uppercase tracking-[3px] text-slate-400">Create Test Post</h2>
            <div className="mt-4 flex flex-wrap gap-4">
              <label className="flex min-w-[140px] flex-col gap-2 text-xs uppercase tracking-[2px] text-slate-500">
                Author (optional)
                <input
                  name="postAuthor"
                  placeholder="Anon"
                  className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-sky-500 focus:outline-none"
                />
              </label>
              <label className="flex flex-1 min-w-[220px] flex-col gap-2 text-xs uppercase tracking-[2px] text-slate-500">
                Message
                <input
                  name="postBody"
                  placeholder="Share an update"
                  className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-sky-500 focus:outline-none"
                  required
                />
              </label>
              <button
                type="submit"
                className="self-end rounded-md bg-emerald-500 px-4 py-2 text-sm font-semibold text-slate-950 transition hover:bg-emerald-400"
              >
                Post
              </button>
            </div>
          </form>

          <h2 className="text-lg font-semibold text-slate-200">Recent Posts</h2>
          {feedError && (
            <p className="mt-3 rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-sm text-amber-200">{feedError}</p>
          )}
          {feedLoading && !feedError && (
            <p className="mt-4 text-sm text-slate-500">Loading posts…</p>
          )}
          {!feedLoading && posts.length === 0 && !feedError && (
            <div className="mt-4 rounded-xl border border-dashed border-slate-800 bg-slate-900/30 p-8 text-center text-sm text-slate-500">
              No posts yet. Use the form above to create one.
            </div>
          )}
          <div className="mt-4 space-y-4">
            {posts.map(post => (
              <article key={post.id} className="rounded-xl border border-slate-800 bg-slate-900/40 p-4 shadow-sm shadow-slate-950/20">
                <header className="flex flex-wrap items-center justify-between gap-3 text-xs text-slate-500">
                  <span className="font-semibold text-slate-200">{post.author || 'Anon'}</span>
                  <time className="font-medium text-slate-300">
                    {new Date(post.createdAt).toLocaleString()}
                  </time>
                </header>
                <p className="mt-3 text-sm text-slate-100">{post.body}</p>
                <footer className="mt-3 text-xs text-slate-500">Reactions: {post.reactionCount}</footer>
              </article>
            ))}
          </div>

          <form onSubmit={handleInject} className="mb-8 rounded-xl border border-slate-800 bg-slate-900/40 p-4 shadow-sm shadow-slate-950/30">
            <h2 className="text-sm font-semibold uppercase tracking-[3px] text-slate-400">Inject Test Event</h2>
            <div className="mt-4 flex flex-wrap gap-4">
              <label className="flex flex-1 min-w-[160px] flex-col gap-2 text-xs uppercase tracking-[2px] text-slate-500">
                Event Type
                <input
                  name="eventType"
                  defaultValue="note"
                  className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-sky-500 focus:outline-none"
                />
              </label>
              <label className="flex flex-[2] min-w-[200px] flex-col gap-2 text-xs uppercase tracking-[2px] text-slate-500">
                Message
                <input
                  name="payload"
                  placeholder="Hello from the UI"
                  className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-sky-500 focus:outline-none"
                />
              </label>
              <button
                type="submit"
                className="self-end rounded-md bg-sky-500 px-4 py-2 text-sm font-semibold text-slate-950 transition hover:bg-sky-400"
              >
                Broadcast
              </button>
            </div>
          </form>

          <h2 className="text-lg font-semibold text-slate-200">Event Stream</h2>
          <p className="text-xs text-slate-500">Newest events at the bottom.</p>

          <div className="mt-4 space-y-4">
            {sortedEvents.map(event => (
              <article
                key={event.id}
                className="rounded-xl border border-slate-800 bg-slate-900/40 p-4 shadow-sm shadow-slate-950/20"
              >
                <header className="flex flex-wrap items-center justify-between gap-3 text-xs text-slate-500">
                  <span className="font-mono text-sky-200">{event.traceId}</span>
                  <time className="font-medium text-slate-300">
                    {new Date(event.timestamp).toLocaleTimeString()}
                  </time>
                </header>
                <div className="mt-3">
                  <span className="inline-flex items-center gap-2 rounded-full bg-sky-500/10 px-3 py-1 text-xs font-semibold uppercase tracking-wide text-sky-300">
                    {event.event}
                  </span>
                </div>
                <pre className="mt-3 overflow-x-auto rounded-lg bg-slate-950/70 p-3 text-xs text-slate-200">
                  {JSON.stringify(event.data, null, 2)}
                </pre>
              </article>
            ))}

            {sortedEvents.length === 0 && (
              <div className="rounded-xl border border-dashed border-slate-800 bg-slate-900/30 p-8 text-center text-sm text-slate-500">
                Waiting for events… use the smoke test or POST to <code className="bg-slate-900 px-1">/boards/{boardId}/events</code> to
                simulate activity.
              </div>
            )}
          </div>
        </section>
      </div>
    </div>
  );
}
