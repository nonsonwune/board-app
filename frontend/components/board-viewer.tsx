'use client';

import Link from 'next/link';
import { FormEvent, useCallback, useEffect, useMemo, useState } from 'react';
import type {
  BoardAlias,
  BoardEventPayload,
  BoardFeedResponse,
  BoardPost,
  BoardSummary,
  GetAliasResponse,
  RegisterIdentityResponse,
  UpsertAliasResponse,
  UpdateReactionResponse
} from '@board-app/shared';
import { useBoardEvents } from '../hooks/use-board-events';
import { useToast } from './toast-provider';
import { useIdentityContext } from '../context/identity-context';
type HttpError = Error & { status?: number; payload?: any };

interface BoardViewerProps {
  boardId: string;
}

export default function BoardViewer({ boardId }: BoardViewerProps) {
  const [workerBaseUrl] = useState(() => process.env.NEXT_PUBLIC_WORKER_BASE_URL ?? 'http://localhost:8788');
  const {
    identity: sharedIdentity,
    aliasMap,
    setIdentity: setSharedIdentity,
    setAlias: setSharedAlias,
    getAlias,
    session,
    setSession,
    refreshSession,
    hydrated: identityHydrated
  } = useIdentityContext();
  const { events, status, error } = useBoardEvents(boardId, { workerBaseUrl });
  const [boardMeta, setBoardMeta] = useState<BoardSummary | null>(null);
  const [posts, setPosts] = useState<BoardPost[]>([]);
  const [feedError, setFeedError] = useState<string | null>(null);
  const [feedLoading, setFeedLoading] = useState<boolean>(true);
  const [identity, setIdentity] = useState<RegisterIdentityResponse['user'] | null>(sharedIdentity ?? null);
  const [identityError, setIdentityError] = useState<string | null>(null);
  const [identityLoading, setIdentityLoading] = useState<boolean>(false);
  const [reactionUserId, setReactionUserId] = useState('');
  const [reactionPostId, setReactionPostId] = useState('');
  const [reactionStatus, setReactionStatus] = useState<string | null>(null);
  const [reactionLoading, setReactionLoading] = useState<boolean>(false);
  const sharedAlias = getAlias(boardId);
  const [alias, setAlias] = useState<BoardAlias | null>(sharedAlias);
  const [aliasStatus, setAliasStatus] = useState<string | null>(null);
  const [aliasError, setAliasError] = useState<string | null>(null);
  const [aliasLoading, setAliasLoading] = useState<boolean>(false);
  const [aliasInput, setAliasInput] = useState(sharedAlias?.alias ?? '');
  const quietPrompts = useMemo(
    () => [
      {
        title: 'It’s quiet right now…',
        body: 'Be the first to share a campus update or plan a meetup.'
      },
        {
        title: 'Start the conversation',
        body: 'Share a study tip, a lunch meetup, or a quick shout-out to your floor.'
      },
      {
        title: 'Need inspiration?',
        body: 'Try posting about today’s events, a lost item, or a quick poll for your dorm.'
      }
    ],
    []
  );
  const quietModePrompt = useMemo(() => quietPrompts[Math.floor(Math.random() * quietPrompts.length)], [quietPrompts]);
  const { addToast } = useToast();

  useEffect(() => {
    setAliasStatus(null);
    setAliasError(null);
  }, [identity?.id, boardId]);

  useEffect(() => {
    if (!identityHydrated) return;
    if (sharedIdentity && sharedIdentity.id !== identity?.id) {
      setIdentity(sharedIdentity);
      setReactionUserId(sharedIdentity.id);
      return;
    }
    if (!sharedIdentity && identity) {
      setIdentity(null);
      setReactionUserId('');
    }
  }, [sharedIdentity, identity, identityHydrated]);

  useEffect(() => {
    if (!identityHydrated) return;
    if (identity?.id !== sharedIdentity?.id) {
      setSharedIdentity(identity);
    }
  }, [identity, sharedIdentity, setSharedIdentity, identityHydrated]);

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

  const effectiveIdentity = identityHydrated ? identity : null;
  const sessionToken = session?.token ?? null;
  const buildHeaders = useCallback(
    (base: HeadersInit = {}) => {
      const headers = new Headers(base);
      if (sessionToken) {
        headers.set('Authorization', `Bearer ${sessionToken}`);
      }
      return headers;
    },
    [sessionToken]
  );
  const registerLabel = effectiveIdentity ? 'Re-register' : 'Register';

  const raiseForStatus = useCallback((res: Response, payload: any, fallback: string) => {
    if (!res.ok) {
      const error = new Error(payload?.error ?? fallback) as HttpError;
      error.status = res.status;
      error.payload = payload;
      throw error;
    }
  }, []);

  const handleSessionError = useCallback(
    async (error: unknown, workerBaseUrl: string, setMessage?: (msg: string) => void) => {
      const httpError = error as HttpError;
      if (httpError?.status === 401) {
        const refreshed = await refreshSession(workerBaseUrl);
        if (refreshed) {
          return 'refreshed';
        }
        setSession(null);
        const message = httpError.payload?.error || 'Session expired. Re-register identity.';
        if (setMessage) {
          setMessage(message);
        } else {
          setIdentityError(message);
        }
        return 'expired';
      }
      return 'noop';
    },
    [refreshSession, setSession, setIdentityError]
  );

  const boardAliasLookup = useMemo(() => {
    const map = new Map<string, string>();
    posts.forEach(post => {
      if (post.userId && (post.alias || post.pseudonym)) {
        map.set(post.userId, post.alias ?? post.pseudonym ?? '');
      }
    });
    return map;
  }, [posts]);

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
    if (identity) {
      setReactionUserId(identity.id);
    }
  }, [identity]);

  useEffect(() => {
    if (!identity || !sessionToken) {
      setAlias(null);
      setAliasInput('');
      return;
    }

    if (sharedAlias && sharedAlias.userId === identity.id) {
      setAlias(sharedAlias);
      setAliasInput(sharedAlias.alias);
      return;
    }

    let cancelled = false;
    async function fetchAlias() {
      try {
        const res = await fetch(
          `${workerBaseUrl}/boards/${encodeURIComponent(boardId)}/aliases?userId=${encodeURIComponent(identity.id)}`,
          {
            headers: buildHeaders()
          }
        );
        const body: GetAliasResponse = await res.json();
        raiseForStatus(res, body, `Failed to load alias (${res.status})`);
        if (!cancelled) {
          const nextAlias = body.alias ?? null;
          setAlias(nextAlias);
          if (!nextAlias) {
            setAliasInput('');
          }
        }
      } catch (error) {
        if (cancelled) return;
        const outcome = await handleSessionError(error, workerBaseUrl, msg => {
          setAliasError(msg);
          setAlias(null);
          setAliasInput('');
        });
        if (outcome === 'refreshed') {
          await fetchAlias();
          return;
        }
        if (outcome !== 'expired') {
          console.warn('[ui] failed to fetch alias', error);
          setAlias(null);
        }
      }
    }

    fetchAlias();

    return () => {
      cancelled = true;
    };
  }, [identity, boardId, workerBaseUrl, sharedAlias, sessionToken]);

  useEffect(() => {
    if (!identityHydrated) return;
    if (!identity) {
      if (sharedAlias) {
        setSharedAlias(boardId, null);
      }
      return;
    }

    if (!alias && sharedAlias) {
      setSharedAlias(boardId, null);
      return;
    }

    if (alias && (!sharedAlias || sharedAlias.id !== alias.id || sharedAlias.alias !== alias.alias)) {
      setSharedAlias(boardId, alias);
    }
  }, [alias, sharedAlias, boardId, identity?.id, setSharedAlias, identityHydrated]);

  useEffect(() => {
    if (alias?.alias) {
      setAliasInput(alias.alias);
    }
  }, [alias]);

  useEffect(() => {
    if (posts.length === 0) {
      setReactionPostId('');
      return;
    }

    if (!reactionPostId || !posts.some(post => post.id === reactionPostId)) {
      setReactionPostId(posts[0].id);
    }
  }, [posts, reactionPostId]);

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
      return;
    }
    if (latest.event === 'post.reacted' && latest.data) {
      const payload = latest.data as {
        postId?: string;
        reactions?: { total: number; likeCount: number; dislikeCount: number };
      };
      if (!payload?.postId || !payload?.reactions) return;
      setPosts(prev =>
        prev.map(post => {
          if (post.id !== payload.postId) return post;
          return {
            ...post,
            reactionCount: payload.reactions.total,
            likeCount: payload.reactions.likeCount,
            dislikeCount: payload.reactions.dislikeCount
          };
        })
      );
      setReactionStatus(
        `Realtime update • Post ${payload.postId}: 👍 ${payload.reactions.likeCount} / 👎 ${payload.reactions.dislikeCount}`
      );
    }
  }, [events]);

  async function handleRegisterIdentity(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const formData = new FormData(form);
    const pseudonym = (formData.get('pseudonym') as string)?.trim();

    if (!pseudonym) {
      setIdentityError('Pseudonym is required.');
      return;
    }

    setIdentityLoading(true);
    setIdentityError(null);

    try {
      const res = await fetch(`${workerBaseUrl}/identity/register`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ pseudonym })
      });

      const payload = await res.json().catch(() => ({}));

      if (!res.ok) {
        throw new Error(payload?.error ?? `Failed to register identity (${res.status})`);
      }

      const body = payload as RegisterIdentityResponse;
      setIdentity(body.user);
      setSession(body.session);
      form.reset();
      addToast({ title: 'Identity registered', description: 'You can now post and react.' });
    } catch (error) {
      setIdentityError((error as Error).message ?? 'Failed to register identity');
    } finally {
      setIdentityLoading(false);
    }
  }

  async function handleSendReaction(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const formData = new FormData(form);
    const action = (formData.get('reactionAction') as string)?.trim();
    const explicitUserId = (formData.get('reactionUserId') as string)?.trim();
    const userId = explicitUserId || identity?.id || reactionUserId;

    if (!reactionPostId) {
      setReactionStatus('Select a post to react to.');
      return;
    }

    if (!userId) {
      setReactionStatus('Provide a user ID or register an identity first.');
      return;
    }

    if (!sessionToken) {
      setReactionStatus('Session expired. Re-register identity.');
      return;
    }

    if (!action) {
      setReactionStatus('Choose a reaction action.');
      return;
    }

    setReactionLoading(true);
    setReactionStatus(null);

    const attempt = async () => {
      const res = await fetch(
        `${workerBaseUrl}/boards/${encodeURIComponent(boardId)}/posts/${encodeURIComponent(reactionPostId)}/reactions`,
        {
          method: 'POST',
          headers: buildHeaders({ 'content-type': 'application/json' }),
          body: JSON.stringify({ userId, action })
        }
      );

      const payload = await res.json().catch(() => ({}));
      raiseForStatus(res, payload, `Failed to update reaction (${res.status})`);

      const body = payload as UpdateReactionResponse;
      setReactionStatus(
        `Acknowledged • Post ${body.postId}: 👍 ${body.reactions.likeCount} / 👎 ${body.reactions.dislikeCount}`
      );
    };

    try {
      await attempt();
    } catch (error) {
      const outcome = await handleSessionError(error, workerBaseUrl, msg => setReactionStatus(msg));
      if (outcome === 'refreshed') {
        try {
          await attempt();
          return;
        } catch (retryError) {
          setReactionStatus((retryError as Error).message ?? 'Failed to send reaction');
        }
      }
      if (outcome !== 'expired') {
        setReactionStatus((error as Error).message ?? 'Failed to send reaction');
      }
    } finally {
      setReactionLoading(false);
    }
  }

  async function handleUpsertAlias(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const formData = new FormData(form);
    const aliasValue = (formData.get('boardAlias') as string)?.trim();

    if (!identity) {
      setAliasError('Register an identity first.');
      return;
    }

    if (!sessionToken) {
      setAliasError('Session expired. Re-register identity.');
      return;
    }

    if (!aliasValue) {
      setAliasError('Alias cannot be empty.');
      return;
    }

    setAliasLoading(true);
    setAliasError(null);
    setAliasStatus(null);

    const attempt = async () => {
      const res = await fetch(`${workerBaseUrl}/boards/${encodeURIComponent(boardId)}/aliases`, {
        method: alias ? 'PUT' : 'POST',
        headers: buildHeaders({ 'content-type': 'application/json' }),
        body: JSON.stringify({ userId: identity.id, alias: aliasValue })
      });

      const payload = await res.json().catch(() => ({}));
      raiseForStatus(res, payload, `Failed to update alias (${res.status})`);

      const body = payload as UpsertAliasResponse;
      setAlias(body.alias);
      setAliasInput(body.alias.alias);
      setAliasStatus(`Alias set to “${body.alias.alias}”.`);
      addToast({ title: 'Alias saved', description: `Showing as ${body.alias.alias} on this board.` });
    };

    try {
      await attempt();
    } catch (error) {
      const outcome = await handleSessionError(error, workerBaseUrl, msg => setAliasError(msg));
      if (outcome === 'refreshed') {
        try {
          await attempt();
          return;
        } catch (retryError) {
          setAliasError((retryError as Error).message ?? 'Failed to update alias');
        }
      }
      if (outcome !== 'expired') {
        setAliasError((error as Error).message ?? 'Failed to update alias');
      }
    } finally {
      setAliasLoading(false);
    }
  }

  async function handleInject(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const formData = new FormData(form);
    const type = (formData.get('eventType') as string)?.trim() || 'note';
    const message = (formData.get('payload') as string)?.trim();

    const payload = message ? { body: message } : {};

    const attempt = async () => {
      const res = await fetch(`${workerBaseUrl}/boards/${encodeURIComponent(boardId)}/events`, {
        method: 'POST',
        headers: buildHeaders({ 'content-type': 'application/json' }),
        body: JSON.stringify({ event: type, data: payload })
      });
      const responsePayload = await res.json().catch(() => ({}));
      raiseForStatus(res, responsePayload, `Failed to send event (${res.status})`);
      form.reset();
      addToast({ title: 'Event dispatched', description: `Sent ${type} event to listeners.` });
    };

    try {
      await attempt();
    } catch (error) {
      const outcome = await handleSessionError(error, workerBaseUrl, msg => setIdentityError(msg));
      if (outcome === 'refreshed') {
        try {
          await attempt();
          return;
        } catch (retryError) {
          console.error('[ui] failed to inject event', retryError);
        }
      }
      if (outcome === 'expired') {
        alert('Session expired. Re-register identity.');
        return;
      }
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
      addToast({ title: 'Message required', description: 'Enter a post before submitting.' });
      return;
    }

    if (!identity || !sessionToken) {
      addToast({ title: 'Session needed', description: 'Register or refresh your identity first.' });
      return;
    }

    const attempt = async () => {
      const resolvedAuthor = author || alias?.alias || identity?.pseudonym || undefined;
      const res = await fetch(`${workerBaseUrl}/boards/${encodeURIComponent(boardId)}/posts`, {
        method: 'POST',
        headers: buildHeaders({ 'content-type': 'application/json' }),
        body: JSON.stringify({ body, author: resolvedAuthor, userId: identity?.id || undefined })
      });
      const payload = await res.json().catch(() => ({}));
      raiseForStatus(res, payload, `Failed to create post (${res.status})`);
      form.reset();
      await fetchFeed();
      addToast({ title: 'Post published', description: 'Shared with everyone on this board.' });
    };

    try {
      await attempt();
    } catch (err) {
      const outcome = await handleSessionError(err, workerBaseUrl, msg => setIdentityError(msg));
      if (outcome === 'refreshed') {
        try {
          await attempt();
          return;
        } catch (retryError) {
          console.error('[ui] failed to create post', retryError);
          addToast({ title: 'Post failed', description: 'See console for details.' });
        }
      }
      if (outcome === 'expired') {
        addToast({ title: 'Session expired', description: 'Re-register identity to keep posting.' });
        return;
      }
      console.error('[ui] failed to create post', err);
      addToast({ title: 'Post failed', description: 'See console for details.' });
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
            Connected to <code className="rounded bg-slate-900 px-1">{workerBaseUrl}</code>{' '}
            · showing posts within {sharedAlias ? 'your saved radius' : 'an adaptive radius'}
          </p>
          {boardMeta?.description ? (
            <p className="text-sm text-slate-500">{boardMeta.description}</p>
          ) : (
            <p className="text-sm text-slate-500">
              Stay updated on events and drop-ins happening around this part of campus.
            </p>
          )}
          <div className="mt-2 flex flex-wrap items-center gap-3 text-xs text-slate-400">
            {effectiveIdentity ? (
              <span className="flex items-center gap-1 rounded-md border border-slate-800 bg-slate-900/60 px-2 py-1 font-medium text-slate-200">
                {effectiveIdentity.pseudonym}
                <span className="text-[10px] text-slate-500">#{effectiveIdentity.id.slice(0, 6)}</span>
              </span>
            ) : (
              <span>Register an identity to post as yourself.</span>
            )}
            {effectiveIdentity && (
              <span className="flex items-center gap-1 rounded-md border border-slate-800 bg-slate-900/60 px-2 py-1 text-slate-300">
                Alias: <strong className="text-slate-100">{alias?.alias ?? boardAliasLookup.get(effectiveIdentity.id) ?? '—'}</strong>
              </span>
            )}
            <Link
              href="/profile"
              className="rounded-md border border-slate-700 px-2 py-1 text-[11px] uppercase tracking-[2px] text-slate-300 transition hover:border-sky-500 hover:text-sky-300"
            >
              Manage Identity →
            </Link>
          </div>
        </header>

        {error && (
          <div className="mt-6 rounded-lg border border-rose-500/40 bg-rose-500/10 p-4 text-sm text-rose-200">
            {error}
          </div>
        )}

        <section className="mt-10">
          <form onSubmit={handleRegisterIdentity} className="mb-8 rounded-xl border border-slate-800 bg-slate-900/40 p-4 shadow-sm shadow-slate-950/30">
            <h2 className="text-sm font-semibold uppercase tracking-[3px] text-slate-400">Register Identity</h2>
            <p className="mt-2 text-xs text-slate-500">
              Identities map to pseudonyms used across boards. Reactions require a user ID.
            </p>
            <div className="mt-4 flex flex-wrap items-end gap-4">
              <label className="flex flex-1 min-w-[220px] flex-col gap-2 text-xs uppercase tracking-[2px] text-slate-500">
                Pseudonym
                <input
                  name="pseudonym"
                  placeholder="e.g. CampusScout"
                  className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-sky-500 focus:outline-none"
                  required
                />
              </label>
              <button
                type="submit"
                disabled={identityLoading}
                className="rounded-md bg-sky-500 px-4 py-2 text-sm font-semibold text-slate-950 transition hover:bg-sky-400 disabled:cursor-not-allowed disabled:bg-slate-700 disabled:text-slate-400"
              >
                {identityLoading ? 'Registering…' : registerLabel}
              </button>
            </div>
            {effectiveIdentity && (
              <div className="mt-3 rounded-md border border-slate-800 bg-slate-900/60 p-3 text-xs text-slate-400">
                <p>
                  Active identity:{' '}
                  <span className="font-semibold text-slate-200">{effectiveIdentity.pseudonym}</span>{' '}
                  <code className="ml-1 rounded bg-slate-950 px-2 py-1 text-[11px] text-slate-300">{effectiveIdentity.id}</code>
                </p>
                {alias && (
                  <p className="mt-2 text-[11px] text-slate-500">
                    Board alias: <span className="font-semibold text-slate-200">{alias.alias}</span>
                  </p>
                )}
                <Link
                  href="/profile"
                  className="mt-2 inline-flex items-center gap-1 text-[11px] uppercase tracking-[2px] text-sky-300 transition hover:text-sky-100"
                >
                  Manage identity & sessions →
                </Link>
              </div>
            )}
            {effectiveIdentity && !sessionToken && (
              <div className="mt-3 rounded-md border border-amber-500/30 bg-amber-500/10 p-3 text-xs text-amber-200">
                <p>Your session expired. Re-link your Access identity to continue posting.</p>
                <Link
                  href="/profile"
                  className="mt-2 inline-flex items-center gap-1 text-[11px] uppercase tracking-[2px] text-amber-200 underline-offset-4 hover:text-amber-100 hover:underline"
                >
                  Re-link session →
                </Link>
              </div>
            )}
            {identityError && (
              <p className="mt-3 rounded-md border border-rose-500/40 bg-rose-500/10 p-3 text-xs text-rose-200">{identityError}</p>
            )}
          </form>

          <form
            onSubmit={handleUpsertAlias}
            className="mb-8 rounded-xl border border-slate-800 bg-slate-900/40 p-4 shadow-sm shadow-slate-950/30"
          >
            <h2 className="text-sm font-semibold uppercase tracking-[3px] text-slate-400">Set Board Alias</h2>
            <p className="mt-2 text-xs text-slate-500">
              Aliases display only within this board. They override your global pseudonym.
            </p>
            <div className="mt-4 flex flex-wrap items-end gap-4">
              <label className="flex flex-1 min-w-[220px] flex-col gap-2 text-xs uppercase tracking-[2px] text-slate-500">
                Alias
                <input
                  name="boardAlias"
                  value={aliasInput}
                  onChange={event => {
                    setAliasInput(event.target.value);
                    setAliasStatus(null);
                    setAliasError(null);
                  }}
                  placeholder="e.g. LibraryLookout"
                  className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-sky-500 focus:outline-none"
                  disabled={!identity}
                />
              </label>
              <button
                type="submit"
                disabled={!identity || aliasLoading}
                className="rounded-md bg-emerald-500 px-4 py-2 text-sm font-semibold text-slate-950 transition hover:bg-emerald-400 disabled:cursor-not-allowed disabled:bg-slate-700 disabled:text-slate-400"
              >
                {!identity ? 'Register identity first' : aliasLoading ? 'Saving…' : alias ? 'Update Alias' : 'Save Alias'}
              </button>
            </div>
            {alias && (
              <p className="mt-3 rounded-md border border-slate-800 bg-slate-900/60 p-3 text-xs text-slate-400">
                Current alias: <span className="font-semibold text-slate-200">{alias.alias}</span>
                {alias.aliasNormalized && (
                  <code className="ml-2 rounded bg-slate-950 px-2 py-1 text-[11px] text-slate-300">{alias.aliasNormalized}</code>
                )}
              </p>
            )}
            {aliasStatus && (
              <p className="mt-3 rounded-md border border-slate-800 bg-slate-900/60 p-3 text-xs text-emerald-300/80">{aliasStatus}</p>
            )}
            {aliasError && (
              <p className="mt-3 rounded-md border border-rose-500/40 bg-rose-500/10 p-3 text-xs text-rose-200">{aliasError}</p>
            )}
          </form>

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
              {sessionToken ? (
                <>
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
                </>
              ) : (
                <div className="flex flex-1 items-center justify-between rounded-md border border-dashed border-slate-800 bg-slate-900/40 px-4 py-3 text-xs text-slate-400">
                  <span>Session expired. Re-register identity to post.</span>
                  <Link
                    href="/profile"
                    className="rounded-md border border-slate-700 px-2 py-1 text-[11px] uppercase tracking-[2px] text-slate-300 transition hover:border-sky-500 hover:text-sky-300"
                  >
                    Manage Session
                  </Link>
                </div>
              )}
            </div>
          </form>

          <h2 className="text-lg font-semibold text-slate-200">Recent Posts</h2>
        {feedError && (
          <p className="mt-3 rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-sm text-amber-200">{feedError}</p>
        )}
        {feedLoading && !feedError && (
          <p className="mt-4 text-sm text-slate-500">Loading posts…</p>
        )}
        {!feedLoading && effectiveIdentity && !sessionToken && (
          <div className="mt-4 rounded-md border border-amber-500/30 bg-amber-500/10 p-3 text-xs text-amber-200">
            <p>Your session expired. Re-link your Access identity to continue participating.</p>
            <Link
              href="/profile"
              className="mt-2 inline-flex items-center gap-1 text-[11px] uppercase tracking-[2px] text-amber-200 underline-offset-4 hover:text-amber-100 hover:underline"
            >
              Re-link session →
            </Link>
          </div>
        )}
        {!feedLoading && !feedError && posts.length > 0 && posts.length < 3 && quietModePrompt && (
          <div className="mt-4 rounded-xl border border-dashed border-slate-800 bg-slate-900/40 p-6 text-sm text-slate-300">
            <h3 className="text-base font-semibold text-slate-200">{quietModePrompt.title}</h3>
            <p className="mt-2 text-sm text-slate-400">{quietModePrompt.body}</p>
            <button
              type="button"
              onClick={() => {
                addToast({ title: 'Ready to post?', description: 'Share something with your board.' });
                window.scrollTo({ top: 0, behavior: 'smooth' });
              }}
              className="mt-3 inline-flex items-center gap-1 rounded-md border border-sky-500/40 px-3 py-1 text-xs uppercase tracking-[2px] text-sky-300 transition hover:border-sky-400 hover:text-sky-100"
            >
              Create a post →
            </button>
          </div>
        )}
        {!feedLoading && posts.length === 0 && !feedError && (
          <div className="mt-4 rounded-xl border border-dashed border-slate-800 bg-slate-900/30 p-8 text-center text-sm text-slate-500">
            No posts yet. Use the form above to create one.
          </div>
        )}
          <div className="mt-4 space-y-4">
            {posts.map(post => {
              const isMine = effectiveIdentity?.id && post.userId === effectiveIdentity.id;
              const aliasLabel = post.alias || post.author || post.pseudonym || 'Anon';
              const aliasClasses = post.alias
                ? 'rounded border border-sky-500/40 bg-sky-500/10 px-1.5 py-0.5 text-sky-200'
                : 'rounded border border-slate-800 bg-slate-950/70 px-1.5 py-0.5 text-slate-200';
              return (
                <article
                  key={post.id}
                  className={`rounded-xl border bg-slate-900/40 p-4 shadow-sm transition ${
                    isMine
                      ? 'border-emerald-500/60 shadow-emerald-500/20'
                      : 'border-slate-800 shadow-slate-950/20'
                  }`}
                >
                  <header className="flex flex-wrap items-center justify-between gap-3 text-xs text-slate-500">
                    <div className="flex flex-col">
                      <span className="font-semibold text-slate-200">{post.author || 'Anon'}</span>
                      <div className="flex flex-wrap items-center gap-2 text-[11px] text-slate-500">
                        {post.userId && (
                          <span className="font-mono text-slate-600">#{post.userId.slice(0, 8)}</span>
                        )}
                        <span className="flex items-center gap-1 text-slate-400">
                          <span className="text-[10px] uppercase tracking-[2px] text-slate-500">Alias</span>
                          <span className={aliasClasses}>{aliasLabel}</span>
                        </span>
                        {isMine && (
                          <span className="rounded bg-emerald-500/20 px-1.5 py-0.5 font-medium text-emerald-300">
                            You
                          </span>
                        )}
                      </div>
                    </div>
                    <time className="font-medium text-slate-300">
                      {new Date(post.createdAt).toLocaleString()}
                    </time>
                  </header>
                  <p className="mt-3 text-sm text-slate-100">{post.body}</p>
                  <footer className="mt-3 flex flex-wrap items-center gap-4 text-xs text-slate-500">
                    <span>👍 {post.likeCount}</span>
                    <span>👎 {post.dislikeCount}</span>
                    <span>Total {post.reactionCount}</span>
                  </footer>
                </article>
              );
            })}
          </div>

          <form onSubmit={handleSendReaction} className="mt-8 mb-8 rounded-xl border border-slate-800 bg-slate-900/40 p-4 shadow-sm shadow-slate-950/30">
            <h2 className="text-sm font-semibold uppercase tracking-[3px] text-slate-400">Send Test Reaction</h2>
            <div className="mt-4 grid gap-4 sm:grid-cols-3">
              <label className="flex flex-col gap-2 text-xs uppercase tracking-[2px] text-slate-500">
                Post
                <select
                  name="reactionPostId"
                  value={reactionPostId}
                  onChange={event => setReactionPostId(event.target.value)}
                  className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-sky-500 focus:outline-none"
                  disabled={posts.length === 0}
                >
                  {posts.map(post => (
                    <option key={post.id} value={post.id}>
                      {post.body.slice(0, 40)}
                      {post.body.length > 40 ? '…' : ''}
                    </option>
                  ))}
                  {posts.length === 0 && <option value="">No posts</option>}
                </select>
              </label>
              <label className="flex flex-col gap-2 text-xs uppercase tracking-[2px] text-slate-500">
                User ID
                <input
                  name="reactionUserId"
                  value={reactionUserId}
                  onChange={event => setReactionUserId(event.target.value)}
                  placeholder="Copy from identity"
                  className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-sky-500 focus:outline-none"
                  required
                />
              </label>
              <label className="flex flex-col gap-2 text-xs uppercase tracking-[2px] text-slate-500">
                Action
                <select
                  name="reactionAction"
                  className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-sky-500 focus:outline-none"
                  defaultValue="like"
                >
                  <option value="like">Like</option>
                  <option value="dislike">Dislike</option>
                  <option value="remove">Remove</option>
                </select>
              </label>
            </div>
            <div className="mt-4 flex flex-wrap items-center justify-between gap-3">
              <button
                type="submit"
                disabled={reactionLoading || !reactionPostId}
                className="rounded-md bg-emerald-500 px-4 py-2 text-sm font-semibold text-slate-950 transition hover:bg-emerald-400 disabled:cursor-not-allowed disabled:bg-slate-700 disabled:text-slate-400"
              >
                {reactionLoading ? 'Sending…' : 'Send Reaction'}
              </button>
              {reactionStatus && (
                <p className="text-xs text-slate-400">{reactionStatus}</p>
              )}
            </div>
          </form>

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
