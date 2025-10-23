'use client';

import { FormEvent, useEffect, useMemo, useState } from 'react';
import type {
  BoardAlias,
  CreateSessionResponse,
  GetAliasResponse,
  RegisterIdentityResponse,
  SessionTicket,
  UpsertAliasResponse
} from '@board-app/shared';
type HttpError = Error & { status?: number; payload?: any };
import { useToast } from './toast-provider';
import { useIdentityContext } from '../context/identity-context';

interface IdentityPanelProps {
  workerBaseUrl?: string;
}

export default function IdentityPanel({ workerBaseUrl: baseUrl }: IdentityPanelProps) {
  const workerBaseUrl = baseUrl ?? process.env.NEXT_PUBLIC_WORKER_BASE_URL ?? 'http://localhost:8788';
  const {
    identity,
    aliasMap,
    setIdentity,
    setAlias,
    getAlias,
    session,
    setSession,
    refreshSession,
    linkAccessIdentity,
    hydrated
  } = useIdentityContext();
  const [registerError, setRegisterError] = useState<string | null>(null);
  const [registerLoading, setRegisterLoading] = useState(false);
  const [aliasBoardId, setAliasBoardId] = useState('');
  const [aliasValue, setAliasValue] = useState('');
  const [aliasStatus, setAliasStatus] = useState<string | null>(null);
  const [aliasLoading, setAliasLoading] = useState(false);
  const [fetchingAlias, setFetchingAlias] = useState(false);
  const [hydratedAlias, setHydratedAlias] = useState<BoardAlias | null>(null);
  const [refreshingSession, setRefreshingSession] = useState(false);
  const [linkingAccess, setLinkingAccess] = useState(false);
  const [linkStatus, setLinkStatus] = useState<string | null>(null);
  const [sessionStatus, setSessionStatus] = useState<string | null>(null);
  const aliasSuggestions = useMemo(() => {
    const base = aliasBoardId ? aliasBoardId.replace(/[-_]/g, ' ') : 'Campus';
    const prefix = base
      .split(' ')
      .filter(Boolean)
      .map(part => part[0]?.toUpperCase() + part.slice(1))
      .join(' ');
    return Array.from(
      new Set(
        [
          `${prefix} Scout`,
          `${prefix} Insider`,
          `${prefix} Pulse`,
          'Study Buddy',
          'Coffee Whisperer'
        ]
          .map(value => value.trim())
          .filter(Boolean)
      )
    );
  }, [aliasBoardId]);

  const aliasEntries = useMemo(() => Object.entries(aliasMap).filter(([, value]) => value), [aliasMap]);
  const displayIdentity = hydrated ? identity : null;
  const displaySession = hydrated ? session : null;
  const registerLabel = displayIdentity ? 'Re-register' : 'Register';
  const { addToast } = useToast();

  const raiseForStatus = (res: Response, payload: any, fallback: string) => {
    if (!res.ok) {
      const error = new Error(payload?.error ?? fallback) as HttpError;
      error.status = res.status;
      error.payload = payload;
      throw error;
    }
  };

  const handleSessionError = async (
    error: unknown,
    setter: (msg: string) => void
  ): Promise<'refreshed' | 'expired' | 'noop'> => {
    const httpError = error as HttpError;
    if (httpError?.status === 401) {
      const refreshed = await refreshSession(workerBaseUrl);
      if (refreshed) {
        return 'refreshed';
      }
      setter(httpError.payload?.error || 'Session expired. Re-register identity.');
      setSession(null);
      return 'expired';
    }
    return 'noop';
  };

  useEffect(() => {
    if (!identity) {
      setAliasBoardId('');
      setAliasValue('');
    }
  }, [identity?.id]);

  useEffect(() => {
    setSessionStatus(null);
  }, [identity?.id, session?.token]);

  async function handleRegister(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const formData = new FormData(form);
    const pseudonym = (formData.get('pseudonym') as string)?.trim();
    if (!pseudonym) {
      setRegisterError('Pseudonym is required.');
      return;
    }

    setRegisterError(null);
    setRegisterLoading(true);
    const res = await fetch(`${workerBaseUrl}/identity/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ pseudonym })
    }).catch(error => {
      setRegisterError('Network error registering identity');
      throw error;
    });
    if (!res) {
      setRegisterLoading(false);
      return;
    }

    const payload = await res.json().catch(() => ({}));
    if (!res.ok || !payload?.user) {
      setRegisterError(payload?.error ?? `Failed to register identity (${res.status})`);
      setRegisterLoading(false);
      return;
    }

    const body = payload as RegisterIdentityResponse;
    setIdentity(body.user);
    setSession(body.session as SessionTicket);
    setRegisterError(null);
    form.reset();
    addToast({ title: 'Identity registered', description: `Hello, ${body.user.pseudonym}!` });
    setRegisterLoading(false);
  }

  async function handleRefreshSession() {
    if (!identity || !session?.token) {
      setRegisterError('Register identity before refreshing session.');
      return;
    }
    setSessionStatus(null);
    setRefreshingSession(true);
    try {
      const ticket = await refreshSession(workerBaseUrl);
      if (!ticket) {
        setRegisterError('Session expired. Re-register identity.');
        setSessionStatus('Session refresh failed.');
        addToast({ title: 'Session refresh failed', description: 'Please re-register identity.' });
      } else {
        setRegisterError(null);
        setSessionStatus(`Session refreshed • expires ${new Date(ticket.expiresAt).toLocaleString()}`);
        addToast({ title: 'Session refreshed', description: 'Identity session extended.' });
      }
    } finally {
      setRefreshingSession(false);
    }
  }

  async function handleLinkAccess() {
    setLinkStatus(null);
    setLinkingAccess(true);
    try {
      const user = await linkAccessIdentity(workerBaseUrl);
      if (user) {
        setLinkStatus(`Linked Access identity to ${user.pseudonym}.`);
        addToast({ title: 'Access linked', description: `Running as ${user.pseudonym}.` });
      } else {
        setLinkStatus('No Access identity detected or already linked.');
        addToast({ title: 'Access link unavailable', description: 'No active Access token found.' });
      }
    } catch (error) {
      setLinkStatus((error as Error).message ?? 'Failed to link Access identity');
    } finally {
      setLinkingAccess(false);
    }
  }

  async function handleAliasSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!identity) {
      setAliasStatus('Register an identity first.');
      return;
    }
    if (!session?.token) {
      setAliasStatus('Session expired. Re-register identity.');
      return;
    }
    if (!aliasBoardId.trim()) {
      setAliasStatus('Board ID is required.');
      return;
    }
    const alias = aliasValue.trim();
    if (!alias) {
      setAliasStatus('Alias is required.');
      return;
    }

    setAliasLoading(true);
    setAliasStatus(null);

    const attempt = async () => {
      const res = await fetch(`${workerBaseUrl}/boards/${encodeURIComponent(aliasBoardId)}/aliases`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          Authorization: `Bearer ${session.token}`
        },
        body: JSON.stringify({ userId: identity.id, alias })
      });
      const payload = await res.json().catch(() => ({}));
      raiseForStatus(res, payload, `Failed to update alias (${res.status})`);
      const body = payload as UpsertAliasResponse;
      setAlias(aliasBoardId, body.alias);
      setAliasStatus(`Alias for ${aliasBoardId} set to “${body.alias.alias}”.`);
      addToast({ title: 'Alias saved', description: `Board ${aliasBoardId} now knows you as ${body.alias.alias}.` });
    };

    try {
      await attempt();
    } catch (error) {
      const outcome = await handleSessionError(error, msg => setAliasStatus(msg));
      if (outcome === 'refreshed') {
        try {
          await attempt();
          return;
        } catch (retryError) {
          setAliasStatus((retryError as Error).message ?? 'Failed to update alias');
        }
      }
      if (outcome !== 'expired') {
        setAliasStatus((error as Error).message ?? 'Failed to update alias');
      }
    } finally {
      setAliasLoading(false);
    }
  }

  async function handleHydrateAlias(boardId: string) {
    if (!identity) return;
    if (!session?.token) {
      setAliasStatus('Session expired. Re-register identity.');
      return;
    }
    setFetchingAlias(true);
    const attempt = async () => {
      const res = await fetch(
        `${workerBaseUrl}/boards/${encodeURIComponent(boardId)}/aliases?userId=${encodeURIComponent(identity.id)}`,
        {
          headers: {
            Authorization: `Bearer ${session.token}`
          }
        }
      );
      const payload = await res.json().catch(() => ({}));
      raiseForStatus(res, payload, `Failed to fetch alias (${res.status})`);
      const body = payload as GetAliasResponse;
      if (body.alias) {
        setAlias(boardId, body.alias);
        setHydratedAlias(body.alias);
        setAliasValue(body.alias.alias);
      } else {
        setAlias(boardId, null);
        setHydratedAlias(null);
        setAliasValue('');
      }
    };

    try {
      await attempt();
    } catch (error) {
      const outcome = await handleSessionError(error, msg => setAliasStatus(msg));
      if (outcome === 'refreshed') {
        try {
          await attempt();
          return;
        } catch (retryError) {
          setAliasStatus((retryError as Error).message ?? 'Failed to fetch alias');
        }
      }
      if (outcome !== 'expired') {
        setAliasStatus((error as Error).message ?? 'Failed to fetch alias');
      }
    } finally {
      setFetchingAlias(false);
    }
  }

  return (
    <div className="space-y-10">
      <section className="rounded-xl border border-slate-800 bg-slate-900/40 p-6">
        <h2 className="text-sm font-semibold uppercase tracking-[3px] text-slate-400">Identity</h2>
        <form onSubmit={handleRegister} className="mt-4 flex flex-wrap items-end gap-4">
          <label className="flex flex-1 min-w-[220px] flex-col gap-2 text-xs uppercase tracking-[2px] text-slate-500">
            Pseudonym
            <input
              name="pseudonym"
              placeholder="e.g. StudioScout"
              defaultValue=""
              className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-sky-500 focus:outline-none"
            />
          </label>
          <button
            type="submit"
            disabled={registerLoading}
            className="rounded-md bg-sky-500 px-4 py-2 text-sm font-semibold text-slate-950 transition hover:bg-sky-400 disabled:cursor-not-allowed disabled:bg-slate-700 disabled:text-slate-400"
          >
            {registerLoading ? 'Registering…' : registerLabel}
          </button>
        </form>
        {displayIdentity && (
          <div className="mt-3 space-y-2 rounded-md border border-slate-800 bg-slate-900/60 p-3 text-xs text-slate-400">
            <p>
              Current identity: <span className="font-semibold text-slate-200">{displayIdentity.pseudonym}</span>{' '}
              <code className="ml-1 rounded bg-slate-950 px-2 py-1 text-[11px] text-slate-300">{displayIdentity.id}</code>
            </p>
            {displaySession && (
              <div className="flex flex-wrap items-center gap-3 text-[11px] text-slate-500">
                <span>Session expires {new Date(displaySession.expiresAt).toLocaleString()}</span>
                <button
                  type="button"
                  onClick={handleRefreshSession}
                  disabled={refreshingSession}
                  className="rounded-md border border-sky-500/40 px-2 py-1 uppercase tracking-[2px] text-sky-300 transition hover:border-sky-400 hover:text-sky-200 disabled:cursor-not-allowed disabled:border-slate-800 disabled:text-slate-600"
                >
                  {refreshingSession ? 'Refreshing…' : 'Refresh Session'}
                </button>
                <button
                  type="button"
                  onClick={handleLinkAccess}
                  disabled={linkingAccess}
                  className="rounded-md border border-emerald-500/40 px-2 py-1 uppercase tracking-[2px] text-emerald-300 transition hover:border-emerald-400 hover:text-emerald-200 disabled:cursor-not-allowed disabled:border-slate-800 disabled:text-slate-600"
                >
                  {linkingAccess ? 'Linking…' : 'Link Access Identity'}
                </button>
                <button
                  type="button"
                  onClick={() => setSession(null)}
                  className="rounded-md border border-rose-500/40 px-2 py-1 uppercase tracking-[2px] text-rose-300 transition hover:border-rose-400 hover:text-rose-200"
                >
                  Clear Session
                </button>
              </div>
            )}
          </div>
        )}
        {session && (
          <p className="mt-2 text-[11px] text-slate-500">
            Session expires {new Date(session.expiresAt).toLocaleString()}
          </p>
        )}
        {registerError && (
          <p className="mt-3 rounded-md border border-rose-500/40 bg-rose-500/10 p-3 text-xs text-rose-200">{registerError}</p>
        )}
        {sessionStatus && (
          <p className="mt-3 rounded-md border border-sky-500/30 bg-sky-500/10 p-3 text-xs text-sky-200">{sessionStatus}</p>
        )}
        {linkStatus && (
          <p className="mt-3 rounded-md border border-emerald-500/30 bg-emerald-500/10 p-3 text-xs text-emerald-200">{linkStatus}</p>
        )}
      </section>

      <section className="rounded-xl border border-slate-800 bg-slate-900/40 p-6">
        <h2 className="text-sm font-semibold uppercase tracking-[3px] text-slate-400">Board Alias</h2>
        <form onSubmit={handleAliasSubmit} className="mt-4 grid gap-4 sm:grid-cols-3">
          <label className="flex flex-col gap-2 text-xs uppercase tracking-[2px] text-slate-500">
            Board ID
            <input
              value={aliasBoardId}
              onChange={event => {
                setAliasBoardId(event.target.value);
                const stored = event.target.value ? getAlias(event.target.value) : null;
                setAliasValue(stored?.alias ?? '');
                setAliasStatus(null);
              }}
              placeholder="demo-board"
              className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-sky-500 focus:outline-none"
            />
          </label>
          <label className="flex flex-col gap-2 text-xs uppercase tracking-[2px] text-slate-500">
            Alias
            <input
              value={aliasValue}
              onChange={event => {
                setAliasValue(event.target.value);
                setAliasStatus(null);
              }}
              placeholder="e.g. StudioScout"
              className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-sky-500 focus:outline-none"
              disabled={!identity}
            />
          </label>
          <button
            type="submit"
            disabled={!identity || aliasLoading}
            className="self-end rounded-md bg-emerald-500 px-4 py-2 text-sm font-semibold text-slate-950 transition hover:bg-emerald-400 disabled:cursor-not-allowed disabled:bg-slate-700 disabled:text-slate-400"
          >
            {aliasLoading ? 'Saving…' : 'Save Alias'}
          </button>
        </form>
        <div className="mt-3 flex flex-wrap items-center gap-3 text-xs text-slate-500">
          <button
            type="button"
            onClick={() => aliasBoardId && handleHydrateAlias(aliasBoardId)}
            disabled={!identity || !aliasBoardId || fetchingAlias}
            className="rounded-md border border-slate-700 px-3 py-1 text-[11px] uppercase tracking-[2px] text-slate-300 transition hover:border-sky-500 disabled:cursor-not-allowed disabled:border-slate-800 disabled:text-slate-600"
          >
            {fetchingAlias ? 'Fetching…' : 'Refresh Alias'}
          </button>
          {hydratedAlias && (
            <span className="rounded bg-slate-900 px-2 py-1 font-mono text-[11px] text-slate-300">{hydratedAlias.alias}</span>
          )}
        </div>
        {aliasStatus && (
          <p className="mt-3 rounded-md border border-slate-800 bg-slate-900/60 p-3 text-xs text-emerald-300/80">{aliasStatus}</p>
        )}
        {identity && aliasSuggestions.length > 0 && (
          <div className="mt-4 flex flex-wrap items-center gap-2 text-[11px] text-slate-400">
            <span className="uppercase tracking-[2px] text-slate-500">Try:</span>
            {aliasSuggestions.map(suggestion => (
              <button
                key={suggestion}
                type="button"
                onClick={() => {
                  setAliasValue(suggestion);
                  setAliasStatus(null);
                  addToast({ title: 'Alias suggestion applied', description: suggestion });
                }}
                className="rounded-full border border-slate-700 px-3 py-1 text-slate-300 transition hover:border-sky-500 hover:text-sky-200"
              >
                {suggestion}
              </button>
            ))}
          </div>
        )}
      </section>

      <section className="rounded-xl border border-slate-800 bg-slate-900/40 p-6">
        <h2 className="text-sm font-semibold uppercase tracking-[3px] text-slate-400">Saved Aliases</h2>
        {aliasEntries.length === 0 && (
          <p className="mt-3 text-xs text-slate-500">No aliases cached yet. Register one above to populate this list.</p>
        )}
        {aliasEntries.length > 0 && (
          <ul className="mt-3 space-y-2 text-xs text-slate-300">
            {aliasEntries.map(([boardId, value]) => (
              <li key={boardId} className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-900/60 p-3">
                <div>
                  <p className="font-semibold text-slate-200">{boardId}</p>
                  <p className="text-[11px] text-slate-500">{value?.alias ?? '—'}</p>
                </div>
                <button
                  type="button"
                  onClick={() => {
                    setAlias(boardId, null);
                    if (boardId === aliasBoardId) {
                      setAliasValue('');
                    }
                  }}
                  className="rounded-md border border-rose-500/40 px-3 py-1 text-[11px] uppercase tracking-[2px] text-rose-300 transition hover:border-rose-400 hover:text-rose-200"
                >
                  Clear
                </button>
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}
