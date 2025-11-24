'use client';

import { FormEvent, useEffect, useMemo, useState } from 'react';
import type {
  BoardAlias,
  GetAliasResponse,
  RegisterIdentityResponse,
  SessionTicket,
  UpsertAliasResponse
} from '@board-app/shared';
import { statusMessages } from '@board-app/shared';
type HttpError = Error & { status?: number; payload?: unknown };
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
    recoverIdentity,
    hydrated,
    logout
  } = useIdentityContext();
  const [registerError, setRegisterError] = useState<string | null>(null);
  const [registerLoading, setRegisterLoading] = useState(false);
  const [recoveryKey, setRecoveryKey] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'create' | 'recover'>('create');
  const [recoverError, setRecoverError] = useState<string | null>(null);
  const [recoverLoading, setRecoverLoading] = useState(false);
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
  const hasActiveIdentity = Boolean(displayIdentity?.id && displaySession?.token);
  const allowRegister = !hasActiveIdentity;
  const { addToast } = useToast();
  const copy = statusMessages;
  const aliasCopy = copy.alias;
  const sessionCopy = copy.session;
  const accessCopy = copy.access;

  const raiseForStatus = (res: Response, payload: unknown, fallback: string) => {
    if (res.ok) return;
    const message =
      typeof payload === 'object' && payload !== null && 'error' in payload
        ? String((payload as { error?: unknown }).error ?? '')
        : undefined;
    const error = new Error(message || fallback) as HttpError;
    error.status = res.status;
    error.payload = payload;
    throw error;
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
      const payloadMessage =
        typeof httpError.payload === 'object' && httpError.payload !== null && 'error' in httpError.payload
          ? String((httpError.payload as { error?: unknown }).error ?? '')
          : '';
      setter(payloadMessage || sessionCopy.expired);
      setSession(null);
      return 'expired';
    }
    setter(sessionCopy.error);
    return 'noop';
  };

  useEffect(() => {
    if (!identity) {
      setAliasBoardId('');
      setAliasValue('');
    }
  }, [identity, identity?.id]);

  useEffect(() => {
    setSessionStatus(null);
  }, [identity?.id, session?.token]);

  async function handleRegister(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!allowRegister) {
      setRegisterError('You are already signed in. Sign out before registering a new identity.');
      return;
    }
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
      setRegisterError('Unable to reach the identity service. Make sure the worker is running on http://localhost:8788.');
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

    const body = payload as RegisterIdentityResponse & { recoveryKey?: string };
    setIdentity(body.user);
    setSession(body.session as SessionTicket);
    setRegisterError(null);
    if (body.recoveryKey) {
      setRecoveryKey(body.recoveryKey);
    }
    form.reset();
    addToast({ title: 'Identity registered', description: `Hello, ${body.user.pseudonym}!` });
    setRegisterLoading(false);
  }

  async function handleRecover(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const formData = new FormData(form);
    const pseudonym = (formData.get('pseudonym') as string)?.trim();
    const key = (formData.get('recoveryKey') as string)?.trim();

    if (!pseudonym || !key) {
      setRecoverError('Pseudonym and Recovery Key are required.');
      return;
    }

    setRecoverError(null);
    setRecoverLoading(true);

    const success = await recoverIdentity(pseudonym, key, workerBaseUrl);

    if (success) {
      setRecoverError(null);
      form.reset();
      addToast({ title: 'Identity recovered', description: `Welcome back, ${pseudonym}!` });
    } else {
      setRecoverError('Invalid identity or recovery key.');
    }
    setRecoverLoading(false);
  }

  async function handleRefreshSession() {
    if (!identity || !session?.token) {
      setRegisterError(aliasCopy.requireIdentity);
      return;
    }
    setSessionStatus(sessionCopy.refreshing);
    setRefreshingSession(true);
    try {
      const ticket = await refreshSession(workerBaseUrl);
      if (!ticket) {
        setRegisterError(sessionCopy.expired);
        setSessionStatus(sessionCopy.error);
        addToast({ title: 'Session refresh failed', description: sessionCopy.error });
      } else {
        setRegisterError(null);
        const restoredMessage = sessionCopy.restored({ expiresAt: new Date(ticket.expiresAt) });
        setSessionStatus(restoredMessage);
        addToast({ title: 'Session refreshed', description: restoredMessage });
      }
    } finally {
      setRefreshingSession(false);
    }
  }

  async function handleLinkAccess() {
    setLinkStatus(accessCopy.linking);
    setLinkingAccess(true);
    try {
      const user = await linkAccessIdentity(workerBaseUrl);
      if (user) {
        const linkedMessage = accessCopy.linked({ pseudonym: user.pseudonym });
        setLinkStatus(linkedMessage);
        addToast({ title: 'Access linked', description: linkedMessage });
      } else {
        setLinkStatus(accessCopy.unavailable);
        addToast({ title: 'Access link unavailable', description: accessCopy.unavailable });
      }
    } catch (error) {
      const httpError = error as HttpError;
      if (httpError?.status === 403 || httpError?.status === 401) {
        setLinkStatus(accessCopy.forbidden);
        addToast({ title: 'Access link failed', description: accessCopy.forbidden });
      } else {
        setLinkStatus(httpError?.message ?? accessCopy.error);
        addToast({ title: 'Access link failed', description: httpError?.message ?? accessCopy.error });
      }
    } finally {
      setLinkingAccess(false);
    }
  }

  async function handleLogout() {
    // Clear sensitive data from UI state before logout
    setRecoveryKey(null);
    setRegisterError(null);
    setRecoverError(null);
    await logout(workerBaseUrl);
  }


  async function handleAliasSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!identity) {
      setAliasStatus(aliasCopy.requireIdentity);
      return;
    }
    if (!session?.token) {
      setAliasStatus(aliasCopy.requireSession);
      return;
    }
    if (!aliasBoardId.trim()) {
      setAliasStatus(aliasCopy.boardRequired);
      return;
    }
    const alias = aliasValue.trim();
    if (!alias) {
      setAliasStatus(aliasCopy.aliasRequired);
      return;
    }

    setAliasLoading(true);
    setAliasStatus(aliasCopy.saving);

    const attempt = async () => {
      const res = await fetch(`${workerBaseUrl}/boards/${encodeURIComponent(aliasBoardId)}/aliases`, {
        method: 'PUT',
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
      const savedMessage = aliasCopy.saved({ boardId: aliasBoardId, alias: body.alias.alias });
      setAliasStatus(savedMessage);
      addToast({ title: 'Alias saved', description: savedMessage });
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
          const httpError = retryError as HttpError;
          if (httpError?.status === 409) {
            setAliasStatus(aliasCopy.conflict);
          } else {
            setAliasStatus(httpError?.message || aliasCopy.error);
          }
        }
      }
      if (outcome !== 'expired') {
        const httpError = error as HttpError;
        if (httpError?.status === 409) {
          setAliasStatus(aliasCopy.conflict);
        } else {
          setAliasStatus(httpError?.message || aliasCopy.error);
        }
      }
    } finally {
      setAliasLoading(false);
    }
  }

  async function handleHydrateAlias(boardId: string) {
    if (!identity) return;
    if (!session?.token) {
      setAliasStatus(aliasCopy.requireSession);
      return;
    }
    setFetchingAlias(true);
    setAliasStatus(aliasCopy.fetching);
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
        setAliasStatus(aliasCopy.fetched({ boardId, alias: body.alias.alias }));
      } else {
        setAlias(boardId, null);
        setHydratedAlias(null);
        setAliasValue('');
        setAliasStatus(aliasCopy.fetched({ boardId, alias: null }));
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
          setAliasStatus((retryError as Error).message ?? aliasCopy.error);
        }
      }
      if (outcome !== 'expired') {
        setAliasStatus((error as Error).message ?? aliasCopy.error);
      }
    } finally {
      setFetchingAlias(false);
    }
  }

  return (
    <div className="space-y-10">
      <section id="identity" className="rounded-xl border border-border bg-surface p-6">
        <h2 className="text-xs font-semibold uppercase tracking-[3px] text-text-tertiary">Identity Management</h2>

        {!hasActiveIdentity ? (
          <div className="mt-4 space-y-6">
            <div className="flex gap-4 border-b border-border">
              <button
                type="button"
                onClick={() => setActiveTab('create')}
                className={`pb-2 text-xs font-semibold uppercase tracking-[2px] transition ${activeTab === 'create' ? 'border-b-2 border-primary text-primary' : 'text-text-tertiary hover:text-text-secondary'
                  }`}
              >
                Create
              </button>
              <button
                type="button"
                onClick={() => setActiveTab('recover')}
                className={`pb-2 text-xs font-semibold uppercase tracking-[2px] transition ${activeTab === 'recover' ? 'border-b-2 border-primary text-primary' : 'text-text-tertiary hover:text-text-secondary'
                  }`}
              >
                Recover
              </button>
            </div>

            {activeTab === 'create' ? (
              <div>
                <h3 className="text-sm font-medium text-text-primary">Create New Identity</h3>
                <p className="mt-1 text-xs text-text-secondary">
                  Start fresh with a new pseudonym. This will create a new session on this device.
                </p>
                <form onSubmit={handleRegister} className="mt-3 flex flex-wrap items-end gap-4">
                  <label className="flex min-w-[220px] flex-1 flex-col gap-2 text-xs uppercase tracking-[2px] text-text-tertiary">
                    Pseudonym
                    <input
                      name="pseudonym"
                      placeholder="e.g. StudioScout"
                      defaultValue={identity?.pseudonym ?? ''}
                      className="rounded-md border border-border bg-background px-3 py-2 text-sm text-text-primary focus:border-primary focus:outline-none"
                    />
                  </label>
                  <button
                    type="submit"
                    disabled={registerLoading}
                    className="rounded-full bg-primary px-5 py-2 text-sm font-semibold uppercase tracking-[2px] text-text-inverse transition hover:bg-primary-dark disabled:cursor-not-allowed disabled:bg-primary/40 disabled:text-text-inverse/70"
                  >
                    {registerLoading ? 'Creating…' : 'Create Identity'}
                  </button>
                </form>
                {registerError && (
                  <p className="mt-3 rounded-lg border border-primary/40 bg-primary/10 p-3 text-xs text-primary">{registerError}</p>
                )}
              </div>
            ) : (
              <div>
                <h3 className="text-sm font-medium text-text-primary">Recover Identity</h3>
                <p className="mt-1 text-xs text-text-secondary">
                  Enter your pseudonym and recovery key to sign back in.
                </p>
                <form onSubmit={handleRecover} className="mt-3 space-y-4">
                  <div className="flex flex-wrap gap-4">
                    <label className="flex min-w-[200px] flex-1 flex-col gap-2 text-xs uppercase tracking-[2px] text-text-tertiary">
                      Pseudonym
                      <input
                        name="pseudonym"
                        placeholder="e.g. StudioScout"
                        className="rounded-md border border-border bg-background px-3 py-2 text-sm text-text-primary focus:border-primary focus:outline-none"
                      />
                    </label>
                    <label className="flex min-w-[200px] flex-1 flex-col gap-2 text-xs uppercase tracking-[2px] text-text-tertiary">
                      Recovery Key
                      <input
                        name="recoveryKey"
                        placeholder="xxxx-xxxx-xxxx-xxxx"
                        className="rounded-md border border-border bg-background px-3 py-2 text-sm text-text-primary focus:border-primary focus:outline-none"
                      />
                    </label>
                  </div>
                  <button
                    type="submit"
                    disabled={recoverLoading}
                    className="rounded-full bg-primary px-5 py-2 text-sm font-semibold uppercase tracking-[2px] text-text-inverse transition hover:bg-primary-dark disabled:cursor-not-allowed disabled:bg-primary/40 disabled:text-text-inverse/70"
                  >
                    {recoverLoading ? 'Recovering…' : 'Recover Identity'}
                  </button>
                </form>
                {recoverError && (
                  <p className="mt-3 rounded-lg border border-primary/40 bg-primary/10 p-3 text-xs text-primary">{recoverError}</p>
                )}
              </div>
            )}

            <div className="border-t border-border pt-4">
              <h3 className="text-sm font-medium text-text-primary">Cloudflare Access</h3>
              <p className="mt-1 text-xs text-text-secondary">
                If you are using Cloudflare Access, you can link your existing identity to this session.
              </p>
              <div className="mt-3">
                <button
                  type="button"
                  onClick={handleLinkAccess}
                  disabled={linkingAccess}
                  className="rounded-full border border-border px-4 py-2 text-xs font-semibold uppercase tracking-[2px] text-text-secondary transition hover:border-primary hover:text-primary disabled:cursor-not-allowed disabled:opacity-60"
                >
                  {linkingAccess ? 'Linking…' : 'Link Access Identity'}
                </button>
              </div>
            </div>
          </div>
        ) : (
          <div className="mt-4">
            <p className="text-sm text-text-secondary">
              You are currently signed in.
            </p>
            {displayIdentity && (
              <div className="mt-4 space-y-3 rounded-lg border border-border bg-background p-4 text-sm text-text-secondary">
                <div className="flex items-center justify-between">
                  <p>
                    Current identity: <span className="font-semibold text-text-primary">{displayIdentity.pseudonym}</span>{' '}
                    <code className="ml-2 rounded bg-surface px-2 py-1 text-[11px] text-text-tertiary">{displayIdentity.id}</code>
                  </p>
                  <span className="flex items-center gap-2 text-[10px] uppercase tracking-wider text-green-600">
                    <span className="h-2 w-2 rounded-full bg-green-500"></span>
                    Active Session
                  </span>
                </div>

                <div className="flex flex-wrap items-center gap-3 text-[11px] uppercase tracking-[2px] text-text-secondary pt-2 border-t border-border/50">
                  {displaySession ? (
                    <span>Expires {new Date(displaySession.expiresAt).toLocaleString()}</span>
                  ) : (
                    <span>No active session detected</span>
                  )}
                  <div className="flex-1"></div>
                  <button
                    type="button"
                    onClick={handleRefreshSession}
                    disabled={refreshingSession || !session?.token} // Actually session.token is not available in context if we removed it from state? Wait, we kept session state, just not in localStorage.
                    className="rounded-full border border-border px-3 py-1 transition hover:border-primary hover:text-primary disabled:cursor-not-allowed disabled:opacity-60"
                  >
                    {refreshingSession ? 'Refreshing…' : 'Refresh'}
                  </button>
                  <button
                    type="button"
                    onClick={handleLogout}
                    className="rounded-full border border-border px-3 py-1 transition hover:border-primary hover:text-primary"
                  >
                    Sign Out
                  </button>
                </div>
              </div>
            )}
          </div>
        )}

        {recoveryKey && (
          <div className="mt-4 rounded-lg border border-green-500/40 bg-green-500/10 p-4">
            <h3 className="text-sm font-bold text-green-600 uppercase tracking-wider">Save This Key!</h3>
            <p className="mt-1 text-xs text-text-secondary">
              This is your only way to recover your account if you log out. We do not store it.
            </p>
            <div className="mt-3 flex items-center gap-2">
              <code className="flex-1 rounded bg-surface px-3 py-2 font-mono text-sm text-text-primary select-all">
                {recoveryKey}
              </code>
              <button
                type="button"
                onClick={() => {
                  navigator.clipboard.writeText(recoveryKey);
                  addToast({ title: 'Copied', description: 'Recovery key copied to clipboard' });
                }}
                className="rounded-md border border-border bg-background px-3 py-2 text-xs font-semibold uppercase tracking-wider text-text-secondary hover:text-primary"
              >
                Copy
              </button>
            </div>
          </div>
        )}
        {/* Removed duplicate registerError display since it is inside the tab now */}
        {sessionStatus && (
          <p className="mt-3 rounded-lg border border-border bg-background p-3 text-xs text-text-secondary">{sessionStatus}</p>
        )}
        {linkStatus && (
          <p className="mt-3 rounded-lg border border-border bg-background p-3 text-xs text-text-secondary">{linkStatus}</p>
        )}
      </section>

      <section id="aliases" className="rounded-xl border border-border bg-surface p-6">
        <h2 className="text-xs font-semibold uppercase tracking-[3px] text-text-tertiary">Board Alias</h2>
        <form onSubmit={handleAliasSubmit} className="mt-4 grid gap-4 sm:grid-cols-3">
          <label className="flex flex-col gap-2 text-xs uppercase tracking-[2px] text-text-tertiary">
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
              className="rounded-md border border-border bg-background px-3 py-2 text-sm text-text-primary focus:border-primary focus:outline-none"
            />
          </label>
          <label className="flex flex-col gap-2 text-xs uppercase tracking-[2px] text-text-tertiary">
            Alias
            <input
              value={aliasValue}
              onChange={event => {
                setAliasValue(event.target.value);
                setAliasStatus(null);
              }}
              placeholder="e.g. StudioScout"
              className="rounded-md border border-border bg-background px-3 py-2 text-sm text-text-primary focus:border-primary focus:outline-none"
              disabled={!identity}
            />
          </label>
          <button
            type="submit"
            disabled={!identity || aliasLoading}
            className="self-end rounded-full bg-primary px-5 py-2 text-sm font-semibold uppercase tracking-[2px] text-text-inverse transition hover:bg-primary-dark disabled:cursor-not-allowed disabled:bg-primary/40 disabled:text-text-inverse/70"
          >
            {aliasLoading ? 'Saving…' : 'Save Alias'}
          </button>
        </form>
        <div className="mt-3 flex flex-wrap items-center gap-3 text-xs text-text-secondary">
          <button
            type="button"
            onClick={() => aliasBoardId && handleHydrateAlias(aliasBoardId)}
            disabled={!identity || !aliasBoardId || fetchingAlias}
            className="rounded-full border border-border px-3 py-1 uppercase tracking-[2px] transition hover:border-primary hover:text-primary disabled:cursor-not-allowed disabled:opacity-60"
          >
            {fetchingAlias ? 'Fetching…' : 'Refresh Alias'}
          </button>
          {hydratedAlias && (
            <span className="rounded bg-background px-2 py-1 font-mono text-[11px] text-text-secondary">{hydratedAlias.alias}</span>
          )}
        </div>
        {aliasStatus && (
          <p className="mt-3 rounded-lg border border-primary/40 bg-primary/10 p-3 text-xs text-primary">{aliasStatus}</p>
        )}
        {identity && aliasSuggestions.length > 0 && (
          <div className="mt-4 flex flex-wrap items-center gap-2 text-[11px] text-text-secondary">
            <span className="uppercase tracking-[2px] text-text-tertiary">Try:</span>
            {aliasSuggestions.map(suggestion => (
              <button
                key={suggestion}
                type="button"
                onClick={() => {
                  setAliasValue(suggestion);
                  setAliasStatus(null);
                  addToast({ title: 'Alias suggestion applied', description: suggestion });
                }}
                className="rounded-full border border-border px-3 py-1 transition hover:border-primary hover:text-primary"
              >
                {suggestion}
              </button>
            ))}
          </div>
        )}
      </section>

      <section className="rounded-xl border border-border bg-surface p-6">
        <h2 className="text-xs font-semibold uppercase tracking-[3px] text-text-tertiary">Saved Aliases</h2>
        {aliasEntries.length === 0 && (
          <p className="mt-3 text-xs text-text-secondary">No aliases cached yet. Register one above to populate this list.</p>
        )}
        {aliasEntries.length > 0 && (
          <ul className="mt-3 space-y-2 text-xs text-text-secondary">
            {aliasEntries.map(([boardId, value]) => (
              <li key={boardId} className="flex items-center justify-between rounded-lg border border-border bg-background p-3">
                <div>
                  <p className="font-semibold text-text-primary">{boardId}</p>
                  <p className="text-[11px] text-text-tertiary">{value?.alias ?? '—'}</p>
                </div>
                <button
                  type="button"
                  onClick={() => {
                    setAlias(boardId, null);
                    if (boardId === aliasBoardId) {
                      setAliasValue('');
                    }
                    setAliasStatus(aliasCopy.cleared({ boardId }));
                  }}
                  className="rounded-full border border-primary px-3 py-1 text-[11px] uppercase tracking-[2px] text-primary transition hover:bg-primary hover:text-text-inverse"
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
