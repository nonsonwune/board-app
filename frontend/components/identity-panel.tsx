'use client';

import { FormEvent, useEffect, useMemo, useState } from 'react';
import type { BoardAlias, GetAliasResponse, RegisterIdentityResponse, UpsertAliasResponse } from '@board-app/shared';
import { useIdentityContext } from '../context/identity-context';

interface IdentityPanelProps {
  workerBaseUrl?: string;
}

export default function IdentityPanel({ workerBaseUrl: baseUrl }: IdentityPanelProps) {
  const workerBaseUrl = baseUrl ?? process.env.NEXT_PUBLIC_WORKER_BASE_URL ?? 'http://localhost:8788';
  const { identity, aliasMap, setIdentity, setAlias, getAlias } = useIdentityContext();
  const [registerError, setRegisterError] = useState<string | null>(null);
  const [registerLoading, setRegisterLoading] = useState(false);
  const [aliasBoardId, setAliasBoardId] = useState('');
  const [aliasValue, setAliasValue] = useState('');
  const [aliasStatus, setAliasStatus] = useState<string | null>(null);
  const [aliasLoading, setAliasLoading] = useState(false);
  const [fetchingAlias, setFetchingAlias] = useState(false);
  const [hydratedAlias, setHydratedAlias] = useState<BoardAlias | null>(null);

  const aliasEntries = useMemo(() => Object.entries(aliasMap).filter(([, value]) => value), [aliasMap]);

  useEffect(() => {
    if (!identity) {
      setAliasBoardId('');
      setAliasValue('');
    }
  }, [identity?.id]);

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
      form.reset();
    } catch (error) {
      setRegisterError((error as Error).message ?? 'Failed to register identity');
    } finally {
      setRegisterLoading(false);
    }
  }

  async function handleAliasSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!identity) {
      setAliasStatus('Register an identity first.');
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
    try {
      const res = await fetch(`${workerBaseUrl}/boards/${encodeURIComponent(aliasBoardId)}/aliases`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ userId: identity.id, alias })
      });
      const payload = await res.json().catch(() => ({}));
      if (!res.ok) {
        throw new Error(payload?.error ?? `Failed to update alias (${res.status})`);
      }
      const body = payload as UpsertAliasResponse;
      setAlias(aliasBoardId, body.alias);
      setAliasStatus(`Alias for ${aliasBoardId} set to “${body.alias.alias}”.`);
    } catch (error) {
      setAliasStatus((error as Error).message ?? 'Failed to update alias');
    } finally {
      setAliasLoading(false);
    }
  }

  async function handleHydrateAlias(boardId: string) {
    if (!identity) return;
    setFetchingAlias(true);
    try {
      const res = await fetch(
        `${workerBaseUrl}/boards/${encodeURIComponent(boardId)}/aliases?userId=${encodeURIComponent(identity.id)}`
      );
      const payload = await res.json().catch(() => ({}));
      if (!res.ok) {
        throw new Error(payload?.error ?? `Failed to fetch alias (${res.status})`);
      }
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
    } catch (error) {
      setAliasStatus((error as Error).message ?? 'Failed to fetch alias');
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
            {registerLoading ? 'Registering…' : identity ? 'Re-register' : 'Register'}
          </button>
        </form>
        {identity && (
          <p className="mt-3 rounded-md border border-slate-800 bg-slate-900/60 p-3 text-xs text-slate-400">
            Current identity: <span className="font-semibold text-slate-200">{identity.pseudonym}</span>{' '}
            <code className="ml-1 rounded bg-slate-950 px-2 py-1 text-[11px] text-slate-300">{identity.id}</code>
          </p>
        )}
        {registerError && (
          <p className="mt-3 rounded-md border border-rose-500/40 bg-rose-500/10 p-3 text-xs text-rose-200">{registerError}</p>
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
