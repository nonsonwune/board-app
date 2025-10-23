
'use client';

import { FormEvent, useCallback, useState } from 'react';
import { useToast } from './toast-provider';

interface PhaseSettings {
  boardId: string;
  phaseMode: 'default' | 'phase1';
  textOnly: boolean;
  radiusMeters: number;
}

const DEFAULT_BASE_URL = process.env.NEXT_PUBLIC_WORKER_BASE_URL ?? 'http://localhost:8788';

export default function PhaseAdminPanel() {
  const { addToast } = useToast();
  const [workerUrl, setWorkerUrl] = useState(DEFAULT_BASE_URL);
  const [boardId, setBoardId] = useState('');
  const [token, setToken] = useState('');
  const [loading, setLoading] = useState(false);
  const [settings, setSettings] = useState<PhaseSettings | null>(null);

  const fetchSettings = useCallback(async () => {
    if (!boardId.trim()) {
      addToast({ title: 'Board required', description: 'Enter a board ID to load settings.' });
      return;
    }
    setLoading(true);
    try {
      const res = await fetch(`${workerUrl.replace(/\/$/, '')}/boards/${encodeURIComponent(boardId.trim())}/phase`, {
        headers: token ? { Authorization: `Bearer ${token}` } : undefined
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) {
        throw new Error(body?.error ?? `Failed to load (${res.status})`);
      }
      setSettings({
        boardId: body.boardId ?? boardId.trim(),
        phaseMode: body.phaseMode === 'phase1' ? 'phase1' : 'default',
        textOnly: Boolean(body.textOnly),
        radiusMeters: Number(body.radiusMeters) || 1500
      });
      addToast({ title: 'Settings loaded', description: `Board ${boardId.trim()} ready.` });
    } catch (error) {
      addToast({ title: 'Fetch failed', description: (error as Error).message });
      setSettings(null);
    } finally {
      setLoading(false);
    }
  }, [workerUrl, boardId, token, addToast]);

  const handleSubmit = useCallback(
    async (event: FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      if (!boardId.trim()) {
        addToast({ title: 'Board required', description: 'Enter a board ID before saving.' });
        return;
      }
      if (!token.trim()) {
        addToast({ title: 'Token required', description: 'Provide the admin token to update settings.' });
        return;
      }
      if (!settings) {
        addToast({ title: 'Load settings first', description: 'Fetch the board before saving changes.' });
        return;
      }
      setLoading(true);
      try {
        const res = await fetch(`${workerUrl.replace(/\/$/, '')}/boards/${encodeURIComponent(boardId.trim())}/phase`, {
          method: 'PUT',
          headers: {
            'content-type': 'application/json',
            Authorization: `Bearer ${token}`
          },
          body: JSON.stringify({
            phaseMode: settings.phaseMode,
            textOnly: settings.textOnly,
            radiusMeters: settings.radiusMeters
          })
        });
        const body = await res.json().catch(() => ({}));
        if (!res.ok) {
          throw new Error(body?.error ?? `Failed to save (${res.status})`);
        }
        addToast({ title: 'Phase settings updated', description: `Board ${boardId.trim()} saved.` });
      } catch (error) {
        addToast({ title: 'Save failed', description: (error as Error).message });
      } finally {
        setLoading(false);
      }
    },
    [workerUrl, boardId, token, settings, addToast]
  );

  return (
    <div className="space-y-8 rounded-xl border border-slate-800 bg-slate-950/50 p-6 text-slate-100">
      <header className="space-y-2">
        <h1 className="text-2xl font-semibold text-white">Phase 1 Controls</h1>
        <p className="text-sm text-slate-400">
          Manage fixed-radius and text-only launch settings for individual boards.
        </p>
      </header>

      <form onSubmit={handleSubmit} className="space-y-6">
        <div className="grid gap-4 sm:grid-cols-2">
          <label className="flex flex-col gap-2 text-xs uppercase tracking-[2px] text-slate-500">
            Worker URL
            <input
              value={workerUrl}
              onChange={event => setWorkerUrl(event.target.value)}
              className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-sky-500 focus:outline-none"
            />
          </label>
          <label className="flex flex-col gap-2 text-xs uppercase tracking-[2px] text-slate-500">
            Admin Token
            <input
              value={token}
              onChange={event => setToken(event.target.value)}
              placeholder="Bearer token"
              className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-rose-500 focus:outline-none"
            />
          </label>
        </div>
        <div className="grid gap-4 sm:grid-cols-3">
          <label className="flex flex-col gap-2 text-xs uppercase tracking-[2px] text-slate-500">
            Board ID
            <input
              value={boardId}
              onChange={event => setBoardId(event.target.value)}
              placeholder="campus-north"
              className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-sky-500 focus:outline-none"
            />
          </label>
          <button
            type="button"
            onClick={fetchSettings}
            disabled={loading}
            className="self-end rounded-md border border-sky-500/40 px-3 py-2 text-sm font-semibold text-sky-200 transition hover:border-sky-400 hover:text-sky-100 disabled:cursor-not-allowed disabled:border-slate-800 disabled:text-slate-500"
          >
            {loading ? 'Loading…' : 'Fetch Settings'}
          </button>
        </div>

        {settings && (
          <div className="space-y-4 rounded-lg border border-slate-800 bg-slate-900/40 p-4">
            <div className="flex flex-wrap items-center gap-3 text-sm text-slate-300">
              <span className="rounded-full border border-sky-500/40 bg-sky-500/10 px-3 py-1 text-sky-200">
                Mode: {settings.phaseMode === 'phase1' ? 'Phase 1 (fixed radius)' : 'Default'}
              </span>
              {settings.textOnly && (
                <span className="rounded-full border border-amber-500/40 bg-amber-500/10 px-3 py-1 text-amber-200">
                  Text-only enabled
                </span>
              )}
              <span className="rounded-full border border-slate-700 px-3 py-1 text-xs uppercase tracking-[2px] text-slate-400">
                Board: {settings.boardId}
              </span>
            </div>
            <div className="flex flex-wrap items-center gap-4">
              <label className="flex items-center gap-2 text-sm text-slate-200">
                <input
                  type="radio"
                  name="phaseMode"
                  value="default"
                  checked={settings.phaseMode === 'default'}
                  onChange={() => setSettings(prev => (prev ? { ...prev, phaseMode: 'default' } : prev))}
                />
                Default Mode
              </label>
              <label className="flex items-center gap-2 text-sm text-slate-200">
                <input
                  type="radio"
                  name="phaseMode"
                  value="phase1"
                  checked={settings.phaseMode === 'phase1'}
                  onChange={() => setSettings(prev => (prev ? { ...prev, phaseMode: 'phase1' } : prev))}
                />
                Phase 1 (Fixed Radius)
              </label>
            </div>
            <label className="flex items-center gap-2 text-sm text-slate-200">
              <input
                type="checkbox"
                checked={settings.textOnly}
                onChange={event =>
                  setSettings(prev => (prev ? { ...prev, textOnly: event.target.checked } : prev))
                }
              />
              Text-only posts
            </label>
            <label className="flex flex-col gap-2 text-xs uppercase tracking-[2px] text-slate-500">
              Fixed Radius (meters)
              <input
                type="number"
                min={250}
                max={5000}
                value={settings.radiusMeters}
                onChange={event =>
                  setSettings(prev =>
                    prev ? { ...prev, radiusMeters: Number(event.target.value) || prev.radiusMeters } : prev
                  )
                }
                disabled={settings.phaseMode !== 'phase1'}
                className="w-40 rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-sky-500 focus:outline-none disabled:cursor-not-allowed disabled:border-slate-800 disabled:text-slate-500"
              />
              {settings.phaseMode !== 'phase1' && (
                <span className="text-[11px] text-slate-500">Radius adjustments only apply in Phase 1 mode.</span>
              )}
            </label>
          </div>
        )}

        <div className="flex items-center gap-3">
          <button
            type="submit"
            disabled={loading || !settings}
            className="rounded-md bg-sky-500 px-4 py-2 text-sm font-semibold text-slate-950 transition hover:bg-sky-400 disabled:cursor-not-allowed disabled:bg-slate-800 disabled:text-slate-500"
          >
            {loading ? 'Saving…' : 'Save Phase Settings'}
          </button>
          {settings && (
            <span className="text-xs text-slate-500">Last radius: {Math.round(settings.radiusMeters)} m</span>
          )}
        </div>
      </form>
    </div>
  );
}
