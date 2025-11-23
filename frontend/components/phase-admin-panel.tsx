
'use client';

import { FormEvent, useCallback, useEffect, useMemo, useState } from 'react';
import dynamic from 'next/dynamic';
import { useToast } from './toast-provider';
import type { BoardSummary } from '@board-app/shared';
import type { BoardMapProps } from './board-map';
import type { BoardLocationPickerProps } from './board-location-picker';
import { formatRelativeTime } from '../lib/date';

interface PhaseSettings {
  boardId: string;
  phaseMode: 'default' | 'phase1';
  textOnly: boolean;
  radiusMeters: number;
  latitude: number | null;
  longitude: number | null;
}

const DEFAULT_BASE_URL = process.env.NEXT_PUBLIC_WORKER_BASE_URL ?? 'http://localhost:8788';

const BoardMap = dynamic<BoardMapProps>(() => import('./board-map'), {
  ssr: false,
  loading: () => (
    <div className="overflow-hidden rounded-2xl border border-border/60">
      <div className="flex h-[260px] w-full items-center justify-center bg-surface text-sm text-text-secondary">
        Loading map…
      </div>
    </div>
  )
});

const BoardLocationPicker = dynamic<BoardLocationPickerProps>(() => import('./board-location-picker'), {
  ssr: false,
  loading: () => (
    <div className="overflow-hidden rounded-2xl border border-border/60">
      <div className="flex h-[260px] w-full items-center justify-center bg-surface text-sm text-text-secondary">
        Loading map tools…
      </div>
    </div>
  )
});

export default function PhaseAdminPanel() {
  const { addToast } = useToast();
  const [workerUrl, setWorkerUrl] = useState(DEFAULT_BASE_URL);
  const [boardId, setBoardId] = useState('');
  const [token, setToken] = useState('');
  const [loading, setLoading] = useState(false);
  const [settings, setSettings] = useState<PhaseSettings | null>(null);
  const [boards, setBoards] = useState<BoardSummary[]>([]);
  const [boardsLoading, setBoardsLoading] = useState(false);
  const [boardsError, setBoardsError] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const filteredBoards = useMemo(() => {
    const term = search.trim().toLowerCase();
    if (!term) {
      return boards;
    }
    return boards.filter(board =>
      board.displayName?.toLowerCase().includes(term) || board.id.toLowerCase().includes(term)
    );
  }, [boards, search]);

  const selectedBoard = useMemo(
    () => boards.find(board => board.id === settings?.boardId) ?? null,
    [boards, settings?.boardId]
  );

  const fetchBoards = useCallback(async () => {
    setBoardsLoading(true);
    setBoardsError(null);
    try {
      const res = await fetch(`${workerUrl.replace(/\/$/, '')}/boards/catalog?limit=200`);
      const payload = await res.json().catch(() => ({}));
      if (!res.ok || !payload?.boards) {
        throw new Error(payload?.error ?? `Failed to load boards (${res.status})`);
      }
      setBoards(payload.boards as BoardSummary[]);
    } catch (error) {
      setBoardsError((error as Error).message);
    } finally {
      setBoardsLoading(false);
    }
  }, [workerUrl]);

  const fetchSettings = useCallback(async (targetId?: string) => {
    const resolvedId = targetId !== undefined ? targetId.trim() : boardId.trim();
    if (!resolvedId) {
      addToast({ title: 'Board required', description: 'Enter a board ID to load settings.' });
      return;
    }
    setLoading(true);
    try {
      const res = await fetch(`${workerUrl.replace(/\/$/, '')}/boards/${encodeURIComponent(resolvedId)}/phase`, {
        headers: token ? { Authorization: `Bearer ${token}` } : undefined
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) {
        throw new Error(body?.error ?? `Failed to load (${res.status})`);
      }
      setSettings({
        boardId: body.boardId ?? resolvedId,
        phaseMode: body.phaseMode === 'phase1' ? 'phase1' : 'default',
        textOnly: Boolean(body.textOnly),
        radiusMeters: Number(body.radiusMeters) || 1500,
        latitude: typeof body.latitude === 'number' ? body.latitude : null,
        longitude: typeof body.longitude === 'number' ? body.longitude : null
      });
      setBoardId(resolvedId);
      addToast({ title: 'Settings loaded', description: `Board ${resolvedId} ready.` });
    } catch (error) {
      addToast({ title: 'Fetch failed', description: (error as Error).message });
      setSettings(null);
    } finally {
      setLoading(false);
    }
  }, [workerUrl, boardId, token, addToast]);

  useEffect(() => {
    fetchBoards();
  }, [fetchBoards]);

  useEffect(() => {
    if (!settings && boards.length > 0) {
      fetchSettings(boards[0].id);
    }
  }, [boards, settings, fetchSettings]);

  const handleSelectBoard = useCallback(
    (id: string) => {
      setBoardId(id);
      fetchSettings(id);
    },
    [fetchSettings]
  );

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
      const normalizedLatitude = typeof settings.latitude === 'number' && Number.isFinite(settings.latitude)
        ? settings.latitude
        : null;
      const normalizedLongitude = typeof settings.longitude === 'number' && Number.isFinite(settings.longitude)
        ? settings.longitude
        : null;
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
            radiusMeters: settings.radiusMeters,
            latitude: normalizedLatitude,
            longitude: normalizedLongitude
          })
        });
        const body = await res.json().catch(() => ({}));
        if (!res.ok) {
          throw new Error(body?.error ?? `Failed to save (${res.status})`);
        }
        setSettings(prev =>
          prev
            ? {
                ...prev,
                phaseMode: body.phaseMode === 'phase1' ? 'phase1' : prev.phaseMode,
                textOnly: typeof body.textOnly === 'boolean' ? body.textOnly : prev.textOnly,
                radiusMeters: Number(body.radiusMeters) || prev.radiusMeters,
                latitude: typeof body.latitude === 'number' ? body.latitude : normalizedLatitude,
                longitude: typeof body.longitude === 'number' ? body.longitude : normalizedLongitude
              }
            : prev
        );
        setBoards(prev =>
          prev.map(board =>
            board.id === boardId.trim()
              ? {
                  ...board,
                  phaseMode: body.phaseMode === 'phase1' ? 'phase1' : board.phaseMode,
                  textOnly: typeof body.textOnly === 'boolean' ? body.textOnly : board.textOnly,
                  radiusMeters: Number(body.radiusMeters) || board.radiusMeters,
                  latitude:
                    typeof body.latitude === 'number'
                      ? body.latitude
                      : normalizedLatitude ?? board.latitude ?? null,
                  longitude:
                    typeof body.longitude === 'number'
                      ? body.longitude
                      : normalizedLongitude ?? board.longitude ?? null
                }
              : board
          )
        );
        addToast({ title: 'Phase settings updated', description: `Board ${boardId.trim()} saved.` });
      } catch (error) {
        addToast({ title: 'Save failed', description: (error as Error).message });
      } finally {
        setLoading(false);
      }
    },
    [workerUrl, boardId, token, settings, addToast]
  );

  const previewLatitude = settings?.latitude ?? selectedBoard?.latitude ?? null;
  const previewLongitude = settings?.longitude ?? selectedBoard?.longitude ?? null;
  const previewRadius = settings?.radiusMeters ?? selectedBoard?.radiusMeters ?? 1500;

  return (
    <div className="grid gap-6 lg:grid-cols-[320px,1fr]">
      <aside className="space-y-4">
        <div>
          <h2 className="text-sm font-semibold uppercase tracking-[2px] text-text-tertiary">Boards</h2>
          <div className="mt-2 flex items-center gap-2">
            <input
              value={search}
              onChange={event => setSearch(event.target.value)}
              placeholder="Search boards"
              className="w-full rounded-md border border-border/60 bg-surface px-3 py-2 text-sm text-text-primary focus:border-primary focus:outline-none"
            />
            <button
              type="button"
              onClick={fetchBoards}
              className="inline-flex items-center rounded-md border border-border/60 bg-surface px-3 py-2 text-xs font-semibold uppercase tracking-[2px] text-text-secondary transition hover:border-primary/40 hover:text-primary"
              disabled={boardsLoading}
            >
              Refresh
            </button>
          </div>
        </div>
        {boardsError && (
          <div className="rounded-lg border border-primary/40 bg-primary/10 p-3 text-sm text-primary">
            {boardsError}
          </div>
        )}
        <div className="max-h-[28rem] overflow-y-auto rounded-xl border border-border/60 bg-surface">
          {boardsLoading ? (
            <div className="space-y-2 p-3">
              {[0, 1, 2, 3].map(item => (
                <div key={item} className="h-16 rounded-lg bg-surface-raised/60 animate-pulse" />
              ))}
            </div>
          ) : filteredBoards.length === 0 ? (
            <p className="p-3 text-sm text-text-secondary">No boards found. Adjust your search.</p>
          ) : (
            <div className="divide-y divide-border/40">
              {filteredBoards.map(board => {
                const isActive = board.id === settings?.boardId;
                const trend = board.postsTrend24Hr ?? null;
                const trendClass = trend !== null ? (trend > 0 ? 'text-success' : trend < 0 ? 'text-danger' : 'text-text-secondary') : 'text-text-secondary';
                return (
                  <button
                    key={board.id}
                    type="button"
                    onClick={() => handleSelectBoard(board.id)}
                    className={`w-full px-4 py-3 text-left transition ${
                      isActive ? 'bg-surface-raised/80 border-l-4 border-primary' : 'hover:bg-surface-raised/60'
                    }`}
                  >
                    <p className="text-sm font-semibold text-text-primary">{board.displayName ?? board.id}</p>
                    <p className="text-xs text-text-tertiary">{board.id}</p>
                    <div className="mt-2 flex flex-wrap gap-3 text-[11px] text-text-secondary">
                      <span>Live: {board.activeConnections ?? 0}</span>
                      <span>Posts/hr: {board.postsLastHour ?? 0}</span>
                      {trend !== null && (
                        <span className={trendClass}>Trend: {trend > 0 ? '+' : ''}{Math.round(trend)}%</span>
                      )}
                      {board.lastPostAt && (
                        <span>Last post {formatRelativeTime(board.lastPostAt)}</span>
                      )}
                    </div>
                  </button>
                );
              })}
            </div>
          )}
        </div>
      </aside>

      <div className="space-y-8 rounded-xl border border-border bg-background p-6 text-text-primary">
        <header className="space-y-2">
          <h1 className="text-2xl font-semibold text-text-primary">Phase 1 Controls</h1>
          <p className="text-sm text-text-secondary">Manage radius, text-only mode, and location for individual boards.</p>
        </header>

        {selectedBoard && (
          <section className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            <div className="rounded-lg border border-border bg-surface p-3">
              <p className="text-[11px] uppercase tracking-[2px] text-text-tertiary">Live viewers</p>
              <p className="mt-1 text-lg font-semibold text-text-primary">{selectedBoard.activeConnections ?? 0}</p>
            </div>
            <div className="rounded-lg border border-border bg-surface p-3">
              <p className="text-[11px] uppercase tracking-[2px] text-text-tertiary">Posts (1h)</p>
              <p className="mt-1 text-lg font-semibold text-text-primary">{selectedBoard.postsLastHour ?? 0}</p>
            </div>
            <div className="rounded-lg border border-border bg-surface p-3">
              <p className="text-[11px] uppercase tracking-[2px] text-text-tertiary">Posts (24h)</p>
              <p className="mt-1 text-lg font-semibold text-text-primary">{selectedBoard.postsLastDay ?? 0}</p>
            </div>
            <div className="rounded-lg border border-border bg-surface p-3">
              <p className="text-[11px] uppercase tracking-[2px] text-text-tertiary">Trend 24h</p>
              <p className={`mt-1 text-lg font-semibold ${selectedBoard.postsTrend24Hr ? (selectedBoard.postsTrend24Hr > 0 ? 'text-success' : 'text-danger') : 'text-text-primary'}`}>
                {selectedBoard.postsTrend24Hr ? `${selectedBoard.postsTrend24Hr > 0 ? '+' : ''}${Math.round(selectedBoard.postsTrend24Hr)}%` : 'n/a'}
              </p>
            </div>
            <div className="rounded-lg border border-border bg-surface p-3">
              <p className="text-[11px] uppercase tracking-[2px] text-text-tertiary">Radius</p>
              <p className="mt-1 text-lg font-semibold text-text-primary">{selectedBoard.radiusLabel ?? `${Math.round(selectedBoard.radiusMeters ?? 1500)} m`}</p>
            </div>
            <div className="rounded-lg border border-border bg-surface p-3">
              <p className="text-[11px] uppercase tracking-[2px] text-text-tertiary">Last post</p>
              <p className="mt-1 text-lg font-semibold text-text-primary">
                {selectedBoard.lastPostAt ? formatRelativeTime(selectedBoard.lastPostAt) : 'No activity'}
              </p>
            </div>
          </section>
        )}

        <form onSubmit={handleSubmit} className="space-y-6">
          <div className="grid gap-4 sm:grid-cols-2">
            <label className="flex flex-col gap-2 text-xs uppercase tracking-[2px] text-text-tertiary">
              Worker URL
              <input
                value={workerUrl}
                onChange={event => setWorkerUrl(event.target.value)}
                className="rounded-md border border-border bg-background px-3 py-2 text-sm text-text-primary focus:border-primary focus:outline-none"
              />
            </label>
            <label className="flex flex-col gap-2 text-xs uppercase tracking-[2px] text-text-tertiary">
              Admin Token
              <input
                value={token}
                onChange={event => setToken(event.target.value)}
                placeholder="Bearer token"
                className="rounded-md border border-border bg-background px-3 py-2 text-sm text-text-primary focus:border-primary focus:outline-none"
              />
            </label>
          </div>
          <div className="grid gap-4 sm:grid-cols-3">
            <label className="flex flex-col gap-2 text-xs uppercase tracking-[2px] text-text-tertiary">
              Board ID
              <input
                value={boardId}
                onChange={event => setBoardId(event.target.value)}
                placeholder="campus-north"
                className="rounded-md border border-border bg-background px-3 py-2 text-sm text-text-primary focus:border-primary focus:outline-none"
              />
            </label>
            <button
              type="button"
              onClick={() => fetchSettings()}
              disabled={loading}
              className="self-end rounded-md border border-primary/40 px-3 py-2 text-sm font-semibold text-primary transition hover:border-primary hover:text-primary disabled:cursor-not-allowed disabled:border-border disabled:text-text-tertiary"
            >
              {loading ? 'Loading…' : 'Fetch Settings'}
            </button>
          </div>

          {settings && (
            <div className="space-y-4 rounded-lg border border-border bg-surface p-4">
              <div className="flex flex-wrap items-center gap-3 text-sm text-text-secondary">
                <span className="rounded-full border border-primary/40 bg-primary/10 px-3 py-1 text-primary">
                  Mode: {settings.phaseMode === 'phase1' ? 'Phase 1 (fixed radius)' : 'Default'}
                </span>
                {settings.textOnly && (
                  <span className="rounded-full border border-primary/40 bg-primary/10 px-3 py-1 text-primary">
                    Text-only enabled
                  </span>
                )}
                <span className="rounded-full border border-border px-3 py-1 text-xs uppercase tracking-[2px] text-text-secondary">
                  Board: {settings.boardId}
                </span>
              </div>
              <div className="flex flex-wrap items-center gap-4">
                <label className="flex items-center gap-2 text-sm text-text-primary">
                  <input
                    type="radio"
                    name="phaseMode"
                    value="default"
                    checked={settings.phaseMode === 'default'}
                    onChange={() => setSettings(prev => (prev ? { ...prev, phaseMode: 'default' } : prev))}
                  />
                  Default Mode
                </label>
                <label className="flex items-center gap-2 text-sm text-text-primary">
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
              <label className="flex items-center gap-2 text-sm text-text-primary">
                <input
                  type="checkbox"
                  checked={settings.textOnly}
                  onChange={event =>
                    setSettings(prev => (prev ? { ...prev, textOnly: event.target.checked } : prev))
                  }
                />
                Text-only posts
              </label>
              <label className="flex flex-col gap-2 text-xs uppercase tracking-[2px] text-text-tertiary">
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
                  className="w-40 rounded-md border border-border bg-background px-3 py-2 text-sm text-text-primary focus:border-primary focus:outline-none disabled:cursor-not-allowed disabled:border-border disabled:text-text-tertiary"
                />
                {settings.phaseMode !== 'phase1' && (
                  <span className="text-[11px] text-text-tertiary">Radius adjustments only apply in Phase 1 mode.</span>
                )}
              </label>
            <div className="grid gap-4 sm:grid-cols-2">
              <label className="flex flex-col gap-2 text-xs uppercase tracking-[2px] text-text-tertiary">
                Latitude
                <input
                  type="number"
                    step="0.000001"
                    value={settings.latitude ?? ''}
                    onChange={event =>
                      setSettings(prev =>
                        prev
                          ? {
                              ...prev,
                              latitude: event.target.value.trim() === '' ? null : Number(event.target.value)
                            }
                          : prev
                      )
                    }
                    className="rounded-md border border-border bg-background px-3 py-2 text-sm text-text-primary focus:border-primary focus:outline-none"
                    placeholder="e.g. 6.5244"
                  />
                </label>
                <label className="flex flex-col gap-2 text-xs uppercase tracking-[2px] text-text-tertiary">
                  Longitude
                  <input
                    type="number"
                    step="0.000001"
                    value={settings.longitude ?? ''}
                    onChange={event =>
                      setSettings(prev =>
                        prev
                          ? {
                              ...prev,
                              longitude: event.target.value.trim() === '' ? null : Number(event.target.value)
                            }
                          : prev
                      )
                    }
                    className="rounded-md border border-border bg-background px-3 py-2 text-sm text-text-primary focus:border-primary focus:outline-none"
                  placeholder="e.g. 3.3792"
                />
              </label>
            </div>
            <BoardLocationPicker
              latitude={settings.latitude}
              longitude={settings.longitude}
              radiusMeters={settings.radiusMeters}
              onChange={({ latitude, longitude }) =>
                setSettings(prev => (prev ? { ...prev, latitude, longitude } : prev))
              }
            />
          </div>
        )}

          <div className="flex items-center gap-3">
            <button
              type="submit"
              disabled={loading || !settings}
              className="rounded-md bg-primary px-4 py-2 text-sm font-semibold text-text-inverse transition hover:bg-primary-dark disabled:cursor-not-allowed disabled:bg-border disabled:text-text-tertiary"
            >
              {loading ? 'Saving…' : 'Save Phase Settings'}
            </button>
            {settings && (
              <span className="text-xs text-text-tertiary">Last radius: {Math.round(settings.radiusMeters)} m</span>
            )}
          </div>
        </form>

        {previewLatitude !== null && previewLongitude !== null && (
          <section className="space-y-3">
            <h2 className="text-sm font-semibold uppercase tracking-[2px] text-text-tertiary">Map preview</h2>
            <BoardMap latitude={previewLatitude} longitude={previewLongitude} radiusMeters={previewRadius} />
          </section>
        )}
      </div>
    </div>
  );
}
