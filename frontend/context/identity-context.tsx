"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useState, ReactNode } from 'react';
import type { RegisterIdentityResponse, BoardAlias, SessionTicket } from '@board-app/shared';
import { SESSION_TTL_MS } from '@board-app/shared';

interface IdentityContextValue {
  identity: RegisterIdentityResponse['user'] | null;
  aliasMap: Record<string, BoardAlias | null>;
  setIdentity(user: RegisterIdentityResponse['user'] | null): void;
  setAlias(boardId: string, alias: BoardAlias | null): void;
  getAlias(boardId: string): BoardAlias | null;
  session: SessionTicket | null;
  setSession(session: SessionTicket | null): void;
  refreshSession(workerBaseUrl?: string): Promise<SessionTicket | null>;
  linkAccessIdentity(workerBaseUrl?: string): Promise<RegisterIdentityResponse['user'] | null>;
  recoverIdentity(pseudonym: string, recoveryKey: string, workerBaseUrl?: string): Promise<boolean>;
  logout(workerBaseUrl?: string): Promise<void>;
  hydrated: boolean;
}

const IdentityContext = createContext<IdentityContextValue | undefined>(undefined);
const DEFAULT_WORKER_BASE_URL = process.env.NEXT_PUBLIC_WORKER_BASE_URL ?? 'http://localhost:8788';

function getStoredIdentity(): RegisterIdentityResponse['user'] | null {
  if (typeof window === 'undefined') return null;
  try {
    const raw = window.localStorage.getItem('boardapp:identity');
    return raw ? (JSON.parse(raw) as RegisterIdentityResponse['user']) : null;
  } catch {
    return null;
  }
}

function getStoredAlias(boardId: string): BoardAlias | null {
  if (typeof window === 'undefined') return null;
  try {
    const raw = window.localStorage.getItem(`boardapp:alias:${boardId}`);
    return raw ? (JSON.parse(raw) as BoardAlias) : null;
  } catch {
    return null;
  }
}

function clearStoredAliases() {
  if (typeof window === 'undefined') return;
  const keys: string[] = [];
  for (let i = 0; i < window.localStorage.length; i += 1) {
    const key = window.localStorage.key(i);
    if (key?.startsWith('boardapp:alias:')) {
      keys.push(key);
    }
  }
  for (const key of keys) {
    window.localStorage.removeItem(key);
  }
}

export function IdentityProvider({ children }: { children: ReactNode }) {
  const [identity, setIdentityState] = useState<RegisterIdentityResponse['user'] | null>(null);
  const [aliasMap, setAliasMap] = useState<Record<string, BoardAlias | null>>({});
  const [session, setSessionState] = useState<SessionTicket | null>(null);
  const [hydrated, setHydrated] = useState(false);
  const [linkAttempted, setLinkAttempted] = useState(false);

  useEffect(() => {
    if (typeof window === 'undefined') return;

    // 1. Load optimistic identity (user profile)
    const storedIdentity = getStoredIdentity();
    if (storedIdentity) {
      setIdentityState(storedIdentity);
    }

    // 2. Load aliases
    const entries: Record<string, BoardAlias | null> = {};
    for (let i = 0; i < window.localStorage.length; i += 1) {
      const key = window.localStorage.key(i);
      if (!key?.startsWith('boardapp:alias:')) continue;
      const boardId = key.split(':').at(-1);
      if (!boardId) continue;
      try {
        const value = window.localStorage.getItem(key);
        if (!value) continue;
        entries[boardId] = JSON.parse(value) as BoardAlias;
      } catch {
        // ignore malformed entries
      }
    }
    if (Object.keys(entries).length > 0) {
      setAliasMap(entries);
    }

    // 3. Verify session with backend (HttpOnly cookie)
    const verifySession = async () => {
      // Optimization: if we don't have a stored identity, we likely aren't logged in.
      // Skipping the request avoids 401 errors in the console for guests.
      if (!storedIdentity) {
        setHydrated(true);
        return;
      }

      try {
        const res = await fetch(`${DEFAULT_WORKER_BASE_URL}/identity/session`, {
          method: 'GET',
          headers: { 'content-type': 'application/json' },
          credentials: 'include'
        });

        if (res.ok) {
          const payload = await res.json() as { user: RegisterIdentityResponse['user']; session: SessionTicket };
          setIdentityState(payload.user);
          setSessionState(payload.session);
        } else {
          // Session invalid or expired
          setIdentityState(null);
          setSessionState(null);
          window.localStorage.removeItem('boardapp:identity');
        }
      } catch (error) {
        console.warn('[identity] failed to verify session', error);
        // Keep optimistic identity if network fails? Or clear it? 
        // Safer to clear if we can't verify, but for offline support we might want to keep it.
        // For now, let's assume if we can't reach the backend, we might be offline.
      } finally {
        setHydrated(true);
      }
    };

    verifySession();
  }, []);

  useEffect(() => {
    if (!hydrated || typeof window === 'undefined') return;
    if (identity) {
      window.localStorage.setItem('boardapp:identity', JSON.stringify(identity));
    } else {
      window.localStorage.removeItem('boardapp:identity');
    }
  }, [identity, hydrated]);

  // Removed session persistence effect (handled by cookies)

  const setIdentity = useCallback((user: RegisterIdentityResponse['user'] | null) => {
    const previousId = identity?.id;
    setIdentityState(user);
    if (!user) {
      setSessionState(null);
      clearStoredAliases();
      setAliasMap({});
      return;
    }

    if (!previousId || previousId !== user.id) {
      clearStoredAliases();
      setAliasMap({});
    }
  }, [identity?.id]);

  const setAlias = useCallback((boardId: string, alias: BoardAlias | null) => {
    setAliasMap(prev => ({ ...prev, [boardId]: alias }));
    if (typeof window === 'undefined') return;
    if (alias) {
      window.localStorage.setItem(`boardapp:alias:${boardId}`, JSON.stringify(alias));
    } else {
      window.localStorage.removeItem(`boardapp:alias:${boardId}`);
    }
  }, []);

  const getAlias = useCallback((boardId: string): BoardAlias | null => {
    const existing = aliasMap[boardId];
    if (existing) return existing;
    return getStoredAlias(boardId);
  }, [aliasMap]);

  const setSession = useCallback((ticket: SessionTicket | null) => {
    setSessionState(ticket);
  }, []);

  const refreshSession = useCallback(
    async (workerBaseUrl?: string) => {
      // We don't need the token in the header anymore, cookies handle it
      const base = workerBaseUrl ?? (typeof window !== 'undefined' ? DEFAULT_WORKER_BASE_URL : '');
      if (!base) return null;
      try {
        const res = await fetch(`${base}/identity/session`, {
          method: 'POST',
          headers: {
            'content-type': 'application/json'
          },
          body: JSON.stringify({ userId: identity?.id }), // userId is optional in backend but good to send
          credentials: 'include'
        });
        const payload = await res.json().catch(() => ({}));
        if (!res.ok || !payload?.session) {
          throw new Error(payload?.error ?? `Failed to refresh session (${res.status})`);
        }
        const next = payload.session as SessionTicket;
        setSessionState(next);
        return next;
      } catch (error) {
        console.warn('[identity] failed to refresh session', error);
        setSessionState(null);
        return null;
      }
    },
    [identity?.id]
  );

  const linkAccessIdentity = useCallback(
    async (workerBaseUrl?: string) => {
      const base = workerBaseUrl ?? (typeof window !== 'undefined' ? DEFAULT_WORKER_BASE_URL : '');
      if (!base) return null;
      try {
        const res = await fetch(`${base}/identity/link`, {
          method: 'POST',
          credentials: 'include'
        });
        if (res.status === 401 || res.status === 403) {
          setLinkAttempted(true);
          return null;
        }
        const payload = await res.json().catch(() => ({}));
        if (!res.ok) {
          throw new Error(payload?.error ?? `Failed to link identity (${res.status})`);
        }
        const linkedUser = payload?.user as RegisterIdentityResponse['user'] | undefined;
        if (linkedUser) {
          setIdentity(linkedUser);
          setLinkAttempted(true);
          return linkedUser;
        }
        setLinkAttempted(true);
        return null;
      } catch (error) {
        console.warn('[identity] failed to link access identity', error);
        setLinkAttempted(true);
        return null;
      }
    },
    [setIdentity]
  );

  const recoverIdentity = useCallback(
    async (pseudonym: string, recoveryKey: string, workerBaseUrl?: string) => {
      const base = workerBaseUrl ?? (typeof window !== 'undefined' ? DEFAULT_WORKER_BASE_URL : '');
      if (!base) return false;
      try {
        const res = await fetch(`${base}/identity/recover`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ pseudonym, recoveryKey }),
          credentials: 'include'
        });

        const payload = await res.json().catch(() => ({}));
        if (!res.ok || !payload?.session) {
          throw new Error(payload?.error ?? `Failed to recover identity (${res.status})`);
        }

        const user = payload.user as RegisterIdentityResponse['user'];
        const session = payload.session as SessionTicket;
        setIdentity(user);
        setSession(session);
        return true;
      } catch (error) {
        console.warn('[identity] failed to recover identity', error);
        return false;
      }
    },
    [setIdentity, setSession]
  );

  const logout = useCallback(
    async (workerBaseUrl?: string) => {
      const base = workerBaseUrl ?? DEFAULT_WORKER_BASE_URL;
      try {
        await fetch(`${base}/identity/logout`, {
          method: 'POST',
          credentials: 'include'
        });
      } catch (error) {
        console.warn('[identity] remote logout failed', error);
      }
      setIdentity(null);
      setSession(null);
      setLinkAttempted(false);
      if (typeof window !== 'undefined') {
        window.localStorage.removeItem('boardapp:identity');
        // We don't remove session from local storage because we stopped putting it there
      }
    },
    [setIdentity]
  );

  useEffect(() => {
    if (!identity || !session?.expiresAt) return;
    const msUntilRefresh = session.expiresAt - Date.now() - 60_000;
    if (msUntilRefresh <= 0) {
      refreshSession().catch(() => { });
      return;
    }
    const timer = window.setTimeout(() => {
      refreshSession().catch(() => { });
    }, msUntilRefresh);
    return () => window.clearTimeout(timer);
  }, [identity?.id, session?.expiresAt, refreshSession]);

  useEffect(() => {
    setLinkAttempted(false);
  }, [session?.token, identity?.id]);

  useEffect(() => {
    if (!hydrated || !identity || !session?.token || linkAttempted) return;
    // We only try to link if we have a session but maybe not the right identity?
    // Actually, linkAccessIdentity uses the cookie now, so we just check if we are logged in.
    // But wait, if we are logged in, we have an identity.
    // This logic was: if we have a session token but maybe we want to upgrade/link to Access?
    // Let's keep it but ensure it uses credentials.
    linkAccessIdentity()
      .catch(() => null)
      .finally(() => setLinkAttempted(true));
  }, [hydrated, identity?.id, session?.token, linkAttempted, linkAccessIdentity]);

  const value = useMemo<IdentityContextValue>(
    () => ({ identity, aliasMap, setIdentity, setAlias, getAlias, session, setSession, refreshSession, linkAccessIdentity, recoverIdentity, logout, hydrated }),
    [identity, aliasMap, setIdentity, setAlias, getAlias, session, setSession, refreshSession, linkAccessIdentity, recoverIdentity, logout, hydrated]
  );

  return <IdentityContext.Provider value={value}>{children}</IdentityContext.Provider>;
}

export function useIdentityContext(): IdentityContextValue {
  const context = useContext(IdentityContext);
  if (!context) {
    throw new Error('useIdentityContext must be used within an IdentityProvider');
  }
  return context;
}
