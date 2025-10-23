"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useState, ReactNode } from 'react';
import { setCookie, deleteCookie, getCookie } from 'cookies-next';
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
  hydrated: boolean;
}

const IdentityContext = createContext<IdentityContextValue | undefined>(undefined);
const SESSION_COOKIE_NAME = 'boardapp_session_0';

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

function getStoredSession(): SessionTicket | null {
  if (typeof window === 'undefined') return null;
  try {
    const cookie = getCookie(SESSION_COOKIE_NAME);
    if (cookie) {
      return JSON.parse(cookie.toString()) as SessionTicket;
    }
  } catch {
    // ignore malformed cookie
  }
  try {
    const raw = window.localStorage.getItem('boardapp:session');
    return raw ? (JSON.parse(raw) as SessionTicket) : null;
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
    const storedIdentity = getStoredIdentity();
    if (storedIdentity) {
      setIdentityState(storedIdentity);
    }

    const storedSession = getStoredSession();
    if (storedSession) {
      setSessionState(storedSession);
    }

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
    setHydrated(true);
  }, []);

  useEffect(() => {
    if (!hydrated || typeof window === 'undefined') return;
    if (identity) {
      window.localStorage.setItem('boardapp:identity', JSON.stringify(identity));
    } else {
      window.localStorage.removeItem('boardapp:identity');
    }
  }, [identity, hydrated]);

  useEffect(() => {
    if (!hydrated) return;
    if (session) {
      if (typeof window !== 'undefined') {
        window.localStorage.setItem('boardapp:session', JSON.stringify(session));
      }
      setCookie(SESSION_COOKIE_NAME, JSON.stringify(session), {
        maxAge: SESSION_TTL_MS / 1000,
        sameSite: 'lax',
        path: '/'
      });
    } else {
      if (typeof window !== 'undefined') {
        window.localStorage.removeItem('boardapp:session');
      }
      deleteCookie(SESSION_COOKIE_NAME, { path: '/' });
    }
  }, [session, hydrated]);

  const setIdentity = (user: RegisterIdentityResponse['user'] | null) => {
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
  };

  const setAlias = (boardId: string, alias: BoardAlias | null) => {
    setAliasMap(prev => ({ ...prev, [boardId]: alias }));
    if (typeof window === 'undefined') return;
    if (alias) {
      window.localStorage.setItem(`boardapp:alias:${boardId}`, JSON.stringify(alias));
    } else {
      window.localStorage.removeItem(`boardapp:alias:${boardId}`);
    }
  };

  const getAlias = (boardId: string): BoardAlias | null => {
    const existing = aliasMap[boardId];
    if (existing) return existing;
    return getStoredAlias(boardId);
  };

  const setSession = (ticket: SessionTicket | null) => {
    setSessionState(ticket);
  };

  const refreshSession = useCallback(
    async (workerBaseUrl?: string) => {
      if (!identity || !session?.token) return null;
      const base =
        workerBaseUrl ??
        (typeof window !== 'undefined' ? process.env.NEXT_PUBLIC_WORKER_BASE_URL ?? 'http://localhost:8788' : '');
      if (!base) return null;
      try {
        const res = await fetch(`${base}/identity/session`, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            Authorization: `Bearer ${session.token}`
          },
          body: JSON.stringify({ userId: identity.id })
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
    [identity, session]
  );

  const linkAccessIdentity = useCallback(
    async (workerBaseUrl?: string) => {
      if (!session?.token) return null;
      const base =
        workerBaseUrl ??
        (typeof window !== 'undefined' ? process.env.NEXT_PUBLIC_WORKER_BASE_URL ?? 'http://localhost:8788' : '');
      if (!base) return null;
      try {
        const res = await fetch(`${base}/identity/link`, {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${session.token}`
          }
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
    [session?.token]
  );

  useEffect(() => {
    if (!identity || !session?.expiresAt) return;
    const msUntilRefresh = session.expiresAt - Date.now() - 60_000;
    if (msUntilRefresh <= 0) {
      refreshSession().catch(() => {});
      return;
    }
    const timer = window.setTimeout(() => {
      refreshSession().catch(() => {});
    }, msUntilRefresh);
    return () => window.clearTimeout(timer);
  }, [identity?.id, session?.expiresAt, refreshSession]);

  useEffect(() => {
    setLinkAttempted(false);
  }, [session?.token, identity?.id]);

  useEffect(() => {
    if (!hydrated || !identity || !session?.token || linkAttempted) return;
    linkAccessIdentity()
      .catch(() => null)
      .finally(() => setLinkAttempted(true));
  }, [hydrated, identity?.id, session?.token, linkAttempted, linkAccessIdentity]);

  const value = useMemo<IdentityContextValue>(
    () => ({ identity, aliasMap, setIdentity, setAlias, getAlias, session, setSession, refreshSession, linkAccessIdentity, hydrated }),
    [identity, aliasMap, session, refreshSession, linkAccessIdentity, hydrated]
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
