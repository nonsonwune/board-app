"use client";

import { createContext, useContext, useEffect, useMemo, useState, ReactNode } from 'react';
import type { RegisterIdentityResponse, BoardAlias } from '@board-app/shared';

interface IdentityContextValue {
  identity: RegisterIdentityResponse['user'] | null;
  aliasMap: Record<string, BoardAlias | null>;
  setIdentity(user: RegisterIdentityResponse['user'] | null): void;
  setAlias(boardId: string, alias: BoardAlias | null): void;
  getAlias(boardId: string): BoardAlias | null;
  hydrated: boolean;
}

const IdentityContext = createContext<IdentityContextValue | undefined>(undefined);

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

export function IdentityProvider({ children }: { children: ReactNode }) {
  const [identity, setIdentityState] = useState<RegisterIdentityResponse['user'] | null>(() => getStoredIdentity());
  const [aliasMap, setAliasMap] = useState<Record<string, BoardAlias | null>>({});
  const [hydrated, setHydrated] = useState(false);

  useEffect(() => {
    if (typeof window === 'undefined') return;
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
    if (typeof window === 'undefined') return;
    if (identity) {
      window.localStorage.setItem('boardapp:identity', JSON.stringify(identity));
    } else {
      window.localStorage.removeItem('boardapp:identity');
    }
  }, [identity]);

  const setIdentity = (user: RegisterIdentityResponse['user'] | null) => {
    setIdentityState(user);
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

  const value = useMemo<IdentityContextValue>(
    () => ({ identity, aliasMap, setIdentity, setAlias, getAlias, hydrated }),
    [identity, aliasMap, hydrated]
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
