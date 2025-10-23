"use client";

import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useState,
  type ReactNode
} from "react";

export type ConnectionStatus = "connected" | "connecting" | "offline" | "error";

export interface SpaceTab {
  id: string;
  label: string;
  isActive?: boolean;
  badge?: string;
  disabled?: boolean;
}

export interface BoardPillState {
  name: string;
  radiusLabel?: string;
  isLive?: boolean;
  liveLabel?: string;
  onPress?: () => void;
}

export interface ConnectionIndicatorState {
  status: ConnectionStatus;
  label?: string;
  showDnd?: boolean;
  showAdminLock?: boolean;
  onPress?: () => void;
}

export interface SpaceTabsState {
  tabs: SpaceTab[];
  onSelect?: (tabId: string) => void;
  activeTabId?: string;
}

export interface TopBarState {
  board?: BoardPillState | null;
  spaces?: SpaceTabsState | null;
  connection?: ConnectionIndicatorState | null;
  show?: boolean;
}

export interface FabState {
  label: string;
  icon?: ReactNode;
  onPress?: () => void;
  disabled?: boolean;
  tooltip?: string;
  variant?: "primary" | "live";
  pulse?: boolean;
  visible?: boolean;
}

interface AppChromeContextValue {
  topBar: TopBarState;
  setTopBar: (next: TopBarState | ((prev: TopBarState) => TopBarState)) => void;
  resetTopBar: () => void;
  fab: FabState | null;
  setFab: (next: FabState | null) => void;
  resetFab: () => void;
}

const defaultTopBarState: TopBarState = {
  board: null,
  spaces: null,
  connection: null,
  show: true
};

const AppChromeContext = createContext<AppChromeContextValue | undefined>(undefined);

export function AppChromeProvider({ children }: { children: ReactNode }) {
  const [topBar, setTopBarState] = useState<TopBarState>(defaultTopBarState);
  const [fab, setFabState] = useState<FabState | null>(null);

  const setTopBar = useCallback(
    (next: TopBarState | ((prev: TopBarState) => TopBarState)) => {
      setTopBarState(current => (typeof next === "function" ? (next as (prev: TopBarState) => TopBarState)(current) : next));
    },
    []
  );

  const resetTopBar = useCallback(() => {
    setTopBarState(defaultTopBarState);
  }, []);

  const setFab = useCallback((next: FabState | null) => {
    setFabState(next);
  }, []);

  const resetFab = useCallback(() => {
    setFabState(null);
  }, []);

  const value = useMemo<AppChromeContextValue>(
    () => ({ topBar, setTopBar, resetTopBar, fab, setFab, resetFab }),
    [topBar, setTopBar, resetTopBar, fab, setFab, resetFab]
  );

  return <AppChromeContext.Provider value={value}>{children}</AppChromeContext.Provider>;
}

export function useAppChrome(): AppChromeContextValue {
  const context = useContext(AppChromeContext);
  if (!context) {
    throw new Error("useAppChrome must be used within an AppChromeProvider");
  }
  return context;
}
