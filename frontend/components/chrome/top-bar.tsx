"use client";

import type {
  ConnectionIndicatorState,
  TopBarState
} from "../../context/app-chrome-context";
import { Lock, MapPin, Moon, Wifi } from "lucide-react";

interface TopBarProps {
  state: TopBarState;
}

const statusTone: Record<ConnectionIndicatorState["status"], string> = {
  connected: "bg-success/25 text-success",
  connecting: "bg-warning/20 text-warning",
  offline: "bg-text-tertiary/20 text-text-tertiary",
  error: "bg-danger/20 text-danger"
};

function BoardPill({ state }: { state: NonNullable<TopBarState["board"]> }) {
  const { name, radiusLabel, isLive, liveLabel, onPress } = state;
  const Element = onPress ? "button" : "div";
  return (
    <Element
      type={onPress ? "button" : undefined}
      onClick={onPress}
      className={cn(
        "group inline-flex items-center gap-2 rounded-full border border-border/70 bg-surface-raised/80 px-3 py-1.5 text-sm font-medium",
        onPress && "transition-colors hover:border-primary/60 hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/60"
      )}
    >
      <span className="inline-flex items-center gap-1 text-text-primary">
        <MapPin className="h-4 w-4" aria-hidden />
        <span className="truncate max-w-[10rem]" title={name}>
          {name}
        </span>
      </span>
      {radiusLabel && <span className="text-xs text-text-secondary">{radiusLabel}</span>}
      {isLive && (
        <span className="inline-flex items-center gap-1 rounded-full bg-danger/15 px-2 py-0.5 text-[11px] uppercase tracking-[1.5px] text-danger">
          <span className="relative inline-flex h-1.5 w-1.5 items-center justify-center">
            <span className="absolute inline-flex h-full w-full rounded-full bg-danger opacity-80 animate-ping" />
            <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-danger" />
          </span>
          {liveLabel ?? "Live"}
        </span>
      )}
    </Element>
  );
}

function SpaceTabs({ state }: { state: NonNullable<TopBarState["spaces"]> }) {
  const { tabs, onSelect, activeTabId } = state;
  if (!tabs?.length) return null;
  return (
    <div className="flex overflow-x-auto pb-1" role="tablist" aria-label="Spaces">
      <div className="flex min-w-full gap-2">
        {tabs.map(tab => {
          const isActive = tab.isActive ?? (activeTabId ? tab.id === activeTabId : false);
          return (
            <button
              key={tab.id}
              type="button"
              disabled={tab.disabled}
              onClick={() => onSelect?.(tab.id)}
              role="tab"
              aria-selected={isActive}
              className={cn(
                "flex items-center gap-2 rounded-full border px-3 py-1 text-sm font-medium transition-colors",
                isActive
                  ? "border-primary/60 bg-primary/15 text-primary"
                  : "border-transparent bg-surface-raised/60 text-text-secondary hover:border-primary/30 hover:text-primary",
                tab.disabled && "opacity-50"
              )}
            >
              <span>{tab.label}</span>
              {tab.badge && (
                <span className="rounded-full bg-primary/20 px-2 py-0.5 text-[11px] uppercase tracking-[1.5px] text-primary">
                  {tab.badge}
                </span>
              )}
            </button>
          );
        })}
      </div>
    </div>
  );
}

function ConnectionIndicator({ state }: { state: NonNullable<TopBarState["connection"]> }) {
  const { status, label, showAdminLock, showDnd, onPress } = state;
  const tone = statusTone[status];
  const Element = onPress ? "button" : "div";
  return (
    <Element
      type={onPress ? "button" : undefined}
      onClick={onPress}
      className={cn(
        "inline-flex items-center gap-2 rounded-full border border-transparent px-3 py-1.5 text-xs font-medium uppercase tracking-[2px]",
        tone,
        onPress && "transition-colors hover:border-primary/40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/60"
      )}
    >
      <span className="inline-flex h-2 w-2 items-center justify-center">
        <span className="inline-flex h-2 w-2 rounded-full bg-current" />
      </span>
      <span>{label ?? status}</span>
      {showDnd && <Moon className="h-3.5 w-3.5" aria-label="Do not disturb" />}
      {showAdminLock && <Lock className="h-3.5 w-3.5" aria-label="Admin lock" />}
    </Element>
  );
}

import Breadcrumbs from "./breadcrumbs";

export function TopBar({ state }: TopBarProps) {
  if (state.show === false) return null;

  const hasBoard = Boolean(state.board);
  const hasSpaces = Boolean(state.spaces?.tabs?.length);
  const hasConnection = Boolean(state.connection);

  return (
    <header className="glass sticky top-0 z-40 border-b border-border/60 bg-surface/90 backdrop-blur supports-[backdrop-filter]:bg-surface/70">
      <div className="mx-auto flex w-full max-w-6xl flex-col gap-3 px-4 py-3 sm:px-6">
        <Breadcrumbs />
        <div className="flex items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            {hasBoard ? (
              <BoardPill state={state.board!} />
            ) : (
              <span className="text-sm font-semibold uppercase tracking-[3px] text-text-secondary">
                Board Rooms
              </span>
            )}
          </div>
          {hasConnection ? (
            <ConnectionIndicator state={state.connection!} />
          ) : (
            <div className="hidden items-center gap-2 text-xs uppercase tracking-[2px] text-text-tertiary sm:inline-flex">
              <Wifi className="h-4 w-4" aria-hidden />
              <span>Ready</span>
            </div>
          )}
        </div>
        {hasSpaces && <SpaceTabs state={state.spaces!} />}
      </div>
    </header>
  );
}

// Utility helper for class concatenation; colocated to avoid repeating inline logic.
function cn(...values: Array<string | undefined | null | false>) {
  return values.filter(Boolean).join(" ");
}

export default TopBar;
