"use client";

import { PenSquare, Zap } from "lucide-react";
import type { FabState } from "../../context/app-chrome-context";
import type { ReactNode } from "react";

interface FloatingActionButtonProps {
  state: FabState | null;
}

export default function FloatingActionButton({ state }: FloatingActionButtonProps) {
  const visible = state?.visible ?? Boolean(state);

  if (!visible) {
    return null;
  }

  const variant = state?.variant ?? "primary";
  const isLive = variant === "live";

  return (
    <div className="pointer-events-none fixed inset-x-0 bottom-[calc(84px+env(safe-area-inset-bottom,_0px))] z-50 flex justify-center sm:bottom-[calc(100px+env(safe-area-inset-bottom,_0px))]">
      <button
        type="button"
        onClick={state?.onPress}
        disabled={state?.disabled}
        title={state?.tooltip ?? state?.label}
        className={`pointer-events-auto inline-flex items-center gap-2 rounded-full px-5 py-3 text-sm font-semibold text-text-inverse shadow-xl shadow-primary/40 transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/60 ${
          isLive
            ? "bg-danger hover:bg-danger/90"
            : "bg-primary hover:bg-primary-dark disabled:bg-text-tertiary/40"
        }`}
      >
        {renderIcon(state, isLive)}
        <span>{state?.label ?? "Post"}</span>
      </button>
    </div>
  );
}

function renderIcon(state: FabState | null, isLive: boolean): ReactNode {
  if (isLive) {
    return <Zap className="h-5 w-5" aria-hidden />;
  }
  if (state?.icon) {
    return <span className="h-5 w-5 text-current">{state.icon}</span>;
  }
  return <PenSquare className="h-5 w-5" aria-hidden />;
}
