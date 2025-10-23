"use client";

import { Zap } from "lucide-react";

interface LiveBannerProps {
  connectionCount?: number;
  postsPerMinute?: number;
  onActivate?: () => void;
}

export default function LiveBanner({ connectionCount = 0, postsPerMinute, onActivate }: LiveBannerProps) {
  if (connectionCount <= 1 && (!postsPerMinute || postsPerMinute <= 0)) {
    return null;
  }

  const activityLabel = postsPerMinute ? `${Math.max(1, Math.round(postsPerMinute))} posts/min` : undefined;

  return (
    <button
      type="button"
      onClick={onActivate}
      className="flex w-full items-center justify-between rounded-2xl border border-danger/40 bg-danger/10 px-4 py-3 text-left text-danger transition hover:border-danger/60 hover:bg-danger/15 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-danger/50"
    >
      <div className="flex items-center gap-3">
        <span className="inline-flex h-10 w-10 items-center justify-center rounded-full bg-danger/20 text-danger">
          <Zap className="h-5 w-5" aria-hidden />
        </span>
        <div className="flex flex-col text-sm">
          <span className="font-semibold uppercase tracking-[2px]">Live Now</span>
          <span className="text-xs text-danger/80">
            {connectionCount} people connected{activityLabel ? ` · ${activityLabel}` : ''}
          </span>
        </div>
      </div>
      <span className="text-xs uppercase tracking-[2px]">Pin live feed →</span>
    </button>
  );
}
