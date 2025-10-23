"use client";

import type { ReactNode } from "react";

interface QuietStateProps {
  title?: string;
  subtitle?: string;
  suggestions?: Array<{ id: string; label: string; onSelect?: () => void } | string>;
  sponsored?: ReactNode;
}

export default function QuietState({
  title = "It's quiet right now…",
  subtitle = "Be the first to start a thread and spark the board.",
  suggestions = [],
  sponsored
}: QuietStateProps) {
  return (
    <div className="rounded-2xl border border-border/70 bg-surface-raised/60 p-6 text-center shadow-sm">
      <h3 className="text-lg font-semibold text-text-primary">{title}</h3>
      <p className="mt-2 text-sm text-text-secondary">{subtitle}</p>
      {suggestions.length > 0 && (
        <div className="mt-4 flex flex-wrap justify-center gap-2">
          {suggestions.map((suggestion, index) => {
            if (typeof suggestion === "string") {
              return (
                <span
                  key={`${suggestion}-${index}`}
                  className="rounded-full border border-border/60 bg-surface px-3 py-1 text-xs text-text-secondary"
                >
                  {suggestion}
                </span>
              );
            }
            return (
              <button
                key={suggestion.id}
                type="button"
                onClick={suggestion.onSelect}
                className="rounded-full border border-border/60 bg-surface px-3 py-1 text-xs text-text-secondary transition hover:border-primary/40 hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/60"
              >
                {suggestion.label}
              </button>
            );
          })}
        </div>
      )}
      {sponsored && <div className="mt-6 text-left">{sponsored}</div>}
    </div>
  );
}
