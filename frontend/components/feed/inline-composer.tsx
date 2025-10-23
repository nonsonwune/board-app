"use client";

import { MouseEvent } from "react";
import { ImageIcon, PenSquare } from "lucide-react";

interface InlineComposerProps {
  disabled?: boolean;
  onOpen?: () => void;
  identityLabel?: string | null;
  remainingCharacters?: number;
  textOnly?: boolean;
}

export default function InlineComposer({ disabled, onOpen, identityLabel, remainingCharacters = 300, textOnly }: InlineComposerProps) {
  const handleClick = (event: MouseEvent) => {
    event.preventDefault();
    if (!disabled) {
      onOpen?.();
    }
  };

  return (
    <button
      type="button"
      onClick={handleClick}
      disabled={disabled}
      className={`flex w-full items-center justify-between rounded-2xl border border-border/70 bg-surface-raised/60 px-4 py-3 text-left shadow-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/60 ${
        disabled ? 'cursor-not-allowed opacity-70' : 'transition-colors hover:border-primary/40'
      }`}
      aria-label="Open composer"
    >
      <div className="flex items-center gap-3">
        <span className="inline-flex h-10 w-10 items-center justify-center rounded-full bg-primary/15 text-primary">
          <PenSquare className="h-5 w-5" aria-hidden />
        </span>
        <div className="flex flex-col text-sm text-text-secondary">
          <span className="font-medium text-text-primary">What’s happening here?</span>
          {textOnly ? (
            <span className="text-xs text-text-tertiary">Text-only board • Images disabled</span>
          ) : identityLabel ? (
            <span className="text-xs uppercase tracking-[2px] text-text-tertiary">Posting as {identityLabel}</span>
          ) : (
            <span className="text-xs text-text-tertiary">Register an identity to post.</span>
          )}
        </div>
      </div>
      <div className="flex items-center gap-3 text-xs uppercase tracking-[2px] text-text-tertiary">
        {!textOnly && <ImageIcon className="h-4 w-4" aria-hidden />}
        <span>{Math.max(0, remainingCharacters)} / 300</span>
      </div>
    </button>
  );
}
