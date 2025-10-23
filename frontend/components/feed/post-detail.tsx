"use client";

import { FormEvent, useState } from "react";
import { X } from "lucide-react";
import type { BoardPost, BoardReply } from "@board-app/shared";
import PostCard from "./post-card";
import { formatRelativeTime } from "../../lib/date";

type ReplyView = BoardReply & { pending?: boolean };

interface PostDetailProps {
  post: BoardPost;
  boardName?: string | null;
  distanceLabel?: string | null;
  replies: ReplyView[];
  isSubmitting?: boolean;
  isLoading?: boolean;
  error?: string | null;
  onCreateReply: (body: string) => Promise<void> | void;
  onClose: () => void;
}

export default function PostDetail({
  post,
  boardName,
  distanceLabel,
  replies,
  isSubmitting,
  isLoading,
  error: repliesError,
  onCreateReply,
  onClose
}: PostDetailProps) {
  const [draft, setDraft] = useState('');
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const trimmed = draft.trim();
    if (!trimmed) {
      setError('Reply cannot be empty.');
      return;
    }
    setError(null);
    await Promise.resolve(onCreateReply(trimmed));
    setDraft('');
  };

  return (
    <div className="fixed inset-0 z-50 flex items-end justify-center bg-black/50 backdrop-blur-sm sm:items-center">
      <button
        type="button"
        className="absolute inset-0"
        onClick={onClose}
        aria-label="Close post detail"
      />
      <div className="relative z-10 flex w-full max-w-3xl flex-col gap-4 rounded-t-3xl border border-border/70 bg-surface-raised/95 p-6 shadow-xl sm:rounded-3xl">
        <header className="flex items-start justify-between gap-4">
          <div>
            <h2 className="text-lg font-semibold text-text-primary">Thread</h2>
            <p className="text-xs uppercase tracking-[2px] text-text-tertiary">
              {replies.length > 0 ? `${replies.length} repl${replies.length === 1 ? 'y' : 'ies'}` : 'No replies yet'}
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-full border border-border/70 p-2 text-text-secondary transition hover:border-border hover:text-text-primary"
            aria-label="Close"
          >
            <X className="h-4 w-4" />
          </button>
        </header>

        <PostCard
          post={post}
          boardName={boardName}
          distanceLabel={distanceLabel}
          disabled
        />

        <section className="space-y-3 rounded-2xl border border-border/60 bg-surface p-4">
          {isLoading ? (
            <p className="text-sm text-text-tertiary">Loading replies…</p>
          ) : replies.length === 0 ? (
            <p className="text-sm text-text-secondary">
              Be the first to reply and keep the conversation going.
            </p>
          ) : (
            replies.map(reply => {
              const displayAuthor = reply.alias || reply.author || reply.pseudonym || 'Anon';
              return (
              <article
                key={reply.id}
                className={`rounded-xl border px-3 py-2 text-sm ${reply.pending ? 'border-warning/50 bg-warning/10 text-warning' : 'border-border/60 bg-surface-raised text-text-secondary'}`}
              >
                <header className="flex items-center justify-between text-xs text-text-tertiary">
                  <span className="font-semibold text-text-primary">{displayAuthor}</span>
                  <time>{formatRelativeTime(reply.createdAt)}</time>
                </header>
                <p className="mt-2 whitespace-pre-wrap text-sm text-text-secondary">{reply.body}</p>
                {reply.pending && <p className="mt-1 text-xs text-warning">Sending…</p>}
              </article>
              );
            })
          )}
        </section>

        <form onSubmit={handleSubmit} className="space-y-3 rounded-2xl border border-border/60 bg-surface p-4">
          {repliesError && <p className="text-xs text-warning">{repliesError}</p>}
          <label className="block text-xs uppercase tracking-[2px] text-text-tertiary">
            Reply
            <textarea
              value={draft}
              onChange={event => setDraft(event.target.value)}
              placeholder="Add your reply"
              className="mt-2 h-24 w-full resize-none rounded-lg border border-border/60 bg-surface-raised px-3 py-2 text-sm text-text-primary placeholder:text-text-tertiary focus:border-primary focus:outline-none focus-visible:ring-2 focus-visible:ring-primary/60"
            />
          </label>
          {error && <p className="text-xs text-danger">{error}</p>}
          <div className="flex justify-end gap-2">
            <button
              type="button"
              onClick={onClose}
              className="rounded-full border border-border/60 px-4 py-2 text-sm font-semibold text-text-secondary transition hover:border-border hover:text-text-primary"
            >
              Close
            </button>
            <button
              type="submit"
              disabled={isSubmitting || !draft.trim()}
              className="rounded-full bg-primary px-4 py-2 text-sm font-semibold text-white transition hover:bg-primary-dark disabled:cursor-not-allowed disabled:bg-border"
            >
              {isSubmitting ? 'Sending…' : 'Reply'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
