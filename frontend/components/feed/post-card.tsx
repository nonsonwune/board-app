"use client";

import Image from "next/image";
import { memo, type ComponentType, type MouseEvent } from "react";
import { MessageCircle, MoreHorizontal, Share2, ThumbsDown, ThumbsUp } from "lucide-react";
import type { BoardPost } from "@board-app/shared";
import { formatRelativeTime } from "../../lib/date";

export interface PostCardProps {
  post: BoardPost;
  boardName?: string | null;
  distanceLabel?: string | null;
  isHot?: boolean;
  topContributor?: boolean;
  onOpen?: (post: BoardPost) => void;
  onLike?: (post: BoardPost) => void;
  onDislike?: (post: BoardPost) => void;
  onReply?: (post: BoardPost) => void;
  onShare?: (post: BoardPost) => void;
  onMore?: (post: BoardPost) => void;
  disabled?: boolean;
  disabledReason?: string;
}

function PostCardComponent({
  post,
  boardName,
  distanceLabel,
  isHot,
  topContributor,
  onOpen,
  onLike,
  onDislike,
  onReply,
  onShare,
  onMore,
  disabled,
  disabledReason
}: PostCardProps) {
  const createdLabel = formatRelativeTime(post.createdAt);
  const displayName = post.alias?.trim() || post.pseudonym?.trim() || "Anonymous";
  const boardLabel = boardName
    ? distanceLabel
      ? `${boardName}${distanceLabel ? ` · ${distanceLabel}` : ""}`
      : `From: ${boardName}`
    : undefined;
  const replyCount = typeof post.replyCount === "number"
    ? post.replyCount
    : Math.max(0, post.reactionCount - (post.likeCount + post.dislikeCount));
  const showHeatBar = Boolean(isHot || typeof post.hotRank === "number");

  const className = disabled
    ? "cursor-not-allowed opacity-70"
    : "transition-colors hover:border-primary/40 hover:bg-surface-raised";

  const handleCardClick = () => {
    if (disabled) return;
    onOpen?.(post);
  };

  const handleAction = (handler?: (post: BoardPost) => void) => (event: MouseEvent) => {
    event.stopPropagation();
    if (!disabled) {
      handler?.(post);
    }
  };

  return (
    <article
      role="listitem"
      onClick={handleCardClick}
      className={`group relative rounded-2xl border border-border/70 bg-surface-raised/80 p-5 shadow-sm ${className}`}
    >
      <header className="flex flex-wrap items-start justify-between gap-4">
        <div className="flex flex-col gap-1">
          <div className="flex items-center gap-2 text-sm font-semibold text-text-primary">
            <span>{displayName}</span>
            {topContributor && (
              <span className="inline-flex items-center gap-1 rounded-full bg-primary/15 px-2 py-0.5 text-[11px] uppercase tracking-[1.5px] text-primary">
                🏆 Top
              </span>
            )}
          </div>
          <div className="flex flex-wrap items-center gap-2 text-xs uppercase tracking-[2px] text-text-tertiary">
            <span>{createdLabel}</span>
            {boardLabel && <span>• {boardLabel}</span>}
          </div>
        </div>
        <button
          type="button"
          onClick={handleAction(onMore)}
          className="rounded-full border border-transparent p-2 text-text-tertiary transition-colors hover:border-border/70 hover:text-text-secondary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/60"
          aria-label="More actions"
        >
          <MoreHorizontal className="h-5 w-5" />
        </button>
      </header>

      {showHeatBar && (
        <div className="mt-4 h-1.5 overflow-hidden rounded-full bg-border">
          <div className="h-full w-full rounded-full bg-gradient-to-r from-color-accent-heat-start to-color-accent-heat-end opacity-80" />
        </div>
      )}

      <div className="mt-4 whitespace-pre-wrap text-base text-text-primary">
        {post.body}
      </div>

      {post.images?.length ? (
        <div className="mt-4 grid gap-2" style={{ gridTemplateColumns: `repeat(${Math.min(post.images.length, 2)}, minmax(0, 1fr))` }}>
          {post.images.map(image => (
            <div key={image} className="relative overflow-hidden rounded-xl border border-border/70 bg-surface">
              <Image
                src={image}
                alt="Post attachment"
                width={400}
                height={160}
                className="h-40 w-full object-cover"
                loading="lazy"
                unoptimized
              />
            </div>
          ))}
        </div>
      ) : null}

      <footer className="mt-5 flex items-center gap-4 text-sm text-text-secondary">
        <ActionButton
          icon={ThumbsUp}
          label="Like"
          count={post.likeCount}
          onClick={handleAction(onLike)}
          disabled={disabled}
        />
        <ActionButton
          icon={ThumbsDown}
          label="Dislike"
          count={post.dislikeCount}
          onClick={handleAction(onDislike)}
          disabled={disabled}
        />
        <ActionButton
          icon={MessageCircle}
          label="Reply"
          count={replyCount}
          onClick={handleAction(onReply)}
          disabled={disabled}
        />
        <ActionButton
          icon={Share2}
          label="Share"
          onClick={handleAction(onShare)}
          disabled={disabled}
        />
      </footer>
      {disabled && disabledReason ? (
        <p className="mt-2 text-xs uppercase tracking-[1.5px] text-text-tertiary">
          {disabledReason}
        </p>
      ) : null}
    </article>
  );
}

interface ActionButtonProps {
  icon: ComponentType<{ className?: string }>;
  label: string;
  count?: number;
  onClick?: (event: MouseEvent) => void;
  disabled?: boolean;
}

function ActionButton({ icon: Icon, label, count, onClick, disabled }: ActionButtonProps) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className="inline-flex items-center gap-1 rounded-full px-2 py-1 text-sm font-medium transition-colors hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/60 disabled:cursor-not-allowed disabled:text-text-tertiary"
      aria-label={label}
    >
      <Icon className="h-4 w-4" aria-hidden />
      <span>{count ?? 0}</span>
    </button>
  );
}

export const PostCard = memo(PostCardComponent);

export default PostCard;
