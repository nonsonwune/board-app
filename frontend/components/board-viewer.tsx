'use client';

import Link from 'next/link';
import { FormEvent, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type {
  BoardAlias,
  BoardFeedResponse,
  BoardPost,
  BoardSummary,
  GetAliasResponse,
  RegisterIdentityResponse,
  UpsertAliasResponse,
  UpdateReactionResponse,
  ReactionAction,
  BoardSpace,
  BoardReply,
  ListRepliesResponse,
  CreateReplyResponse
} from '@board-app/shared';
import { useBoardEvents } from '../hooks/use-board-events';
import { useToast } from './toast-provider';
import { useIdentityContext } from '../context/identity-context';
import { useAppChrome } from '../context/app-chrome-context';
import InlineComposer from './feed/inline-composer';
import LiveBanner from './feed/live-banner';
import QuietState from './feed/quiet-state';
import PostCard from './feed/post-card';
import PostDetail from './feed/post-detail';
import { formatBoardDistance } from '../lib/date';
import { formatBoardName } from '../lib/board';
import BoardMap from './board-map';

const DEFAULT_SPACE_TABS = ['Home', 'Student Life', 'Events', 'Sports'];
type ReplyState = BoardReply & { pending?: boolean };

function extractErrorMessage(value: unknown): string | null {
  if (value && typeof value === 'object' && 'error' in value) {
    const { error } = value as { error?: unknown };
    return error ? String(error) : null;
  }
  return null;
}

type HttpError = Error & { status?: number; payload?: unknown };

interface BoardViewerProps {
  boardId: string;
}

type SponsoredQuietCard = {
  id: string;
  title: string;
  body: string;
  cta: string;
  href: string;
  boards?: string[];
  impressionCap?: number;
};

function loadSponsoredQuietCards(): SponsoredQuietCard[] {
  const raw = process.env.NEXT_PUBLIC_SPONSORED_QUIET_CARDS;
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw) as SponsoredQuietCard[];
    if (!Array.isArray(parsed)) {
      return [];
    }
    return parsed
      .filter(card => typeof card?.id === 'string' && card.id.trim().length > 0)
      .map(card => ({
        ...card,
        impressionCap: typeof card.impressionCap === 'number' && card.impressionCap >= 0 ? card.impressionCap : undefined,
        boards: Array.isArray(card.boards) ? card.boards.filter(board => typeof board === 'string' && board) : undefined
      }));
  } catch (error) {
    console.warn('[ui] failed to parse NEXT_PUBLIC_SPONSORED_QUIET_CARDS', error);
    return [];
  }
}

const SPONSORED_QUIET_CARDS = loadSponsoredQuietCards();
const SPONSORED_DISMISSED_STORAGE_KEY = 'boardapp:sponsoredQuiet:dismissed';
const SPONSORED_IMPRESSIONS_STORAGE_KEY = 'boardapp:sponsoredQuiet:impressions';
const MAX_POST_CHARACTERS = 300;

export default function BoardViewer({ boardId }: BoardViewerProps) {
  const [workerBaseUrl] = useState(() => process.env.NEXT_PUBLIC_WORKER_BASE_URL ?? 'http://localhost:8788');
  const {
    identity: sharedIdentity,
    setIdentity: setSharedIdentity,
    setAlias: setSharedAlias,
    getAlias,
    session,
    setSession,
    refreshSession,
    hydrated: identityHydrated
  } = useIdentityContext();
  const { setTopBar, resetTopBar, setFab, resetFab } = useAppChrome();
  const { events, status, error, lastHeartbeat } = useBoardEvents(boardId, { workerBaseUrl });
  const [boardMeta, setBoardMeta] = useState<BoardSummary | null>(null);
  const [posts, setPosts] = useState<BoardPost[]>([]);
  const [connectionCount, setConnectionCount] = useState<number>(0);
  const [backendSpaces, setBackendSpaces] = useState<BoardSpace[]>([]);
  const [feedError, setFeedError] = useState<string | null>(null);
  const [feedLoading, setFeedLoading] = useState<boolean>(true);
  const [identity, setIdentity] = useState<RegisterIdentityResponse['user'] | null>(sharedIdentity ?? null);
  const [identityError, setIdentityError] = useState<string | null>(null);
  const [identityLoading, setIdentityLoading] = useState<boolean>(false);
  const [reactionUserId, setReactionUserId] = useState('');
  const [reactionPostId, setReactionPostId] = useState('');
  const [reactionStatus, setReactionStatus] = useState<string | null>(null);
  const [reactionLoading, setReactionLoading] = useState<boolean>(false);
  const sharedAlias = getAlias(boardId);
  const [alias, setAlias] = useState<BoardAlias | null>(sharedAlias);
  const [aliasStatus, setAliasStatus] = useState<string | null>(null);
  const [aliasError, setAliasError] = useState<string | null>(null);
  const [aliasLoading, setAliasLoading] = useState<boolean>(false);
  const [aliasInput, setAliasInput] = useState(sharedAlias?.alias ?? '');
  const [composerOpen, setComposerOpen] = useState(false);
  const [composerBody, setComposerBody] = useState('');
  const [composerAuthor, setComposerAuthor] = useState('');
  const [composerSubmitting, setComposerSubmitting] = useState(false);
  const [selectedPost, setSelectedPost] = useState<BoardPost | null>(null);
  const [repliesByPostId, setRepliesByPostId] = useState<Record<string, ReplyState[]>>({});
  const [replySubmitting, setReplySubmitting] = useState(false);
  const [repliesLoading, setRepliesLoading] = useState(false);
  const [replyError, setReplyError] = useState<string | null>(null);
  const [activeSpaceId, setActiveSpaceId] = useState('home');
  const [showIdentityModal, setShowIdentityModal] = useState(false);
  const [identityModalMode, setIdentityModalMode] = useState<'register' | 'session' | 'alias'>('register');
  const [sessionRefreshing, setSessionRefreshing] = useState(false);
  const [sessionMessage, setSessionMessage] = useState<string | null>(null);
  const sessionToken = session?.token ?? null;
  const { addToast } = useToast();
  const [heartbeatTick, setHeartbeatTick] = useState(() => Date.now());
  const quietPrompts = useMemo(
    () => [
      {
        title: 'It’s quiet right now…',
        body: 'Be the first to share a campus update or plan a meetup.'
      },
        {
        title: 'Start the conversation',
        body: 'Share a study tip, a lunch meetup, or a quick shout-out to your floor.'
      },
      {
        title: 'Need inspiration?',
        body: 'Try posting about today’s events, a lost item, or a quick poll for your dorm.'
      }
    ],
    []
  );

  useEffect(() => {
    const interval = window.setInterval(() => setHeartbeatTick(Date.now()), 15000);
    return () => window.clearInterval(interval);
  }, []);
  const quietModePrompt = useMemo(() => quietPrompts[Math.floor(Math.random() * quietPrompts.length)], [quietPrompts]);
  const openComposer = useCallback(() => {
    if (!identity) {
      setIdentityModalMode('register');
      setShowIdentityModal(true);
      return;
    }
    if (!sessionToken) {
      setIdentityModalMode('session');
      setShowIdentityModal(true);
      return;
    }
    setComposerOpen(true);
  }, [identity, sessionToken]);

  const postsPerMinute = useMemo(() => {
    if (events.length === 0) return 0;
    const windowStart = Date.now() - 60_000;
    let count = 0;
    for (let i = events.length - 1; i >= 0; i -= 1) {
      const event = events[i];
      if (event.timestamp < windowStart) break;
      if (event.event === 'post.created') {
        count += 1;
      }
    }
    return count;
  }, [events]);

  const quietSuggestions = useMemo(
    () =>
      quietPrompts.map((prompt, index) => ({
        id: `prompt-${index}`,
        label: prompt.title,
        onSelect: openComposer
      })),
    [quietPrompts, openComposer]
  );

  const topicTags = useMemo(() => {
    const counts = new Map<string, number>();
    const hashtagRegex = /#[\p{L}0-9_-]+/gu;
    posts.forEach(post => {
      const matches = post.body.match(hashtagRegex);
      if (!matches) return;
      matches.forEach(tag => {
        const normalized = tag.toLowerCase();
        counts.set(normalized, (counts.get(normalized) ?? 0) + 1);
      });
    });
    return Array.from(counts.entries())
      .sort((a, b) => b[1] - a[1])
      .map(([tag]) => tag)
      .slice(0, 3);
  }, [posts]);

  const viewSpaces = useMemo(() => {
    const baseTabs = DEFAULT_SPACE_TABS.map(label => ({
      id: label.toLowerCase().replace(/\s+/g, '-'),
      label,
      type: 'default' as const
    }));

    const backendTabs = backendSpaces.map(space => ({
      id: space.id,
      label: space.label,
      type: space.type ?? 'custom',
      topic: typeof space.metadata?.topic === 'string' ? space.metadata.topic : space.label
    }));

    const dynamicTabs = topicTags
      .filter(tag => !backendTabs.some(space => space.label.toLowerCase() === tag.toLowerCase()))
      .map(tag => ({
        id: `topic-${tag.slice(1).toLowerCase()}`,
        label: tag,
        type: 'topic' as const,
        topic: tag
      }));

    const merged = [baseTabs[0], ...backendTabs, ...dynamicTabs, ...baseTabs.slice(1)];
    const seen = new Set<string>();
    return merged.filter(tab => {
      if (seen.has(tab.id)) return false;
      seen.add(tab.id);
      return true;
    });
  }, [backendSpaces, topicTags]);

  useEffect(() => {
    if (viewSpaces.length === 0) return;
    if (!viewSpaces.some(tab => tab.id === activeSpaceId)) {
      setActiveSpaceId(viewSpaces[0].id);
    }
  }, [viewSpaces, activeSpaceId]);

  const handleSpaceSelect = useCallback(
    (tabId: string) => {
      setActiveSpaceId(tabId);
      const tab = viewSpaces.find(space => space.id === tabId);
      if (tab?.type === 'topic') {
        addToast({ title: 'Topic filter active', description: `Filtering posts tagged ${tab.label}.` });
      }
    },
    [viewSpaces, addToast]
  );

  const filteredPosts = useMemo(() => {
    const activeTab = viewSpaces.find(tab => tab.id === activeSpaceId);
    if (!activeTab || activeTab.type === 'default') return posts;
    if (activeTab.type === 'topic') {
      const needle = (activeTab.topic ?? activeTab.label).toLowerCase();
      return posts.filter(post => post.body.toLowerCase().includes(needle));
    }
    if (activeTab.type === 'events') {
      return posts.filter(post => /event|meet|tonight|today|tomorrow/i.test(post.body));
    }
    return posts;
  }, [posts, viewSpaces, activeSpaceId]);

  const statusLabel = useMemo(() => {
    if (status === 'connected') return 'Live';
    if (status === 'connecting') return 'Connecting…';
    if (status === 'error') return 'Retrying…';
    return 'Offline';
  }, [status]);

  const chromeConnectionStatus = useMemo(() => {
    if (status === 'connected') return 'connected';
    if (status === 'connecting') return 'connecting';
    if (status === 'error') return 'error';
    return 'offline';
  }, [status]);

  const heartbeatAgeMs = useMemo(() => (lastHeartbeat ? heartbeatTick - lastHeartbeat : null), [lastHeartbeat, heartbeatTick]);
  const isHeartbeatStale = heartbeatAgeMs !== null && heartbeatAgeMs > 30_000;

  const remainingCharacters = MAX_POST_CHARACTERS - composerBody.length;
  const showQuietState = !feedLoading && !feedError && filteredPosts.length === 0;
  const enableDevToolsFlag = process.env.NEXT_PUBLIC_UI_DEVTOOLS === 'true';
  const showDevTools = process.env.NODE_ENV !== 'production' || enableDevToolsFlag;
  const activeReplies = selectedPost ? repliesByPostId[selectedPost.id] ?? [] : [];
  const showLiveBanner = status === 'connected' && !isHeartbeatStale && (connectionCount > 1 || postsPerMinute > 0);

  const handleComposerClose = useCallback(() => {
    if (composerSubmitting) return;
    setComposerOpen(false);
  }, [composerSubmitting]);

  async function handleComposerSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (composerSubmitting) return;
    setComposerSubmitting(true);
    const success = await createPost(composerBody, composerAuthor);
    if (success) {
      setComposerBody('');
      setComposerAuthor('');
      setComposerOpen(false);
    }
    setComposerSubmitting(false);
  }
  const [dismissedSponsored, setDismissedSponsored] = useState<Set<string>>(() => new Set());
  const [sponsoredImpressions, setSponsoredImpressions] = useState<Record<string, number>>(() => ({}));
  const lastSponsoredImpressionRef = useRef<string | null>(null);
  const [sponsoredStorageHydrated, setSponsoredStorageHydrated] = useState(false);
  const isPhaseOneBoard = boardMeta?.phaseMode === 'phase1';
  const isTextOnlyBoard = boardMeta?.textOnly ?? false;
  const radiusMetersDisplay = boardMeta?.radiusMeters ? Math.round(boardMeta.radiusMeters) : null;
  const boardDistanceLabel = boardMeta ? formatBoardDistance(boardMeta.radiusMeters) : null;
  const friendlyBoardName = useMemo(() => formatBoardName(boardId, boardMeta?.displayName), [boardId, boardMeta?.displayName]);
  const boardLatitude = boardMeta?.latitude ?? null;
  const boardLongitude = boardMeta?.longitude ?? null;

  useEffect(() => {
    const connectionStatus = isHeartbeatStale ? 'connecting' : chromeConnectionStatus;
    const connectionLabel =
      status === 'connected'
        ? isHeartbeatStale
          ? 'Reconnecting…'
          : `Live · ${connectionCount} nearby`
        : statusLabel;
    const chromeSpaceTabs = viewSpaces.map(tab => ({
      id: tab.id,
      label: tab.label,
      isActive: tab.id === activeSpaceId
    }));

    setTopBar({
      show: true,
      board: {
        name: friendlyBoardName,
        radiusLabel: boardDistanceLabel ?? undefined,
        isLive: status === 'connected'
      },
      connection: {
        status: connectionStatus,
        label: connectionLabel,
        showAdminLock: isPhaseOneBoard,
        showDnd: false,
        onPress: () => addToast({ title: connectionLabel, description: 'Realtime status updates in progress.' })
      },
      spaces: chromeSpaceTabs.length
        ? {
            tabs: chromeSpaceTabs,
            activeTabId: activeSpaceId,
            onSelect: handleSpaceSelect
          }
        : null
    });

    return () => {
      resetTopBar();
    };
  }, [friendlyBoardName, boardDistanceLabel, status, statusLabel, chromeConnectionStatus, isPhaseOneBoard, setTopBar, resetTopBar, connectionCount, viewSpaces, activeSpaceId, handleSpaceSelect, addToast, isHeartbeatStale]);

  useEffect(() => {
    const canCompose = Boolean(identity && sessionToken);
    setFab({
      label: 'Post',
      onPress: openComposer,
      disabled: !canCompose,
      tooltip: canCompose ? 'Share an update with the board' : 'Register an identity to post',
      visible: true,
      variant: status === 'connected' ? 'live' : 'primary'
    });

    return () => {
      resetFab();
    };
  }, [identity, sessionToken, status, openComposer, setFab, resetFab]);

  useEffect(() => {
    if (typeof window === 'undefined') return;
    try {
      const rawDismissed = window.localStorage.getItem(SPONSORED_DISMISSED_STORAGE_KEY);
      if (rawDismissed) {
        const parsed = JSON.parse(rawDismissed);
        if (Array.isArray(parsed)) {
          setDismissedSponsored(new Set(parsed.filter((value): value is string => typeof value === 'string' && value.length > 0)));
        }
      }
    } catch (error) {
      console.warn('[ui] failed to hydrate sponsored dismissals', error);
    }

    try {
      const rawImpressions = window.localStorage.getItem(SPONSORED_IMPRESSIONS_STORAGE_KEY);
      if (rawImpressions) {
        const parsed = JSON.parse(rawImpressions) as Record<string, number> | null;
        if (parsed && typeof parsed === 'object') {
          const normalized: Record<string, number> = {};
          for (const [key, value] of Object.entries(parsed)) {
            if (typeof value === 'number' && value >= 0) {
              normalized[key] = value;
            }
          }
          setSponsoredImpressions(normalized);
        }
      }
    } catch (error) {
      console.warn('[ui] failed to hydrate sponsored impressions', error);
    }

    setSponsoredStorageHydrated(true);
  }, []);

  useEffect(() => {
    if (typeof window === 'undefined' || !sponsoredStorageHydrated) return;
    try {
      window.localStorage.setItem(
        SPONSORED_DISMISSED_STORAGE_KEY,
        JSON.stringify(Array.from(dismissedSponsored))
      );
    } catch (error) {
      console.warn('[ui] failed to persist sponsored dismissals', error);
    }
  }, [dismissedSponsored, sponsoredStorageHydrated]);

  useEffect(() => {
    if (typeof window === 'undefined' || !sponsoredStorageHydrated) return;
    try {
      window.localStorage.setItem(SPONSORED_IMPRESSIONS_STORAGE_KEY, JSON.stringify(sponsoredImpressions));
    } catch (error) {
      console.warn('[ui] failed to persist sponsored impressions', error);
    }
  }, [sponsoredImpressions, sponsoredStorageHydrated]);

  useEffect(() => {
    setAliasStatus(null);
    setAliasError(null);
  }, [identity?.id, boardId]);

  useEffect(() => {
    if (!identityHydrated) return;
    if (sharedIdentity && sharedIdentity.id !== identity?.id) {
      setIdentity(sharedIdentity);
      setReactionUserId(sharedIdentity.id);
      return;
    }
    if (!sharedIdentity && identity) {
      setIdentity(null);
      setReactionUserId('');
    }
  }, [sharedIdentity, identity, identityHydrated]);

  useEffect(() => {
    if (!identityHydrated) return;
    if (identity?.id !== sharedIdentity?.id) {
      setSharedIdentity(identity);
    }
  }, [identity, sharedIdentity, setSharedIdentity, identityHydrated]);

  const badgeTone = useMemo(() => {
    switch (status) {
      case 'connected':
        return 'bg-emerald-500/20 text-emerald-300';
      case 'connecting':
        return 'bg-sky-500/20 text-sky-200';
      case 'error':
        return 'bg-amber-500/20 text-amber-200';
      default:
        return 'bg-slate-700/40 text-slate-300';
    }
  }, [status]);

  const sponsoredQuietCard = useMemo(() => {
    if (SPONSORED_QUIET_CARDS.length === 0) {
      return null;
    }
    return (
      SPONSORED_QUIET_CARDS.find(card => {
        if (card.boards && card.boards.length > 0 && !card.boards.includes(boardId)) {
          return false;
        }
        if (dismissedSponsored.has(card.id)) {
          return false;
        }
        const impressions = sponsoredImpressions[card.id] ?? 0;
        if (card.impressionCap !== undefined && card.impressionCap >= 0 && impressions >= card.impressionCap) {
          return false;
        }
        return true;
      }) ?? null
    );
  }, [boardId, dismissedSponsored, sponsoredImpressions]);

  useEffect(() => {
    if (!sponsoredStorageHydrated) return;
    if (!sponsoredQuietCard) {
      lastSponsoredImpressionRef.current = null;
      return;
    }
    if (lastSponsoredImpressionRef.current === sponsoredQuietCard.id) return;
    lastSponsoredImpressionRef.current = sponsoredQuietCard.id;
    setSponsoredImpressions(prev => ({
      ...prev,
      [sponsoredQuietCard.id]: (prev[sponsoredQuietCard.id] ?? 0) + 1
    }));
  }, [sponsoredQuietCard, sponsoredStorageHydrated]);

  const sortedEvents = useMemo(() => events.slice().sort((a, b) => a.timestamp - b.timestamp), [events]);

  const effectiveIdentity = identityHydrated ? identity : null;
  const buildHeaders = useCallback(
    (base: HeadersInit = {}) => {
      const headers = new Headers(base);
      if (sessionToken) {
        headers.set('Authorization', `Bearer ${sessionToken}`);
      }
      return headers;
    },
    [sessionToken]
  );
  const registerLabel = effectiveIdentity ? 'Re-register' : 'Register';

  const raiseForStatus = useCallback((res: Response, payload: unknown, fallback: string) => {
    if (res.ok) return;
    const message =
      typeof payload === 'object' && payload !== null && 'error' in payload
        ? String((payload as { error?: unknown }).error ?? '')
        : undefined;
    const error = new Error(message || fallback) as HttpError;
    error.status = res.status;
    error.payload = payload;
    throw error;
  }, []);

  const handleSponsoredDismiss = useCallback((cardId: string, cardTitle: string) => {
    setDismissedSponsored(prev => {
      const next = new Set(prev);
      next.add(cardId);
      return next;
    });
    addToast({ title: 'Card dismissed', description: `Muted ${cardTitle}.` });
  }, [addToast]);

  const handleSponsoredCtaClick = useCallback((card: SponsoredQuietCard) => {
    addToast({ title: 'Opening sponsor', description: card.title });
  }, [addToast]);

  const sponsoredQuietContent = useMemo(() => {
    if (!sponsoredQuietCard) return null;
    return (
      <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-4 text-left">
        <p className="text-sm font-semibold text-slate-200">{sponsoredQuietCard.title}</p>
        <p className="mt-2 text-xs text-slate-400">{sponsoredQuietCard.body}</p>
        <div className="mt-3 flex flex-wrap items-center gap-2">
          <a
            href={sponsoredQuietCard.href}
            target="_blank"
            rel="noopener noreferrer"
            onClick={event => {
              event.stopPropagation();
              handleSponsoredCtaClick(sponsoredQuietCard);
            }}
            className="inline-flex items-center gap-1 rounded-full bg-sky-500 px-3 py-1 text-xs font-semibold text-slate-950 transition hover:bg-sky-400"
          >
            {sponsoredQuietCard.cta}
          </a>
          <button
            type="button"
            onClick={event => {
              event.stopPropagation();
              handleSponsoredDismiss(sponsoredQuietCard.id, sponsoredQuietCard.title);
            }}
            className="inline-flex items-center gap-1 rounded-full border border-slate-700 px-3 py-1 text-xs text-slate-400 transition hover:border-slate-500 hover:text-slate-200"
          >
            Dismiss
          </button>
        </div>
      </div>
    );
  }, [sponsoredQuietCard, handleSponsoredCtaClick, handleSponsoredDismiss]);

  const handleSessionError = useCallback(
    async (error: unknown, workerBaseUrl: string, setMessage?: (msg: string) => void) => {
      const httpError = error as HttpError;
      if (httpError?.status === 401) {
        const refreshed = await refreshSession(workerBaseUrl);
        if (refreshed) {
          return 'refreshed';
        }
        setSession(null);
        const message =
          typeof httpError.payload === 'object' && httpError.payload !== null && 'error' in httpError.payload
            ? String((httpError.payload as { error?: unknown }).error ?? 'Session expired. Re-register identity.')
            : 'Session expired. Re-register identity.';
        if (setMessage) {
          setMessage(message);
        } else {
          setIdentityError(message);
        }
        return 'expired';
      }
      return 'noop';
    },
    [refreshSession, setSession, setIdentityError]
  );

  const ensureReplies = useCallback((post: BoardPost) => {
    setRepliesByPostId(prev => {
      if (prev[post.id]) return prev;
      return { ...prev, [post.id]: [] };
    });
  }, []);

  const loadReplies = useCallback(
    async (post: BoardPost) => {
      setRepliesLoading(true);
      setReplyError(null);
      try {
        const res = await fetch(
          `${workerBaseUrl}/boards/${encodeURIComponent(boardId)}/posts/${encodeURIComponent(post.id)}/replies`
        );
        const payload = (await res.json().catch(() => ({}))) as ListRepliesResponse;
        if (!res.ok || !payload?.ok) {
          const message = extractErrorMessage(payload) ?? `Failed to load replies (${res.status})`;
          throw new Error(message);
        }
        const replies = (payload.replies ?? []).map(reply => ({ ...reply, pending: false })) as ReplyState[];
        setRepliesByPostId(prev => ({ ...prev, [post.id]: replies }));
        setReplyError(null);
      } catch (error) {
        const message = (error as Error).message ?? 'Failed to load replies';
        setReplyError(message);
        addToast({ title: 'Replies unavailable', description: message });
        setRepliesByPostId(prev => ({ ...prev, [post.id]: prev[post.id] ?? [] }));
      } finally {
        setRepliesLoading(false);
      }
    },
    [workerBaseUrl, boardId, addToast]
  );

  const handleCreateReply = useCallback(
    async (post: BoardPost, message: string) => {
      const trimmed = message.trim();
      if (!trimmed) return;
      if (!identity || !sessionToken) {
        addToast({ title: 'Session required', description: 'Register or refresh your identity to reply.' });
        return;
      }

      const optimistic: ReplyState = {
        id: `local-${Date.now()}`,
        postId: post.id,
        boardId: post.boardId,
        userId: identity.id,
        author: alias?.alias || identity.pseudonym || 'You',
        alias: alias?.alias ?? null,
        pseudonym: identity.pseudonym,
        body: trimmed,
        createdAt: Date.now(),
        pending: true
      };

      let optimisticReplies: ReplyState[] = [];

      setRepliesByPostId(prev => {
        const existing = prev[post.id] ?? [];
        optimisticReplies = [...existing, optimistic];
        return { ...prev, [post.id]: optimisticReplies };
      });
      setPosts(prev =>
        prev.map(item =>
          item.id === post.id ? { ...item, replyCount: optimisticReplies.length } : item
        )
      );
      setSelectedPost(current =>
        current && current.id === post.id ? { ...current, replyCount: optimisticReplies.length } : current
      );

      setReplySubmitting(true);
      try {
        const res = await fetch(
          `${workerBaseUrl}/boards/${encodeURIComponent(boardId)}/posts/${encodeURIComponent(post.id)}/replies`,
          {
            method: 'POST',
            headers: buildHeaders({ 'content-type': 'application/json' }),
            body: JSON.stringify({ body: trimmed, userId: identity.id, author: alias?.alias ?? identity.pseudonym })
          }
        );
        const payload = (await res.json().catch(() => ({}))) as CreateReplyResponse;
        if (!res.ok || !payload?.ok) {
          const message = extractErrorMessage(payload) ?? `Failed to send reply (${res.status})`;
          throw new Error(message);
        }
        const persisted: ReplyState = { ...payload.reply, pending: false };
        setReplyError(null);
        let nextReplies: ReplyState[] = [];
        setRepliesByPostId(prev => {
          const existing = prev[post.id] ?? [];
          nextReplies = existing.map(reply => (reply.id === optimistic.id ? persisted : reply));
          return {
            ...prev,
            [post.id]: nextReplies
          };
        });
        const resolvedReplyCount = nextReplies.length;
        setPosts(prev =>
          prev.map(item => (item.id === post.id ? { ...item, replyCount: resolvedReplyCount } : item))
        );
        setSelectedPost(current =>
          current && current.id === post.id ? { ...current, replyCount: resolvedReplyCount } : current
        );
      } catch (error) {
        const message = (error as Error).message ?? 'Failed to send reply';
        addToast({ title: 'Reply failed', description: message });
        let revertedReplies: ReplyState[] = [];
        setRepliesByPostId(prev => {
          const existing = prev[post.id] ?? [];
          revertedReplies = existing.filter(reply => reply.id !== optimistic.id);
          return {
            ...prev,
            [post.id]: revertedReplies
          };
        });
        setPosts(prev =>
          prev.map(item =>
            item.id === post.id ? { ...item, replyCount: revertedReplies.length } : item
          )
        );
        setSelectedPost(current =>
          current && current.id === post.id ? { ...current, replyCount: revertedReplies.length } : current
        );
      } finally {
        setReplySubmitting(false);
      }
    },
    [alias?.alias, identity, sessionToken, workerBaseUrl, boardId, buildHeaders, addToast]
  );

  const boardAliasLookup = useMemo(() => {
    const map = new Map<string, string>();
    posts.forEach(post => {
      if (post.userId && (post.alias || post.pseudonym)) {
        map.set(post.userId, post.alias ?? post.pseudonym ?? '');
      }
    });
    return map;
  }, [posts]);

  const sendReaction = useCallback(
    async (postId: string, action: ReactionAction, overrideUserId?: string) => {
      const userId = overrideUserId?.trim() || identity?.id || reactionUserId.trim();
      if (!postId) {
        setReactionStatus('Select a post to react to.');
        return;
      }
      if (!userId) {
        const message = 'Register an identity to react to posts.';
        setReactionStatus(message);
        setIdentityModalMode('register');
        setShowIdentityModal(true);
        return;
      }
      if (!sessionToken) {
        const message = 'Session expired. Re-register identity.';
        setReactionStatus(message);
        setIdentityModalMode('session');
        setShowIdentityModal(true);
        return;
      }

      setReactionLoading(true);
      setReactionStatus(null);
      setReactionPostId(postId);

      const attempt = async () => {
        const res = await fetch(
          `${workerBaseUrl}/boards/${encodeURIComponent(boardId)}/posts/${encodeURIComponent(postId)}/reactions`,
          {
            method: 'POST',
            headers: buildHeaders({ 'content-type': 'application/json' }),
            body: JSON.stringify({ userId, action })
          }
        );

        const payload = await res.json().catch(() => ({}));
        raiseForStatus(res, payload, `Failed to update reaction (${res.status})`);

        const body = payload as UpdateReactionResponse;
        setReactionStatus(
          `Acknowledged • Post ${body.postId}: 👍 ${body.reactions.likeCount} / 👎 ${body.reactions.dislikeCount}`
        );
        setPosts(prev =>
          prev.map(post =>
            post.id === body.postId
              ? {
                  ...post,
                  reactionCount: body.reactions.total,
                  likeCount: body.reactions.likeCount,
                  dislikeCount: body.reactions.dislikeCount
                }
              : post
          )
        );
      };

      try {
        await attempt();
      } catch (error) {
        const outcome = await handleSessionError(error, workerBaseUrl, msg => setReactionStatus(msg));
        if (outcome === 'refreshed') {
          try {
            await attempt();
            return;
          } catch (retryError) {
            setReactionStatus((retryError as Error).message ?? 'Failed to send reaction');
          }
        }
        if (outcome !== 'expired') {
          setReactionStatus((error as Error).message ?? 'Failed to send reaction');
        }
      } finally {
        setReactionLoading(false);
      }
    },
    [
      identity,
      reactionUserId,
      sessionToken,
      workerBaseUrl,
      boardId,
      buildHeaders,
      raiseForStatus,
      handleSessionError,
      setReactionStatus,
      setIdentityModalMode,
      setShowIdentityModal
    ]
  );

  const fetchFeed = useCallback(
    async (signal?: AbortSignal) => {
      setFeedLoading(true);
      try {
        const res = await fetch(`${workerBaseUrl}/boards/${encodeURIComponent(boardId)}/feed?limit=20`, {
          signal
        });
        if (!res.ok) {
          throw new Error(`Failed to load feed (${res.status})`);
        }
        const body: BoardFeedResponse = await res.json();
        if (signal?.aborted) return;
        setBoardMeta(body.board ?? null);
        setPosts(body.posts ?? []);
        setSelectedPost(prev => {
          if (!prev) return prev;
          const updated = body.posts?.find(item => item.id === prev.id);
          return updated ? { ...prev, ...updated } : prev;
        });
        setConnectionCount(body.realtimeConnections ?? 0);
        setBackendSpaces(body.spaces ?? []);
        setFeedError(null);
      } catch (err) {
        if (signal?.aborted) return;
        if (err instanceof DOMException && err.name === 'AbortError') {
          return;
        }
        setFeedError((err as Error).message ?? 'Failed to load feed');
      } finally {
        if (signal?.aborted) return;
        setFeedLoading(false);
      }
    },
    [boardId, workerBaseUrl]
  );

  const createPost = useCallback(
    async (message: string, author?: string) => {
      const trimmed = message.trim();
      if (!trimmed) {
        addToast({ title: 'Message required', description: 'Enter a post before submitting.' });
        return false;
      }
      if (!identity) {
        setIdentityModalMode('register');
        setShowIdentityModal(true);
        return false;
      }
      if (!sessionToken) {
        setIdentityModalMode('session');
        setShowIdentityModal(true);
        return false;
      }

      const resolvedAuthor = author?.trim() || alias?.alias || identity.pseudonym || undefined;

      const attempt = async () => {
        const res = await fetch(`${workerBaseUrl}/boards/${encodeURIComponent(boardId)}/posts`, {
          method: 'POST',
          headers: buildHeaders({ 'content-type': 'application/json' }),
          body: JSON.stringify({ body: trimmed, author: resolvedAuthor, userId: identity.id })
        });
        const payload = await res.json().catch(() => ({}));
        raiseForStatus(res, payload, `Failed to create post (${res.status})`);
        await fetchFeed();
        addToast({ title: 'Post published', description: 'Shared with everyone on this board.' });
      };

      try {
        await attempt();
        return true;
      } catch (err) {
        const outcome = await handleSessionError(err, workerBaseUrl, msg => setIdentityError(msg));
        if (outcome === 'refreshed') {
          try {
            await attempt();
            return true;
          } catch (retryError) {
            console.error('[ui] failed to create post', retryError);
            addToast({ title: 'Post failed', description: 'See console for details.' });
          }
        } else if (outcome !== 'expired') {
          console.error('[ui] failed to create post', err);
          addToast({ title: 'Post failed', description: 'See console for details.' });
        }
      }
      return false;
    },
    [
      identity,
      sessionToken,
      alias,
      workerBaseUrl,
      boardId,
      buildHeaders,
      raiseForStatus,
      fetchFeed,
      addToast,
      handleSessionError,
      setIdentityError,
      setIdentityModalMode,
      setShowIdentityModal
    ]
  );

  const registerIdentity = useCallback(
    async (pseudonym: string) => {
      const trimmed = pseudonym.trim();
      if (!trimmed) {
        setIdentityError('Pseudonym is required.');
        return false;
      }

      setIdentityLoading(true);
      setIdentityError(null);

      try {
        const res = await fetch(`${workerBaseUrl}/identity/register`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ pseudonym: trimmed })
        });

        const payload = await res.json().catch(() => ({}));
        if (!res.ok || !payload?.user) {
          throw new Error(payload?.error ?? `Failed to register identity (${res.status})`);
        }

        const body = payload as RegisterIdentityResponse;
        setIdentity(body.user);
        setSession(body.session);
        addToast({ title: 'Identity registered', description: `Hello, ${body.user.pseudonym}!` });
        return true;
      } catch (error) {
        setIdentityError((error as Error).message ?? 'Failed to register identity');
        return false;
      } finally {
        setIdentityLoading(false);
      }
    },
    [workerBaseUrl, setIdentity, setSession, addToast, setIdentityError, setIdentityLoading]
  );

  const saveAlias = useCallback(
    async (value: string) => {
      const trimmed = value.trim();

      if (!identity) {
        setAliasError('Register an identity first.');
        setIdentityModalMode('register');
        setShowIdentityModal(true);
        return false;
      }
      if (!sessionToken) {
        setAliasError('Session expired. Re-register identity.');
        setIdentityModalMode('session');
        setShowIdentityModal(true);
        return false;
      }
      if (!trimmed) {
        setAliasError('Alias cannot be empty.');
        return false;
      }

      setAliasLoading(true);
      setAliasError(null);
      setAliasStatus(null);

      const attempt = async () => {
        const res = await fetch(`${workerBaseUrl}/boards/${encodeURIComponent(boardId)}/aliases`, {
          method: alias ? 'PUT' : 'POST',
          headers: buildHeaders({ 'content-type': 'application/json' }),
          body: JSON.stringify({ userId: identity.id, alias: trimmed })
        });

        const payload = await res.json().catch(() => ({}));
        raiseForStatus(res, payload, `Failed to update alias (${res.status})`);

        const body = payload as UpsertAliasResponse;
        setAlias(body.alias);
        setAliasInput(body.alias.alias);
        setAliasStatus(`Alias set to “${body.alias.alias}”.`);
        addToast({ title: 'Alias saved', description: `Showing as ${body.alias.alias} on this board.` });
      };

      try {
        await attempt();
        return true;
      } catch (error) {
        const outcome = await handleSessionError(error, workerBaseUrl, msg => setAliasError(msg));
        if (outcome === 'refreshed') {
          try {
            await attempt();
            return true;
          } catch (retryError) {
            setAliasError((retryError as Error).message ?? 'Failed to update alias');
          }
        } else if (outcome !== 'expired') {
          setAliasError((error as Error).message ?? 'Failed to update alias');
        }
        return false;
      } finally {
        setAliasLoading(false);
      }
    },
    [
      identity,
      sessionToken,
      alias,
      workerBaseUrl,
      boardId,
      buildHeaders,
      raiseForStatus,
      setAlias,
      addToast,
      handleSessionError,
      setAliasError,
      setAliasInput,
      setAliasStatus,
      setAliasLoading,
      setIdentityModalMode,
      setShowIdentityModal
    ]
  );

  const closeIdentityModal = useCallback(() => {
    setShowIdentityModal(false);
  }, []);

  const dismissIdentityModal = useCallback(() => {
    setIdentityError(null);
    setAliasError(null);
    setSessionMessage(null);
    closeIdentityModal();
  }, [closeIdentityModal, setAliasError, setIdentityError, setSessionMessage]);

  const refreshIdentitySession = useCallback(async () => {
    if (!identity || !session?.token) {
      setSessionMessage('Register identity again to create a new session.');
      return false;
    }

    setSessionRefreshing(true);
    setSessionMessage(null);

    try {
      const ticket = await refreshSession(workerBaseUrl);
      if (!ticket) {
        setSessionMessage('Session expired. Re-register identity.');
        setSession(null);
        return false;
      }
      setSessionMessage(`Session refreshed • expires ${new Date(ticket.expiresAt).toLocaleString()}`);
      addToast({ title: 'Session refreshed', description: 'Identity session extended.' });
      return true;
    } catch (error) {
      setSessionMessage((error as Error).message ?? 'Unable to refresh session.');
      return false;
    } finally {
      setSessionRefreshing(false);
    }
  }, [identity, session?.token, refreshSession, workerBaseUrl, setSession, addToast, setSessionMessage, setSessionRefreshing]);

  useEffect(() => {
    const controller = new AbortController();
    fetchFeed(controller.signal);
    return () => controller.abort();
  }, [fetchFeed]);

  useEffect(() => {
    if (identity) {
      setReactionUserId(identity.id);
    }
  }, [identity]);

  useEffect(() => {
    if (!identity || !sessionToken) {
      setAlias(null);
      setAliasInput('');
      return;
    }

    const identityId = identity.id;

    if (sharedAlias && sharedAlias.userId === identityId) {
      setAlias(sharedAlias);
      setAliasInput(sharedAlias.alias);
      return;
    }

    let cancelled = false;
    async function fetchAlias() {
      try {
        const res = await fetch(
          `${workerBaseUrl}/boards/${encodeURIComponent(boardId)}/aliases?userId=${encodeURIComponent(identityId)}`,
          {
            headers: buildHeaders()
          }
        );
        const body: GetAliasResponse = await res.json();
        raiseForStatus(res, body, `Failed to load alias (${res.status})`);
        if (!cancelled) {
          const nextAlias = body.alias ?? null;
          setAlias(nextAlias);
          if (!nextAlias) {
            setAliasInput('');
          }
        }
      } catch (error) {
        if (cancelled) return;
        const outcome = await handleSessionError(error, workerBaseUrl, msg => {
          setAliasError(msg);
          setAlias(null);
          setAliasInput('');
        });
        if (outcome === 'refreshed') {
          await fetchAlias();
          return;
        }
        if (outcome !== 'expired') {
          console.warn('[ui] failed to fetch alias', error);
          setAlias(null);
        }
      }
    }

    fetchAlias();

    return () => {
      cancelled = true;
    };
  }, [identity, boardId, workerBaseUrl, sharedAlias, sessionToken, buildHeaders, raiseForStatus, handleSessionError]);

  useEffect(() => {
    if (!identityHydrated) return;
    if (!identity) {
      if (sharedAlias) {
        setSharedAlias(boardId, null);
      }
      return;
    }

    if (!alias && sharedAlias) {
      setSharedAlias(boardId, null);
      return;
    }

    if (alias && (!sharedAlias || sharedAlias.id !== alias.id || sharedAlias.alias !== alias.alias)) {
      setSharedAlias(boardId, alias);
    }
  }, [alias, sharedAlias, boardId, identity, identity?.id, setSharedAlias, identityHydrated]);

  useEffect(() => {
    if (alias?.alias) {
      setAliasInput(alias.alias);
    }
  }, [alias]);

  useEffect(() => {
    if (selectedPost) {
      ensureReplies(selectedPost);
      loadReplies(selectedPost).catch(() => null);
    }
  }, [selectedPost, ensureReplies, loadReplies]);

  useEffect(() => {
    if (posts.length === 0) {
      setReactionPostId('');
      return;
    }

    if (!reactionPostId || !posts.some(post => post.id === reactionPostId)) {
      setReactionPostId(posts[0].id);
    }
  }, [posts, reactionPostId]);

  useEffect(() => {
    const latest = events.at(-1);
    if (!latest) return;
    if (latest.event === 'post.created' && latest.data) {
      const payload = latest.data as BoardPost;
      setPosts(prev => {
        const exists = prev.some(post => post.id === payload.id);
        if (exists) return prev;
        return [payload, ...prev].slice(0, 20);
      });
      return;
    }
    if (latest.event === 'post.reacted' && latest.data) {
      const payload = latest.data as {
        postId?: string;
        reactions?: { total: number; likeCount: number; dislikeCount: number };
      };
      if (!payload?.postId || !payload?.reactions) return;
      const reactions = payload.reactions;
      setPosts(prev =>
        prev.map(post => {
          if (post.id !== payload.postId) return post;
          return {
            ...post,
            reactionCount: reactions.total,
            likeCount: reactions.likeCount,
            dislikeCount: reactions.dislikeCount
          };
        })
      );
      setSelectedPost(current =>
        current && current.id === payload.postId
          ? {
              ...current,
              reactionCount: reactions.total,
              likeCount: reactions.likeCount,
              dislikeCount: reactions.dislikeCount
            }
          : current
      );
      setReactionStatus(
        `Realtime update • Post ${payload.postId}: 👍 ${reactions.likeCount} / 👎 ${reactions.dislikeCount}`
      );
    }
  }, [events]);

  async function handleRegisterIdentity(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const formData = new FormData(form);
    const pseudonym = (formData.get('pseudonym') as string)?.trim();

    const success = await registerIdentity(pseudonym ?? '');
    if (success) {
      form.reset();
    }
  }

  async function handleSendReaction(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const formData = new FormData(form);
    const action = (formData.get('reactionAction') as string)?.trim();
    const explicitUserId = (formData.get('reactionUserId') as string)?.trim();
    const userId = explicitUserId || identity?.id || reactionUserId;

    if (!reactionPostId) {
      setReactionStatus('Select a post to react to.');
      return;
    }

    if (!action) {
      setReactionStatus('Choose a reaction action.');
      return;
    }
    await sendReaction(reactionPostId, action as ReactionAction, userId);
  }

  async function handleUpsertAlias(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const formData = new FormData(form);
    const aliasValue = (formData.get('boardAlias') as string)?.trim();

    const success = await saveAlias(aliasValue ?? '');
    if (success) {
      form.reset();
    }
  }

  async function handleInject(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const formData = new FormData(form);
    const type = (formData.get('eventType') as string)?.trim() || 'note';
    const message = (formData.get('payload') as string)?.trim();

    const payload = message ? { body: message } : {};

    const attempt = async () => {
      const res = await fetch(`${workerBaseUrl}/boards/${encodeURIComponent(boardId)}/events`, {
        method: 'POST',
        headers: buildHeaders({ 'content-type': 'application/json' }),
        body: JSON.stringify({ event: type, data: payload })
      });
      const responsePayload = await res.json().catch(() => ({}));
      raiseForStatus(res, responsePayload, `Failed to send event (${res.status})`);
      form.reset();
      addToast({ title: 'Event dispatched', description: `Sent ${type} event to listeners.` });
    };

    try {
      await attempt();
    } catch (error) {
      const outcome = await handleSessionError(error, workerBaseUrl, msg => setIdentityError(msg));
      if (outcome === 'refreshed') {
        try {
          await attempt();
          return;
        } catch (retryError) {
          console.error('[ui] failed to inject event', retryError);
        }
      }
      if (outcome === 'expired') {
        addToast({ title: 'Session expired', description: 'Re-register identity to keep sending events.' });
        return;
      }
      console.error('[ui] failed to inject event', error);
      addToast({ title: 'Event dispatch failed', description: 'Check console for details.' });
    }
  }

  async function handleCreatePost(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const formData = new FormData(form);
    const body = (formData.get('postBody') as string)?.trim();
    const author = (formData.get('postAuthor') as string)?.trim();
    const success = await createPost(body ?? '', author);
    if (success) {
      form.reset();
    }
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 py-12">
      <div className="mx-auto max-w-4xl px-6">
        <header className="flex flex-col gap-3 border-b border-slate-800 pb-6">
          <div className="flex items-center gap-3 text-sm text-slate-400">
            <span className={`rounded-full px-2.5 py-1 text-xs font-semibold uppercase tracking-wide ${badgeTone}`}>
              {statusLabel}
            </span>
            <span className="text-xs uppercase tracking-[2px] text-slate-500">Board</span>
          </div>
          <h1 className="text-4xl font-semibold text-white">{boardMeta?.displayName ?? boardId}</h1>
          <p className="text-sm text-slate-400">
            Connected to <code className="rounded bg-slate-900 px-1">{workerBaseUrl}</code>{' '}
            ·{' '}
            {isPhaseOneBoard
              ? `showing posts within a fixed ${radiusMetersDisplay ?? 1500} m radius`
              : `showing posts within ${sharedAlias ? 'your saved radius' : 'an adaptive radius'}`}
          </p>
          {boardMeta?.description ? (
            <p className="text-sm text-slate-500">{boardMeta.description}</p>
          ) : (
            <p className="text-sm text-slate-500">
              Stay updated on events and drop-ins happening around this part of campus.
            </p>
          )}
          <div className="mt-2 flex flex-wrap items-center gap-3 text-xs text-slate-400">
            {effectiveIdentity ? (
              <span className="flex items-center gap-1 rounded-md border border-slate-800 bg-slate-900/60 px-2 py-1 font-medium text-slate-200">
                {effectiveIdentity.pseudonym}
                <span className="text-[10px] text-slate-500">#{effectiveIdentity.id.slice(0, 6)}</span>
              </span>
            ) : (
              <span>Register an identity to post as yourself.</span>
            )}
            {effectiveIdentity && (
              <span className="flex items-center gap-1 rounded-md border border-slate-800 bg-slate-900/60 px-2 py-1 text-slate-300">
                Alias: <strong className="text-slate-100">{alias?.alias ?? boardAliasLookup.get(effectiveIdentity.id) ?? '—'}</strong>
              </span>
            )}
            {effectiveIdentity && (
              <button
                type="button"
                onClick={() => {
                  setIdentityModalMode('alias');
                  setShowIdentityModal(true);
                }}
                className="rounded-md border border-slate-700 px-2 py-1 text-[11px] uppercase tracking-[2px] text-slate-300 transition hover:border-sky-500 hover:text-sky-300"
              >
                Edit alias
              </button>
            )}
            <Link
              href="/profile"
              className="rounded-md border border-slate-700 px-2 py-1 text-[11px] uppercase tracking-[2px] text-slate-300 transition hover:border-sky-500 hover:text-sky-300"
            >
              Manage Identity →
            </Link>
          </div>
        </header>

        {(isPhaseOneBoard || isTextOnlyBoard) && (
          <div className="mt-6 rounded-lg border border-sky-500/40 bg-sky-500/10 p-4 text-sm text-sky-100">
            {isPhaseOneBoard && (
              <p>
                Phase 1 launch mode active. Radius locked to {radiusMetersDisplay ?? 1500} m for consistent dorm coverage.
              </p>
            )}
            {isTextOnlyBoard && (
              <p className="mt-2">
                Posts are limited to text while we tune onboarding. Images will return in the next phase.
              </p>
            )}
          </div>
        )}

        {boardLatitude !== null && boardLongitude !== null ? (
          <section className="mt-8 space-y-3">
            <h2 className="text-sm font-semibold uppercase tracking-[2px] text-text-tertiary">Board coverage map</h2>
            <BoardMap latitude={boardLatitude} longitude={boardLongitude} radiusMeters={boardMeta?.radiusMeters ?? null} />
          </section>
        ) : null}

        {error && (
          <div className="mt-6 rounded-lg border border-rose-500/40 bg-rose-500/10 p-4 text-sm text-rose-200">
            {error}
          </div>
        )}

        <section className="mt-10">
          {showDevTools && (
            <>
          <form onSubmit={handleRegisterIdentity} className="mb-8 rounded-xl border border-slate-800 bg-slate-900/40 p-4 shadow-sm shadow-slate-950/30">
            <h2 className="text-sm font-semibold uppercase tracking-[3px] text-slate-400">Register Identity</h2>
            <p className="mt-2 text-xs text-slate-500">
              Identities map to pseudonyms used across boards. Reactions require a user ID.
            </p>
            <div className="mt-4 flex flex-wrap items-end gap-4">
              <label className="flex flex-1 min-w-[220px] flex-col gap-2 text-xs uppercase tracking-[2px] text-slate-500">
                Pseudonym
                <input
                  name="pseudonym"
                  placeholder="e.g. CampusScout"
                  className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-sky-500 focus:outline-none"
                  required
                />
              </label>
              <button
                type="submit"
                disabled={identityLoading}
                className="rounded-md bg-sky-500 px-4 py-2 text-sm font-semibold text-slate-950 transition hover:bg-sky-400 disabled:cursor-not-allowed disabled:bg-slate-700 disabled:text-slate-400"
              >
                {identityLoading ? 'Registering…' : registerLabel}
              </button>
            </div>
            {effectiveIdentity && (
              <div className="mt-3 rounded-md border border-slate-800 bg-slate-900/60 p-3 text-xs text-slate-400">
                <p>
                  Active identity:{' '}
                  <span className="font-semibold text-slate-200">{effectiveIdentity.pseudonym}</span>{' '}
                  <code className="ml-1 rounded bg-slate-950 px-2 py-1 text-[11px] text-slate-300">{effectiveIdentity.id}</code>
                </p>
                {alias && (
                  <p className="mt-2 text-[11px] text-slate-500">
                    Board alias: <span className="font-semibold text-slate-200">{alias.alias}</span>
                  </p>
                )}
                <Link
                  href="/profile"
                  className="mt-2 inline-flex items-center gap-1 text-[11px] uppercase tracking-[2px] text-sky-300 transition hover:text-sky-100"
                >
                  Manage identity & sessions →
                </Link>
              </div>
            )}
            {effectiveIdentity && !sessionToken && (
              <div className="mt-3 rounded-md border border-amber-500/30 bg-amber-500/10 p-3 text-xs text-amber-200">
                <p>Your session expired. Re-link your Access identity to continue posting.</p>
                <Link
                  href="/profile"
                  className="mt-2 inline-flex items-center gap-1 text-[11px] uppercase tracking-[2px] text-amber-200 underline-offset-4 hover:text-amber-100 hover:underline"
                >
                  Re-link session →
                </Link>
              </div>
            )}
            {identityError && (
              <p className="mt-3 rounded-md border border-rose-500/40 bg-rose-500/10 p-3 text-xs text-rose-200">{identityError}</p>
            )}
          </form>

          <form
            onSubmit={handleUpsertAlias}
            className="mb-8 rounded-xl border border-slate-800 bg-slate-900/40 p-4 shadow-sm shadow-slate-950/30"
          >
            <h2 className="text-sm font-semibold uppercase tracking-[3px] text-slate-400">Set Board Alias</h2>
            <p className="mt-2 text-xs text-slate-500">
              Aliases display only within this board. They override your global pseudonym.
            </p>
            <div className="mt-4 flex flex-wrap items-end gap-4">
              <label className="flex flex-1 min-w-[220px] flex-col gap-2 text-xs uppercase tracking-[2px] text-slate-500">
                Alias
                <input
                  name="boardAlias"
                  value={aliasInput}
                  onChange={event => {
                    setAliasInput(event.target.value);
                    setAliasStatus(null);
                    setAliasError(null);
                  }}
                  placeholder="e.g. LibraryLookout"
                  className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-sky-500 focus:outline-none"
                  disabled={!identity}
                />
              </label>
              <button
                type="submit"
                disabled={!identity || aliasLoading}
                className="rounded-md bg-emerald-500 px-4 py-2 text-sm font-semibold text-slate-950 transition hover:bg-emerald-400 disabled:cursor-not-allowed disabled:bg-slate-700 disabled:text-slate-400"
              >
                {!identity ? 'Register identity first' : aliasLoading ? 'Saving…' : alias ? 'Update Alias' : 'Save Alias'}
              </button>
            </div>
            {alias && (
              <p className="mt-3 rounded-md border border-slate-800 bg-slate-900/60 p-3 text-xs text-slate-400">
                Current alias: <span className="font-semibold text-slate-200">{alias.alias}</span>
                {alias.aliasNormalized && (
                  <code className="ml-2 rounded bg-slate-950 px-2 py-1 text-[11px] text-slate-300">{alias.aliasNormalized}</code>
                )}
              </p>
            )}
            {aliasStatus && (
              <p className="mt-3 rounded-md border border-slate-800 bg-slate-900/60 p-3 text-xs text-emerald-300/80">{aliasStatus}</p>
            )}
            {aliasError && (
              <p className="mt-3 rounded-md border border-rose-500/40 bg-rose-500/10 p-3 text-xs text-rose-200">{aliasError}</p>
            )}
          </form>

          <form onSubmit={handleCreatePost} className="mb-8 rounded-xl border border-slate-800 bg-slate-900/40 p-4 shadow-sm shadow-slate-950/30">
            <h2 className="text-sm font-semibold uppercase tracking-[3px] text-slate-400">Create Test Post</h2>
            <div className="mt-4 flex flex-wrap gap-4">
              <label className="flex min-w-[140px] flex-col gap-2 text-xs uppercase tracking-[2px] text-slate-500">
                Author (optional)
                <input
                  name="postAuthor"
                  placeholder="Anon"
                  className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-sky-500 focus:outline-none"
                />
              </label>
              {sessionToken ? (
                <>
                  <label className="flex flex-1 min-w-[220px] flex-col gap-2 text-xs uppercase tracking-[2px] text-slate-500">
                    Message
                    <input
                      name="postBody"
                      placeholder="Share an update"
                      className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-sky-500 focus:outline-none"
                      required
                    />
                  </label>
                  <button
                    type="submit"
                    className="self-end rounded-md bg-emerald-500 px-4 py-2 text-sm font-semibold text-slate-950 transition hover:bg-emerald-400"
                  >
                    Post
                  </button>
                </>
              ) : (
                <div className="flex flex-1 items-center justify-between rounded-md border border-dashed border-slate-800 bg-slate-900/40 px-4 py-3 text-xs text-slate-400">
                  <span>Session expired. Re-register identity to post.</span>
                  <Link
                    href="/profile"
                    className="rounded-md border border-slate-700 px-2 py-1 text-[11px] uppercase tracking-[2px] text-slate-300 transition hover:border-sky-500 hover:text-sky-300"
                  >
                    Manage Session
                  </Link>
                </div>
              )}
            </div>
          </form>

          </>
          )}

          <section className="mt-10 space-y-4">
            <InlineComposer
              disabled={!identity || !sessionToken}
              onOpen={openComposer}
              identityLabel={alias?.alias ?? identity?.pseudonym ?? null}
              remainingCharacters={MAX_POST_CHARACTERS}
              textOnly={isTextOnlyBoard}
            />
            {showLiveBanner && (
              <LiveBanner
                connectionCount={connectionCount}
                postsPerMinute={postsPerMinute}
                onActivate={() =>
                  addToast({
                    title: 'Live pin coming soon',
                    description: 'Live pinning will land in a future milestone.'
                  })
                }
              />
            )}
            {feedError && (
              <div className="rounded-2xl border border-amber-500/40 bg-amber-500/10 p-3 text-sm text-amber-200">
                {feedError}
              </div>
            )}
            {feedLoading && !feedError && (
              <div className="space-y-3">
                {[0, 1, 2].map(index => (
                  <div key={index} className="h-32 rounded-2xl border border-slate-800 bg-slate-900/40 animate-pulse" />
                ))}
              </div>
            )}
            {!feedLoading && effectiveIdentity && !sessionToken && (
              <div className="rounded-2xl border border-amber-500/30 bg-amber-500/10 p-4 text-xs text-amber-200">
                <p>Your session expired. Re-link your Access identity to continue participating.</p>
                <Link
                  href="/profile"
                  className="mt-2 inline-flex items-center gap-1 text-[11px] uppercase tracking-[2px] text-amber-200 underline-offset-4 hover:text-amber-100 hover:underline"
                >
                  Re-link session →
                </Link>
              </div>
            )}
            {!feedLoading && !feedError && filteredPosts.map(post => (
              <PostCard
                key={post.id}
                post={post}
                boardName={friendlyBoardName}
                distanceLabel={boardDistanceLabel}
                isHot={typeof post.hotRank === 'number' && post.hotRank <= 120}
                onLike={() => sendReaction(post.id, 'like')}
                onDislike={() => sendReaction(post.id, 'dislike')}
                onReply={() => {
                  ensureReplies(post);
                  setSelectedPost(post);
                }}
                onShare={() => {
                  const shareUrl = `${workerBaseUrl}/boards/${boardId}/posts/${post.id}`;
                  navigator.clipboard
                    ?.writeText(shareUrl)
                    .then(() => addToast({ title: 'Link copied', description: 'Share it with your board.' }))
                    .catch(() => addToast({ title: 'Unable to copy', description: 'Copy manually for now.' }));
                }}
                onMore={() =>
                  addToast({
                    title: 'More actions coming soon',
                    description: 'Flag, mute, and block arrive shortly.'
                  })
                }
                onOpen={() => {
                  ensureReplies(post);
                  setSelectedPost(post);
                }}
              />
            ))}
            {showQuietState && (
              <QuietState
                title={quietModePrompt?.title}
                subtitle={quietModePrompt?.body}
                suggestions={quietSuggestions}
                sponsored={sponsoredQuietContent}
              />
            )}
          </section>

          {showDevTools && (
            <>
          <form onSubmit={handleSendReaction} className="mt-8 mb-8 rounded-xl border border-slate-800 bg-slate-900/40 p-4 shadow-sm shadow-slate-950/30">
            <h2 className="text-sm font-semibold uppercase tracking-[3px] text-slate-400">Send Test Reaction</h2>
            <div className="mt-4 grid gap-4 sm:grid-cols-3">
              <label className="flex flex-col gap-2 text-xs uppercase tracking-[2px] text-slate-500">
                Post
                <select
                  name="reactionPostId"
                  value={reactionPostId}
                  onChange={event => setReactionPostId(event.target.value)}
                  className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-sky-500 focus:outline-none"
                  disabled={posts.length === 0}
                >
                  {posts.map(post => (
                    <option key={post.id} value={post.id}>
                      {post.body.slice(0, 40)}
                      {post.body.length > 40 ? '…' : ''}
                    </option>
                  ))}
                  {posts.length === 0 && <option value="">No posts</option>}
                </select>
              </label>
              <label className="flex flex-col gap-2 text-xs uppercase tracking-[2px] text-slate-500">
                User ID
                <input
                  name="reactionUserId"
                  value={reactionUserId}
                  onChange={event => setReactionUserId(event.target.value)}
                  placeholder="Copy from identity"
                  className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-sky-500 focus:outline-none"
                  required
                />
              </label>
              <label className="flex flex-col gap-2 text-xs uppercase tracking-[2px] text-slate-500">
                Action
                <select
                  name="reactionAction"
                  className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-sky-500 focus:outline-none"
                  defaultValue="like"
                >
                  <option value="like">Like</option>
                  <option value="dislike">Dislike</option>
                  <option value="remove">Remove</option>
                </select>
              </label>
            </div>
            <div className="mt-4 flex flex-wrap items-center justify-between gap-3">
              <button
                type="submit"
                disabled={reactionLoading || !reactionPostId}
                className="rounded-md bg-emerald-500 px-4 py-2 text-sm font-semibold text-slate-950 transition hover:bg-emerald-400 disabled:cursor-not-allowed disabled:bg-slate-700 disabled:text-slate-400"
              >
                {reactionLoading ? 'Sending…' : 'Send Reaction'}
              </button>
              {reactionStatus && (
                <p className="text-xs text-slate-400">{reactionStatus}</p>
              )}
            </div>
          </form>

          <form onSubmit={handleInject} className="mb-8 rounded-xl border border-slate-800 bg-slate-900/40 p-4 shadow-sm shadow-slate-950/30">
            <h2 className="text-sm font-semibold uppercase tracking-[3px] text-slate-400">Inject Test Event</h2>
            <div className="mt-4 flex flex-wrap gap-4">
              <label className="flex flex-1 min-w-[160px] flex-col gap-2 text-xs uppercase tracking-[2px] text-slate-500">
                Event Type
                <input
                  name="eventType"
                  defaultValue="note"
                  className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-sky-500 focus:outline-none"
                />
              </label>
              <label className="flex flex-[2] min-w-[200px] flex-col gap-2 text-xs uppercase tracking-[2px] text-slate-500">
                Message
                <input
                  name="payload"
                  placeholder="Hello from the UI"
                  className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-sky-500 focus:outline-none"
                />
              </label>
              <button
                type="submit"
                className="self-end rounded-md bg-sky-500 px-4 py-2 text-sm font-semibold text-slate-950 transition hover:bg-sky-400"
              >
                Broadcast
              </button>
            </div>
          </form>

          <h2 className="text-lg font-semibold text-slate-200">Event Stream</h2>
          <p className="text-xs text-slate-500">Newest events at the bottom.</p>

          <div className="mt-4 space-y-4">
            {sortedEvents.map(event => (
              <article
                key={event.id}
                className="rounded-xl border border-slate-800 bg-slate-900/40 p-4 shadow-sm shadow-slate-950/20"
              >
                <header className="flex flex-wrap items-center justify-between gap-3 text-xs text-slate-500">
                  <span className="font-mono text-sky-200">{event.traceId}</span>
                  <time className="font-medium text-slate-300">
                    {new Date(event.timestamp).toLocaleTimeString()}
                  </time>
                </header>
                <div className="mt-3">
                  <span className="inline-flex items-center gap-2 rounded-full bg-sky-500/10 px-3 py-1 text-xs font-semibold uppercase tracking-wide text-sky-300">
                    {event.event}
                  </span>
                </div>
                <pre className="mt-3 overflow-x-auto rounded-lg bg-slate-950/70 p-3 text-xs text-slate-200">
                  {JSON.stringify(event.data, null, 2)}
                </pre>
              </article>
            ))}

            {sortedEvents.length === 0 && (
              <div className="rounded-xl border border-dashed border-slate-800 bg-slate-900/30 p-8 text-center text-sm text-slate-500">
                Waiting for events… use the smoke test or POST to <code className="bg-slate-900 px-1">/boards/{boardId}/events</code> to
                simulate activity.
              </div>
            )}
          </div>
          </>
          )}
        </section>
      </div>
      {showIdentityModal && (
        <IdentityOnboardingModal
          mode={identityModalMode}
          loading={identityLoading}
          aliasLoading={aliasLoading}
          identityError={identityError}
          aliasError={aliasError}
          defaultAlias={aliasInput}
          sessionMessage={sessionMessage}
          sessionRefreshing={sessionRefreshing}
          onClose={dismissIdentityModal}
          onRegister={async (pseudonym, aliasValue) => {
            const success = await registerIdentity(pseudonym);
            if (!success) {
              return false;
            }
            if (aliasValue && aliasValue.trim()) {
              const aliasSaved = await saveAlias(aliasValue);
              if (!aliasSaved) {
                return false;
              }
            }
            dismissIdentityModal();
            return true;
          }}
          onSaveAlias={async aliasValue => {
            const aliasSaved = await saveAlias(aliasValue);
            if (aliasSaved) {
              dismissIdentityModal();
              return true;
            }
            return false;
          }}
          onRefreshSession={async () => {
            const result = await refreshIdentitySession();
            if (result) {
              dismissIdentityModal();
            }
            return result;
          }}
        />
      )}
      {composerOpen && (
        <div className="fixed inset-0 z-50 flex items-end justify-center bg-black/40 backdrop-blur-sm sm:items-center">
          <button
            type="button"
            className="absolute inset-0"
            onClick={handleComposerClose}
            aria-label="Close composer"
          />
          <div className="relative z-10 w-full max-w-lg rounded-t-3xl border border-slate-800 bg-slate-900 p-6 shadow-xl sm:rounded-3xl">
            <form onSubmit={handleComposerSubmit} className="space-y-4">
              <header>
                <p className="text-xs uppercase tracking-[2px] text-slate-500">Post to {friendlyBoardName}</p>
                <h3 className="mt-1 text-lg font-semibold text-slate-100">What’s happening here?</h3>
              </header>
              {isTextOnlyBoard && (
                <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-100">
                  Images are disabled for this board. Share a quick text update to reach your neighbors.
                </div>
              )}
              <textarea
                value={composerBody}
                onChange={event => setComposerBody(event.target.value.slice(0, MAX_POST_CHARACTERS))}
                placeholder="Share a quick update or ask a question."
                className="h-32 w-full resize-none rounded-xl border border-slate-800 bg-slate-950 px-3 py-2 text-base text-slate-100 placeholder:text-slate-500 focus:border-sky-500 focus:outline-none"
              />
              <div className="flex flex-wrap items-center justify-between gap-3 text-xs text-slate-400">
                <span>{Math.max(0, remainingCharacters)} characters remaining</span>
                <label className="flex items-center gap-2">
                  <span className="text-slate-500">Post as</span>
                  <input
                    value={composerAuthor}
                    onChange={event => setComposerAuthor(event.target.value)}
                    placeholder={alias?.alias ?? identity?.pseudonym ?? 'Anonymous'}
                    className="rounded-lg border border-slate-800 bg-slate-950 px-3 py-1 text-sm text-slate-100 placeholder:text-slate-500 focus:border-sky-500 focus:outline-none"
                  />
                </label>
              </div>
              <div className="flex justify-end gap-3">
                <button
                  type="button"
                  onClick={handleComposerClose}
                  className="rounded-md border border-slate-700 px-4 py-2 text-sm font-semibold text-slate-300 transition hover:border-slate-500 hover:text-slate-100"
                  disabled={composerSubmitting}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={composerSubmitting || !composerBody.trim()}
                  className="rounded-md bg-sky-500 px-4 py-2 text-sm font-semibold text-slate-950 transition hover:bg-sky-400 disabled:cursor-not-allowed disabled:bg-slate-700 disabled:text-slate-400"
                >
                  {composerSubmitting ? 'Posting…' : 'Post'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
      {selectedPost && (
        <PostDetail
          post={selectedPost}
          boardName={friendlyBoardName}
          distanceLabel={boardDistanceLabel}
          replies={activeReplies}
          isSubmitting={replySubmitting}
          isLoading={repliesLoading}
          error={replyError}
          onCreateReply={body => handleCreateReply(selectedPost, body)}
          onClose={() => setSelectedPost(null)}
        />
      )}
    </div>
  );
}

interface IdentityOnboardingModalProps {
  mode: 'register' | 'session' | 'alias';
  loading: boolean;
  aliasLoading: boolean;
  identityError: string | null;
  aliasError: string | null;
  defaultAlias?: string | null;
  sessionMessage: string | null;
  sessionRefreshing: boolean;
  onRegister: (pseudonym: string, alias?: string) => Promise<boolean>;
  onSaveAlias: (alias: string) => Promise<boolean>;
  onRefreshSession: () => Promise<boolean>;
  onClose: () => void;
}

function IdentityOnboardingModal({
  mode,
  loading,
  aliasLoading,
  identityError,
  aliasError,
  defaultAlias,
  sessionMessage,
  sessionRefreshing,
  onRegister,
  onSaveAlias,
  onRefreshSession,
  onClose
}: IdentityOnboardingModalProps) {
  const [pseudonym, setPseudonym] = useState('');
  const [aliasValue, setAliasValue] = useState(defaultAlias ?? '');
  const [touched, setTouched] = useState(false);

  useEffect(() => {
    setPseudonym('');
    setTouched(false);
  }, [mode]);

  useEffect(() => {
    setAliasValue(defaultAlias ?? '');
  }, [defaultAlias, mode]);

  const showPseudonymField = mode === 'register';
  const showAliasField = mode === 'register' || mode === 'alias';

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setTouched(true);
    if (mode === 'register') {
      if (!pseudonym.trim()) {
        return;
      }
      await onRegister(pseudonym, aliasValue);
      return;
    }
    if (mode === 'alias') {
      if (!aliasValue.trim()) {
        return;
      }
      await onSaveAlias(aliasValue);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm px-4">
      <button type="button" className="absolute inset-0" onClick={onClose} aria-label="Close identity modal" />
      <div className="relative z-10 w-full max-w-md rounded-3xl border border-slate-800 bg-slate-950 p-6 text-slate-100 shadow-xl">
        <header className="mb-4 space-y-1">
          <h2 className="text-lg font-semibold">
            {mode === 'register'
              ? 'Create your campus identity'
              : mode === 'alias'
                ? 'Set your board alias'
                : 'Refresh your posting session'}
          </h2>
          <p className="text-sm text-slate-400">
            {mode === 'register'
              ? 'Pick a pseudonym students will see across boards. You can add a board-specific alias now or later.'
              : mode === 'alias'
                ? 'Update how neighbors see you on this board. Aliases stay local and override your global pseudonym.'
                : 'Your session expired. Refresh to keep posting and reacting without losing progress.'}
          </p>
        </header>

        {mode === 'register' || mode === 'alias' ? (
          <form onSubmit={handleSubmit} className="space-y-4">
            {showPseudonymField && (
              <label className="flex flex-col gap-2 text-xs uppercase tracking-[2px] text-slate-500">
                Pseudonym
                <input
                  value={pseudonym}
                  onChange={event => setPseudonym(event.target.value)}
                  placeholder="e.g. CampusScout"
                  className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 focus:border-sky-500 focus:outline-none"
                  autoFocus
                />
              </label>
            )}
            {showPseudonymField && touched && !pseudonym.trim() && (
              <p className="text-xs text-rose-300">Pseudonym is required.</p>
            )}
            {showAliasField && (
              <label className="flex flex-col gap-2 text-xs uppercase tracking-[2px] text-slate-500">
                Board alias (optional)
                <input
                  value={aliasValue}
                  onChange={event => setAliasValue(event.target.value)}
                  placeholder="LibraryLookout"
                  className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 focus:border-sky-500 focus:outline-none"
                  autoFocus={mode === 'alias'}
                />
              </label>
            )}
            {mode === 'alias' && touched && !aliasValue.trim() && (
              <p className="text-xs text-rose-300">Alias cannot be empty.</p>
            )}
            {mode === 'register' && identityError && <p className="text-xs text-rose-300">{identityError}</p>}
            {aliasError && <p className="text-xs text-rose-300">{aliasError}</p>}
            <div className="flex items-center justify-end gap-3">
              <button
                type="button"
                onClick={onClose}
                className="rounded-full border border-slate-700 px-4 py-2 text-sm font-semibold text-slate-300 transition hover:border-slate-500 hover:text-slate-100"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled=
                  {mode === 'register'
                    ? loading || (!pseudonym.trim() && touched)
                    : aliasLoading || (mode === 'alias' && touched && !aliasValue.trim())}
                className="rounded-full bg-sky-500 px-5 py-2 text-sm font-semibold text-slate-950 transition hover:bg-sky-400 disabled:cursor-not-allowed disabled:bg-slate-700 disabled:text-slate-400"
              >
                {loading || aliasLoading ? 'Saving…' : mode === 'alias' ? 'Save alias' : 'Continue'}
              </button>
            </div>
          </form>
        ) : (
          <div className="space-y-4">
            {sessionMessage && <p className="rounded-md border border-slate-800 bg-slate-900/70 p-3 text-xs text-slate-300">{sessionMessage}</p>}
            <div className="flex items-center justify-end gap-3">
              <button
                type="button"
                onClick={onClose}
                className="rounded-full border border-slate-700 px-4 py-2 text-sm font-semibold text-slate-300 transition hover:border-slate-500 hover:text-slate-100"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={onRefreshSession}
                disabled={sessionRefreshing}
                className="rounded-full bg-sky-500 px-5 py-2 text-sm font-semibold text-slate-950 transition hover:bg-sky-400 disabled:cursor-not-allowed disabled:bg-slate-700 disabled:text-slate-400"
              >
                {sessionRefreshing ? 'Refreshing…' : 'Refresh session'}
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
