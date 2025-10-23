export interface BoardSummary {
  id: string;
  displayName: string;
  description: string | null;
  createdAt: number;
  radiusMeters?: number;
  radiusUpdatedAt?: number | null;
  phaseMode?: 'default' | 'phase1';
  textOnly?: boolean;
}

export interface PostImageDraft {
  id?: string;
  name: string;
  type: string;
  size: number;
  width?: number;
  height?: number;
  checksum?: string;
}

export interface BoardPost {
  id: string;
  boardId: string;
  userId: string | null;
  author: string | null;
  alias: string | null;
  pseudonym: string | null;
  body: string;
  createdAt: number;
  reactionCount: number;
  likeCount: number;
  dislikeCount: number;
  hotRank?: number;
  images?: string[];
}

export interface SessionTicket {
  token: string;
  userId: string;
  expiresAt: number;
}

export const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;

export interface BoardEventPayload {
  id: string;
  event: string;
  data: unknown;
  traceId: string;
  timestamp: number;
}

export interface BoardFeedResponse {
  board: BoardSummary;
  posts: BoardPost[];
  realtimeConnections: number;
  spaces?: BoardSpace[];
}

export interface BoardSpace {
  id: string;
  label: string;
  type: 'default' | 'topic' | 'events' | 'custom';
  metadata?: {
    topic?: string;
    count?: number;
    description?: string;
    [key: string]: unknown;
  };
}

export interface CreatePostRequest {
  body: string;
  author?: string;
  userId?: string;
  images?: PostImageDraft[];
}

export interface CreatePostResponse {
  ok: boolean;
  post: BoardPost;
}

export interface UserProfile {
  id: string;
  pseudonym: string;
  createdAt: number;
}

export interface RegisterIdentityRequest {
  pseudonym: string;
}

export interface RegisterIdentityResponse {
  ok: boolean;
  user: UserProfile;
  session: SessionTicket;
}

export interface BoardAlias {
  id: string;
  userId: string;
  boardId: string;
  alias: string;
  aliasNormalized?: string;
  createdAt: number;
}

export interface UpsertAliasRequest {
  userId: string;
  alias: string;
}

export interface UpsertAliasResponse {
  ok: boolean;
  alias: BoardAlias;
}

export interface GetAliasResponse {
  ok: boolean;
  alias?: BoardAlias;
}

export type ReactionAction = 'like' | 'dislike' | 'remove';

export interface UpdateReactionRequest {
  userId: string;
  action: ReactionAction;
}

export interface ReactionSummary {
  total: number;
  likeCount: number;
  dislikeCount: number;
}

export interface UpdateReactionResponse {
  ok: boolean;
  boardId: string;
  postId: string;
  reactions: ReactionSummary;
}

export interface CreateSessionRequest {
  userId: string;
}

export interface CreateSessionResponse {
  ok: boolean;
  session: SessionTicket;
  user?: UserProfile;
}
