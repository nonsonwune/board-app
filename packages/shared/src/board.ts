export interface BoardSummary {
  id: string;
  displayName: string;
  description: string | null;
  createdAt: number;
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
}

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
}

export interface CreatePostRequest {
  body: string;
  author?: string;
  userId?: string;
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
