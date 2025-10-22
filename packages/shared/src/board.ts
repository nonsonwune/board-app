export interface BoardSummary {
  id: string;
  displayName: string;
  description: string | null;
  createdAt: number;
}

export interface BoardPost {
  id: string;
  boardId: string;
  author: string | null;
  body: string;
  createdAt: number;
  reactionCount: number;
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
}

export interface CreatePostResponse {
  ok: boolean;
  post: BoardPost;
}
