// Typed API client for Board App frontend

import type {
    CreatePostRequest,
    CreatePostResponse,
    CreateReplyRequest,
    CreateReplyResponse,
    RegisterIdentityRequest,
    RegisterIdentityResponse,
    CreateSessionRequest,
    CreateSessionResponse,
    BoardFeedResponse,
    BoardCatalogResponse,
    UpdateReactionRequest,
    UpdateReactionResponse,
    UpsertAliasRequest,
    UpsertAliasResponse,
    GetAliasResponse,
    ListRepliesResponse,
    SearchPostsResponse,
    FollowingFeedResponse,
    FollowRequest,
    FollowResponse,
    UserProfile
} from '@board-app/shared';

export class ApiError extends Error {
    constructor(
        public status: number,
        public body: Record<string, unknown>,
        message?: string
    ) {
        super(message || `API Error: ${status}`);
        this.name = 'ApiError';
    }
}

export interface ApiClientConfig {
    baseUrl?: string;
    getToken?: () => string | null;
}

export class ApiClient {
    private baseUrl: string;
    private getToken: () => string | null;

    constructor(config: ApiClientConfig = {}) {
        this.baseUrl = config.baseUrl || '';
        this.getToken = config.getToken || (() => null);
    }

    private async request<T>(
        method: string,
        path: string,
        body?: unknown
    ): Promise<T> {
        const token = this.getToken();
        const headers: Record<string, string> = {
            'Content-Type': 'application/json'
        };

        if (token) {
            headers['Authorization'] = `Bearer ${token}`;
        }

        const response = await fetch(`${this.baseUrl}${path}`, {
            method,
            headers,
            body: body ? JSON.stringify(body) : undefined
        });

        if (!response.ok) {
            let errorBody: Record<string, unknown> = {};
            try {
                errorBody = await response.json();
            } catch {
                errorBody = { error: response.statusText };
            }
            throw new ApiError(response.status, errorBody);
        }

        return response.json();
    }

    // Auth endpoints
    async registerIdentity(data: RegisterIdentityRequest): Promise<RegisterIdentityResponse> {
        return this.request('POST', '/identity/register', data);
    }

    async createSession(data: CreateSessionRequest): Promise<CreateSessionResponse> {
        return this.request('POST', '/identity/session', data);
    }

    async linkIdentity(): Promise<{ ok: boolean; user?: UserProfile }> {
        return this.request('POST', '/identity/link');
    }

    async logout(): Promise<{ ok: boolean }> {
        return this.request('POST', '/identity/logout');
    }

    // Board endpoints
    async getBoardsCatalog(limit?: number): Promise<BoardCatalogResponse> {
        const query = limit ? `?limit=${limit}` : '';
        return this.request('GET', `/boards/catalog${query}`);
    }

    async getBoardFeed(boardId: string, sort: 'hot' | 'new' = 'hot', limit = 50): Promise<BoardFeedResponse> {
        return this.request('GET', `/boards/${boardId}/feed?sort=${sort}&limit=${limit}`);
    }

    // Post endpoints
    async createPost(boardId: string, data: CreatePostRequest): Promise<CreatePostResponse> {
        return this.request('POST', `/boards/${boardId}/posts`, data);
    }

    async createReply(boardId: string, postId: string, data: CreateReplyRequest): Promise<CreateReplyResponse> {
        return this.request('POST', `/boards/${boardId}/posts/${postId}/replies`, data);
    }

    async listReplies(boardId: string, postId: string): Promise<ListRepliesResponse> {
        return this.request('GET', `/boards/${boardId}/posts/${postId}/replies`);
    }

    async updateReaction(boardId: string, postId: string, data: UpdateReactionRequest): Promise<UpdateReactionResponse> {
        return this.request('PUT', `/boards/${boardId}/posts/${postId}/reactions`, data);
    }

    // Alias endpoints
    async upsertAlias(boardId: string, data: UpsertAliasRequest): Promise<UpsertAliasResponse> {
        return this.request('PUT', `/boards/${boardId}/aliases`, data);
    }

    async getAlias(boardId: string): Promise<GetAliasResponse> {
        return this.request('GET', `/boards/${boardId}/aliases`);
    }

    // Search endpoints
    async searchPosts(query: string, limit = 20): Promise<SearchPostsResponse> {
        return this.request('GET', `/search/posts?q=${encodeURIComponent(query)}&limit=${limit}`);
    }

    // Following endpoints
    async follow(data: FollowRequest): Promise<FollowResponse> {
        return this.request('POST', '/follow', data);
    }

    async getFollowingFeed(limit = 50): Promise<FollowingFeedResponse> {
        return this.request('GET', `/following/feed?limit=${limit}`);
    }
}

// Default client instance
export const apiClient = new ApiClient();
