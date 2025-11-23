import { Hono } from 'hono';
import type { Env } from '../types';
import { getSessionFromRequest } from '../lib/session';
import { listFollowingPosts, searchBoardPosts } from '../lib/post';
import { FollowingFeedResponse, SearchPostsResponse } from '@board-app/shared';

const app = new Hono<{ Bindings: Env }>();

// GET /following/feed
app.get('/following/feed', async (c) => {
    const session = await getSessionFromRequest(c.req.raw, c.env);
    const limitParam = Number(c.req.query('limit') ?? '20');
    const limit = Number.isFinite(limitParam) ? limitParam : 20;
    const cursor = c.req.query('cursor') ?? null;

    const feed = await listFollowingPosts(c.env, session.user_id, { limit, cursor });
    const response: FollowingFeedResponse = {
        ok: true,
        posts: feed.posts,
        cursor: feed.cursor,
        hasMore: feed.hasMore
    };

    return c.json(response);
});

// GET /search
app.get('/search', async (c) => {
    const query = c.req.query('q')?.trim();
    if (!query) {
        return c.json({ error: 'query param q is required' }, 400);
    }

    const limitParam = Number(c.req.query('limit') ?? '20');
    const limit = Number.isFinite(limitParam) ? Math.max(1, Math.min(limitParam, 50)) : 20;

    // Optional: filter by boardId if provided
    const boardId = c.req.query('boardId');

    const results = await searchBoardPosts(c.env, { query, limit, boardId });

    const response: SearchPostsResponse = {
        ok: true,
        posts: results.posts,
        cursor: results.cursor,
        hasMore: results.hasMore
    };

    return c.json(response);
});

export default app;
