import { Hono } from 'hono';
import type { Env } from '../types';
import { ensureSession, getSessionFromRequest } from '../lib/session';
import {
    getUserById,
    setFollowState,
    isFollowing,
    getFollowCounts,
    listFollowingIds,
    listAliasesForUser
} from '../lib/user';
import {
    listUserPosts,
    calculateInfluenceScore
} from '../lib/post';
import { normalizeHandle } from '../utils';
import { FollowRequestSchema, FollowResponse, ProfileSummary } from '@board-app/shared';

const app = new Hono<{ Bindings: Env }>();

// GET /profiles/:id (UUID)
app.get('/profiles/:id', async (c) => {
    const id = c.req.param('id');

    // Basic UUID validation
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) {
        return c.json({ error: 'invalid id format' }, 400);
    }

    const user = await getUserById(c.env, id);

    if (!user) {
        return c.json({ error: 'user not found' }, 404);
    }

    // Fetch additional data
    const [aliases, recentPosts, counts] = await Promise.all([
        listAliasesForUser(c.env, user.id),
        listUserPosts(c.env, user.id, 10),
        getFollowCounts(c.env, user.id)
    ]);

    const influence = calculateInfluenceScore(recentPosts);

    // Check if requesting user is following this profile
    let isFollowingUser = false;
    let followingIds: string[] = [];
    try {
        const session = await getSessionFromRequest(c.req.raw, c.env);
        if (session) {
            isFollowingUser = await isFollowing(c.env, session.user_id, user.id);
            if (session.user_id === user.id) {
                followingIds = await listFollowingIds(c.env, user.id);
            }
        }
    } catch {
        // No session, ignore
    }

    const response: ProfileSummary = {
        ok: true,
        user: {
            id: user.id,
            pseudonym: user.pseudonym,
            createdAt: user.created_at,
            influence,
            followerCount: counts.followerCount,
            followingCount: counts.followingCount
        },
        aliases,
        recentPosts,
        viewerFollows: isFollowingUser,
        followingIds: followingIds.length > 0 ? followingIds : undefined
    };

    return c.json(response);
});

// GET /profiles/:handle
app.get('/profiles/:handle', async (c) => {
    const handle = c.req.param('handle');
    const normalized = normalizeHandle(handle);

    if (!normalized) {
        return c.json({ error: 'invalid handle' }, 400);
    }

    const user = await c.env.BOARD_DB.prepare(
        'SELECT id, pseudonym, pseudonym_normalized, created_at, status FROM users WHERE pseudonym_normalized = ?1'
    )
        .bind(normalized)
        .first<{ id: string; pseudonym: string; pseudonym_normalized: string; created_at: number; status: string }>();

    if (!user) {
        return c.json({ error: 'user not found' }, 404);
    }

    // Fetch additional data
    const [aliases, recentPosts, counts] = await Promise.all([
        listAliasesForUser(c.env, user.id),
        listUserPosts(c.env, user.id, 10),
        getFollowCounts(c.env, user.id)
    ]);

    const influence = calculateInfluenceScore(recentPosts);

    // Check if requesting user is following this profile
    let isFollowingUser = false;
    let followingIds: string[] = [];
    try {
        const session = await getSessionFromRequest(c.req.raw, c.env);
        if (session) {
            isFollowingUser = await isFollowing(c.env, session.user_id, user.id);
            if (session.user_id === user.id) {
                followingIds = await listFollowingIds(c.env, user.id);
            }
        }
    } catch {
        // No session, ignore
    }

    const response: ProfileSummary = {
        ok: true,
        user: {
            id: user.id,
            pseudonym: user.pseudonym,
            createdAt: user.created_at,
            influence,
            followerCount: counts.followerCount,
            followingCount: counts.followingCount
        },
        aliases,
        recentPosts,
        viewerFollows: isFollowingUser,
        followingIds: followingIds.length > 0 ? followingIds : undefined
    };

    return c.json(response);
});

// POST /follow
app.post('/follow', async (c) => {
    let payload: unknown;
    try {
        payload = await c.req.json();
    } catch {
        return c.json({ error: 'Invalid JSON body' }, 400);
    }

    const result = FollowRequestSchema.safeParse(payload);
    if (!result.success) {
        return c.json({ error: result.error.issues[0].message }, 400);
    }
    const { targetUserId, action } = result.data;

    const session = await getSessionFromRequest(c.req.raw, c.env);
    await ensureSession(c.req.raw, c.env, session.user_id);

    if (session.user_id === targetUserId) {
        return c.json({ error: 'cannot follow self' }, 400);
    }

    const targetUser = await getUserById(c.env, targetUserId);
    if (!targetUser) {
        return c.json({ error: 'target user not found' }, 404);
    }

    await setFollowState(c.env, session.user_id, targetUserId, action === 'follow');
    const newCounts = await getFollowCounts(c.env, targetUserId);

    const response: FollowResponse = {
        ok: true,
        following: action === 'follow',
        followerCount: newCounts.followerCount,
        followingCount: newCounts.followingCount
    };

    return c.json(response);
});

export default app;
