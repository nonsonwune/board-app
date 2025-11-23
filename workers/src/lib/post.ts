import type { Env } from '../types';
import type { BoardPost as SharedBoardPost, BoardReply } from '@board-app/shared';
import { calculateHotRank } from './ranking';

export async function createPost(
    env: Env,
    boardId: string,
    body: string,
    author?: string | null,
    userId?: string | null,
    alias?: string | null,
    pseudonym?: string | null,
    images?: string[],
    boardName?: string | null
): Promise<SharedBoardPost> {
    const id = crypto.randomUUID();
    const createdAt = Date.now();
    await env.BOARD_DB.prepare(
        `INSERT INTO posts (id, board_id, user_id, author, body, created_at, reaction_count, like_count, dislike_count)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, 0, 0)`
    )
        .bind(id, boardId, userId ?? null, author ?? null, body, createdAt)
        .run();

    const hotRank = calculateHotRank(0, 0, 0, createdAt, createdAt);

    return {
        id,
        boardId,
        boardName: boardName ?? null,
        userId: userId ?? null,
        author: author ?? null,
        alias: alias ?? author ?? null,
        pseudonym: pseudonym ?? null,
        body,
        createdAt,
        reactionCount: 0,
        likeCount: 0,
        dislikeCount: 0,
        replyCount: 0,
        hotRank,
        images: images && images.length > 0 ? images : undefined
    };
}

export async function createReply(
    env: Env,
    postId: string,
    boardId: string,
    body: string,
    author?: string | null,
    userId?: string | null,
    alias?: string | null,
    pseudonym?: string | null
) {
    const id = crypto.randomUUID();
    const createdAt = Date.now();

    await env.BOARD_DB.prepare(
        `INSERT INTO replies (id, post_id, board_id, user_id, author, body, created_at)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)`
    )
        .bind(id, postId, boardId, userId ?? null, author ?? null, body, createdAt)
        .run();

    return {
        id,
        postId,
        boardId,
        userId: userId ?? null,
        author: author ?? null,
        alias: alias ?? author ?? null,
        pseudonym: pseudonym ?? null,
        body,
        createdAt
    };
}

export async function updateReactionCounts(
    env: Env,
    postId: string,
    likeCount: number,
    dislikeCount: number
): Promise<{ total: number; likeCount: number; dislikeCount: number }> {
    const total = likeCount + dislikeCount;
    await env.BOARD_DB.prepare(
        `UPDATE posts SET like_count = ?1,
                      dislike_count = ?2,
                      reaction_count = ?3
      WHERE id = ?4`
    )
        .bind(likeCount, dislikeCount, total, postId)
        .run();

    return { total, likeCount, dislikeCount };
}

export async function applyReaction(
    env: Env,
    boardId: string,
    postId: string,
    userId: string,
    action: 'like' | 'dislike' | 'remove'
): Promise<{ likeCount: number; dislikeCount: number; total: number }> {
    // Get current reaction
    const existing = await env.BOARD_DB.prepare(
        'SELECT id, reaction FROM reactions WHERE post_id = ?1 AND user_id = ?2'
    )
        .bind(postId, userId)
        .first<{ id: string; reaction: number }>();

    const currentReaction = existing?.reaction === 1 ? 'like' : existing?.reaction === -1 ? 'dislike' : null;

    // Determine new reaction
    let newReaction: 'like' | 'dislike' | null = null;
    if (action === 'like') newReaction = 'like';
    else if (action === 'dislike') newReaction = 'dislike';

    // If no change, return current counts
    if (currentReaction === newReaction) {
        const counts = await env.BOARD_DB.prepare(
            'SELECT like_count, dislike_count FROM posts WHERE id = ?1'
        )
            .bind(postId)
            .first<{ like_count: number; dislike_count: number }>();
        return {
            likeCount: counts?.like_count ?? 0,
            dislikeCount: counts?.dislike_count ?? 0,
            total: (counts?.like_count ?? 0) + (counts?.dislike_count ?? 0)
        };
    }

    // Update reaction in DB
    if (newReaction) {
        const reactionValue = newReaction === 'like' ? 1 : -1;
        await env.BOARD_DB.prepare(
            'INSERT INTO reactions (id, post_id, board_id, user_id, reaction, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6) ON CONFLICT(post_id, user_id) DO UPDATE SET reaction = excluded.reaction'
        )
            .bind(crypto.randomUUID(), postId, boardId, userId, reactionValue, Date.now())
            .run();
    } else {
        await env.BOARD_DB.prepare(
            'DELETE FROM reactions WHERE post_id = ?1 AND user_id = ?2'
        )
            .bind(postId, userId)
            .run();
    }

    // Recompute counts
    const counts = await env.BOARD_DB.prepare(
        `SELECT
            SUM(CASE WHEN reaction = 1 THEN 1 ELSE 0 END) as like_count,
            SUM(CASE WHEN reaction = -1 THEN 1 ELSE 0 END) as dislike_count
         FROM reactions
         WHERE post_id = ?1`
    )
        .bind(postId)
        .first<{ like_count: number; dislike_count: number }>();

    const likeCount = counts?.like_count ?? 0;
    const dislikeCount = counts?.dislike_count ?? 0;

    return await updateReactionCounts(env, postId, likeCount, dislikeCount);
}

interface ReplyRow {
    id: string;
    post_id: string;
    board_id: string;
    user_id: string | null;
    author: string | null;
    body: string;
    created_at: number;
    board_alias: string | null;
    pseudonym: string | null;
}

export function mapReplyRowToReply(row: ReplyRow): BoardReply {
    return {
        id: row.id,
        postId: row.post_id,
        boardId: row.board_id,
        userId: row.user_id,
        author: row.author,
        alias: row.board_alias,
        pseudonym: row.pseudonym,
        body: row.body,
        createdAt: row.created_at
    };
}

export async function listReplies(
    env: Env,
    boardId: string,
    postId: string,
    options: { limit?: number; cursor?: string | null }
) {

    const limit = options.limit ?? 50;
    let cursorCreatedAt = 0;
    let cursorId = '';
    if (options.cursor) {
        const [timestamp, id] = options.cursor.split(':');
        cursorCreatedAt = Number(timestamp) || 0;
        cursorId = id ?? '';
    }

    const rows = await env.BOARD_DB.prepare(
        `SELECT
        r.id,
        r.post_id,
        r.board_id,
        r.user_id,
        r.author,
        r.body,
        r.created_at,
        a.alias AS board_alias,
        u.pseudonym AS pseudonym
       FROM replies r
       LEFT JOIN board_aliases a ON a.board_id = r.board_id AND a.user_id = r.user_id
       LEFT JOIN users u ON u.id = r.user_id
      WHERE r.board_id = ?1
        AND r.post_id = ?2
        AND (
          r.created_at > ?3
          OR (r.created_at = ?3 AND r.id > ?4)
        )
      ORDER BY r.created_at ASC, r.id ASC
      LIMIT ?5`
    )
        .bind(boardId, postId, cursorCreatedAt, cursorId, limit)
        .all<ReplyRow>();

    const replies = rows.results?.map(mapReplyRowToReply) ?? [];
    let nextCursor: string | null = null;
    if (rows.results && rows.results.length === limit) {
        const last = rows.results[rows.results.length - 1];
        nextCursor = `${last.created_at}:${last.id}`;
    }

    return { replies, cursor: nextCursor };
}

interface PostListRow {
    id: string;
    board_id: string;
    user_id: string | null;
    author: string | null;
    body: string;
    created_at: number;
    reaction_count: number | null;
    like_count: number | null;
    dislike_count: number | null;
    reply_count: number | null;
    board_name: string | null;
    board_alias: string | null;
    pseudonym: string | null;
}

export function mapPostRowToBoardPost(row: PostListRow, now: number): SharedBoardPost {
    const likeCount = row.like_count ?? 0;
    const dislikeCount = row.dislike_count ?? 0;
    const reactionCount = row.reaction_count ?? likeCount + dislikeCount;
    const replyCount = row.reply_count ?? 0;
    const hotRank = calculateHotRank(likeCount, dislikeCount, reactionCount, row.created_at, now);

    return {
        id: row.id,
        boardId: row.board_id,
        boardName: row.board_name ?? null,
        userId: row.user_id ?? null,
        author: row.board_alias ?? row.author ?? row.pseudonym ?? null,
        alias: row.board_alias ?? row.author ?? null,
        pseudonym: row.pseudonym ?? null,
        body: row.body,
        createdAt: row.created_at,
        reactionCount,
        likeCount,
        dislikeCount,
        replyCount,
        hotRank
    };
}

export async function listPosts(
    env: Env,
    boardId: string,
    limit: number,
    options: { now?: number } = {}
): Promise<SharedBoardPost[]> {

    const now = options.now ?? Date.now();
    const { results } = await env.BOARD_DB.prepare(
        `SELECT
        p.id,
        p.board_id,
        p.user_id,
        p.author,
        p.body,
        p.created_at,
        p.reaction_count,
        p.like_count,
        p.dislike_count,
        COALESCE(r.reply_count, 0) AS reply_count,
        b.display_name AS board_name,
        ba.alias AS board_alias,
        u.pseudonym
       FROM posts p
       LEFT JOIN board_aliases ba
         ON ba.board_id = p.board_id
        AND ba.user_id = p.user_id
       LEFT JOIN users u
         ON u.id = p.user_id
       LEFT JOIN boards b
         ON b.id = p.board_id
       LEFT JOIN (
         SELECT post_id, COUNT(*) AS reply_count
           FROM replies
          GROUP BY post_id
       ) r
         ON r.post_id = p.id
       WHERE p.board_id = ?1
       ORDER BY p.created_at DESC
       LIMIT ?2`
    )
        .bind(boardId, limit)
        .all<PostListRow>();

    return (results ?? [])
        .map(row => mapPostRowToBoardPost(row, now))
        .sort((a, b) => {
            const rankDelta = (b.hotRank ?? 0) - (a.hotRank ?? 0);
            if (Math.abs(rankDelta) > 1e-6) {
                return rankDelta;
            }
            return b.createdAt - a.createdAt;
        });
}

function parsePostCursor(cursor: string | null | undefined) {
    if (!cursor) {
        return null;
    }
    const [timestamp, id] = cursor.split(':');
    const createdAt = Number(timestamp);
    if (!Number.isFinite(createdAt) || !id) {
        return null;
    }
    return { createdAt, id };
}

export async function searchBoardPosts(
    env: Env,
    options: {
        boardId?: string | null;
        query?: string | null;
        limit?: number;
        cursor?: string | null;
        windowMs?: number;
        minReactions?: number;
        now?: number;
    } = {}
): Promise<{ posts: SharedBoardPost[]; cursor: string | null; hasMore: boolean }> {

    const now = options.now ?? Date.now();
    const limit = Math.max(1, Math.min(options.limit ?? 20, 50));
    const cursor = parsePostCursor(options.cursor);
    const windowMs = options.windowMs ?? 7 * 24 * 60 * 60 * 1000;
    const minReactions = options.minReactions ?? 10;
    const extendedWindowMs = Math.max(windowMs, 30 * 24 * 60 * 60 * 1000);
    const earliest = now - extendedWindowMs;
    const boardParam = options.boardId ?? null;
    const likeParam = options.query?.trim()
        ? `%${options.query.trim().replace(/[%_]/g, match => `\\${match}`)}%`
        : null;
    const cursorCreatedAt = cursor?.createdAt ?? Number.MAX_SAFE_INTEGER;
    const cursorId = cursor?.id ?? '\uffff';

    const sql = `SELECT
        p.id,
        p.board_id,
        p.user_id,
        p.author,
        p.body,
        p.created_at,
        p.reaction_count,
        p.like_count,
        p.dislike_count,
        COALESCE(r.reply_count, 0) AS reply_count,
        b.display_name AS board_name,
        ba.alias AS board_alias,
        u.pseudonym
       FROM posts p
       LEFT JOIN board_aliases ba
         ON ba.board_id = p.board_id
        AND ba.user_id = p.user_id
       LEFT JOIN users u
         ON u.id = p.user_id
       LEFT JOIN boards b
         ON b.id = p.board_id
       LEFT JOIN (
         SELECT post_id, COUNT(*) AS reply_count
           FROM replies
          GROUP BY post_id
       ) r
         ON r.post_id = p.id
      WHERE p.created_at >= ?1
        AND (?2 IS NULL OR p.board_id = ?2)
        AND (?3 IS NULL OR p.body LIKE ?3)
        AND (p.created_at < ?4 OR (p.created_at = ?4 AND p.id < ?5))
      ORDER BY p.created_at DESC, p.id DESC
      LIMIT ?6`;

    const { results } = await env.BOARD_DB.prepare(sql)
        .bind(earliest, boardParam, likeParam, cursorCreatedAt, cursorId, limit + 1)
        .all<PostListRow>();
    const rows = results ?? [];
    const filtered = rows
        .filter(row => row.created_at >= now - windowMs || (row.reaction_count ?? 0) >= minReactions)
        .slice(0, limit);

    const posts = filtered.map(row => mapPostRowToBoardPost(row, now));
    const hasMore = rows.length > limit;
    let anchor: PostListRow | undefined;
    if (hasMore) {
        anchor = rows[limit - 1];
    } else if (filtered.length > 0) {
        anchor = filtered[filtered.length - 1];
    }
    const nextCursor = hasMore && anchor ? `${anchor.created_at}:${anchor.id}` : null;

    return { posts, cursor: nextCursor, hasMore };
}

export function extractTrendingTopics(posts: SharedBoardPost[], limit = 5): string[] {
    const hashtagRegex = /#[\p{L}0-9_-]+/gu;
    const counts = new Map<string, { count: number; label: string }>();

    for (const post of posts) {
        const matches = post.body.match(hashtagRegex);
        if (!matches) continue;
        for (const rawTag of matches) {
            const normalized = rawTag.toLowerCase();
            const entry = counts.get(normalized);
            if (entry) {
                entry.count += 1;
            } else {
                counts.set(normalized, { count: 1, label: rawTag });
            }
        }
    }

    return Array.from(counts.values())
        .sort((a, b) => b.count - a.count)
        .slice(0, limit)
        .map(entry => entry.label);
}

export function calculateInfluenceScore(posts: SharedBoardPost[]): number {
    if (!posts.length) {
        return 0;
    }

    let positive = 0;
    let negative = 0;

    for (const post of posts) {
        positive += post.likeCount ?? 0;
        positive += (post.replyCount ?? 0) * 0.5;
        negative += (post.dislikeCount ?? 0) * 0.7;
    }

    const raw = positive - negative;
    const normalized = Math.max(0, Math.min(1, raw / (posts.length * 12 + 12)));
    return Number(normalized.toFixed(2));
}

export async function listUserPosts(
    env: Env,
    userId: string,
    limit: number,
    options: { now?: number } = {}
): Promise<SharedBoardPost[]> {

    const now = options.now ?? Date.now();
    const cappedLimit = Math.max(1, Math.min(limit, 50));
    const { results } = await env.BOARD_DB.prepare(
        `SELECT
        p.id,
        p.board_id,
        p.user_id,
        p.author,
        p.body,
        p.created_at,
        p.reaction_count,
        p.like_count,
        p.dislike_count,
        COALESCE(r.reply_count, 0) AS reply_count,
        b.display_name AS board_name,
        ba.alias AS board_alias,
        u.pseudonym
       FROM posts p
       LEFT JOIN board_aliases ba
         ON ba.board_id = p.board_id
        AND ba.user_id = p.user_id
       LEFT JOIN users u
         ON u.id = p.user_id
       LEFT JOIN boards b
         ON b.id = p.board_id
       LEFT JOIN (
         SELECT post_id, COUNT(*) AS reply_count
           FROM replies
          GROUP BY post_id
       ) r
         ON r.post_id = p.id
       WHERE p.user_id = ?1
       ORDER BY p.created_at DESC
       LIMIT ?2`
    )
        .bind(userId, cappedLimit)
        .all<PostListRow>();

    return (results ?? [])
        .map(row => mapPostRowToBoardPost(row, now));
}

export async function listFollowingPosts(
    env: Env,
    followerId: string,
    options: { limit?: number; cursor?: string | null; now?: number } = {}
): Promise<{ posts: SharedBoardPost[]; cursor: string | null; hasMore: boolean }> {

    const now = options.now ?? Date.now();
    const limit = Math.max(1, Math.min(options.limit ?? 20, 50));
    const cursor = parsePostCursor(options.cursor);
    const cursorCreatedAt = cursor?.createdAt ?? Number.MAX_SAFE_INTEGER;
    const cursorId = cursor?.id ?? '\uffff';

    const sql = `SELECT
        p.id,
        p.board_id,
        p.user_id,
        p.author,
        p.body,
        p.created_at,
        p.reaction_count,
        p.like_count,
        p.dislike_count,
        COALESCE(r.reply_count, 0) AS reply_count,
        b.display_name AS board_name,
        ba.alias AS board_alias,
       u.pseudonym
       FROM posts p
       LEFT JOIN board_aliases ba
         ON ba.board_id = p.board_id
        AND ba.user_id = p.user_id
       LEFT JOIN users u
         ON u.id = p.user_id
       LEFT JOIN boards b
         ON b.id = p.board_id
       LEFT JOIN (
         SELECT post_id, COUNT(*) AS reply_count
           FROM replies
          GROUP BY post_id
       ) r
         ON r.post_id = p.id
      WHERE p.user_id IS NOT NULL
        AND p.user_id IN (SELECT following_id FROM follows WHERE follower_id = ?1)
        AND (p.created_at < ?2 OR (p.created_at = ?2 AND p.id < ?3))
      ORDER BY p.created_at DESC, p.id DESC
      LIMIT ?4`;

    const { results } = await env.BOARD_DB.prepare(sql)
        .bind(followerId, cursorCreatedAt, cursorId, limit + 1)
        .all<PostListRow>();
    const rows = results ?? [];
    const posts = rows.slice(0, limit).map(row => mapPostRowToBoardPost(row, now));
    const hasMore = rows.length > limit;
    const nextCursor = hasMore && rows[limit - 1]
        ? `${rows[limit - 1].created_at}:${rows[limit - 1].id}`
        : null;

    return { posts, cursor: nextCursor, hasMore };
}
