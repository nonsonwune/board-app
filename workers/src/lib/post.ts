import type { Env } from '../types';
import type { BoardPost as SharedBoardPost } from '@board-app/shared';
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
