import type { Env, UserAccessLink, AccessPrincipal } from '../types';
import { ApiError } from '../types';
import { normalizeHandle, isUniqueConstraintError } from '../utils';
import type { UserProfile, BoardAlias } from '@board-app/shared';
import { logger } from './logger';

const PSEUDONYM_MIN = 3;
const PSEUDONYM_MAX = 20;

export type UserRecord = {
    id: string;
    pseudonym: string;
    pseudonym_normalized: string;
    created_at: number;
    status: 'active' | 'access_auto' | 'access_orphan';
};

async function recordAccessIdentityEvent(
    env: Env,
    event: {
        eventType: string;
        subject: string;
        userId?: string | null;
        email?: string | null;
        traceId?: string | null;
        metadata?: Record<string, unknown> | null;
        createdAt?: number;
    }
) {
    const id = crypto.randomUUID();
    const createdAt = event.createdAt ?? Date.now();
    await env.BOARD_DB.prepare(
        `INSERT INTO access_identity_events (id, event_type, subject, user_id, email, trace_id, metadata, created_at)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)`
    )
        .bind(
            id,
            event.eventType,
            event.subject,
            event.userId ?? null,
            event.email ?? null,
            event.traceId ?? null,
            event.metadata ? JSON.stringify(event.metadata) : null,
            createdAt
        )
        .run();
}

async function emitAccessIdentityEvent(
    env: Env,
    eventType: string,
    payload: {
        subject: string;
        user_id?: string | null;
        email?: string | null;
        trace_id?: string | null;
        metadata?: Record<string, unknown> | null;
    }
) {
    const timestamp = Date.now();
    const { subject, user_id, email, trace_id, metadata } = payload;
    const rest: Record<string, unknown> = {
        ...(metadata ?? {})
    };
    logger.info('Access identity event', {
        event: eventType,
        subject,
        user_id: user_id ?? null,
        email: email ?? null,
        trace_id: trace_id ?? null,
        ...rest,
        timestamp
    });
    await recordAccessIdentityEvent(env, {
        eventType,
        subject,
        userId: user_id ?? null,
        email: email ?? null,
        traceId: trace_id ?? null,
        metadata: Object.keys(rest).length > 0 ? rest : null,
        createdAt: timestamp
    });
}

export async function createUser(
    env: Env,
    pseudonym: string,
    normalized: string,
    status: 'active' | 'access_auto' | 'access_orphan' = 'active'
): Promise<UserProfile> {
    const id = crypto.randomUUID();
    const createdAt = Date.now();

    await env.BOARD_DB.prepare(
        `INSERT INTO users (id, pseudonym, pseudonym_normalized, created_at, status)
       VALUES (?1, ?2, ?3, ?4, ?5)`
    )
        .bind(id, pseudonym, normalized, createdAt, status)
        .run();

    return { id, pseudonym, createdAt };
}

async function createUserWithUniquePseudonym(env: Env, basePseudonym: string): Promise<UserProfile> {
    let attempt = 0;
    while (attempt < 10) {
        const suffix = attempt === 0 ? '' : `-${attempt}`;
        let candidate = `${basePseudonym}${suffix}`.slice(0, PSEUDONYM_MAX);
        if (candidate.length < PSEUDONYM_MIN) {
            candidate = candidate.padEnd(PSEUDONYM_MIN, 'x');
        }
        const normalized = normalizeHandle(candidate);
        if (!normalized) {
            attempt += 1;
            continue;
        }
        try {
            return await createUser(env, candidate, normalized, 'access_auto');
        } catch (error) {
            if (isUniqueConstraintError(error)) {
                attempt += 1;
                continue;
            }
            throw error;
        }
    }
    throw new ApiError(500, { error: 'failed to create unique pseudonym' });
}

export function deriveAccessPseudonym(principal: AccessPrincipal): string {
    const emailLocal = principal?.email?.split('@')[0] ?? '';
    const subjectFragment = principal?.subject?.split('/').at(-1) ?? principal?.subject ?? '';
    const source = emailLocal || subjectFragment;
    let cleaned = source.replace(/[^a-zA-Z0-9]+/g, ' ').trim();
    if (!cleaned) {
        cleaned = 'Board User';
    }
    let base = cleaned
        .split(' ')
        .filter(Boolean)
        .map(word => word[0]?.toUpperCase() + word.slice(1))
        .join(' ')
        .slice(0, PSEUDONYM_MAX);
    if (base.length < PSEUDONYM_MIN) {
        base = `${base} User`.trim().slice(0, PSEUDONYM_MAX);
    }
    if (base.length < PSEUDONYM_MIN) {
        base = base.padEnd(PSEUDONYM_MIN, 'x');
    }
    return base;
}

export function userRecordToProfile(user: UserRecord): UserProfile {
    return {
        id: user.id,
        pseudonym: user.pseudonym,
        createdAt: user.created_at
    };
}

async function markUserStatus(env: Env, userId: string, status: 'active' | 'access_auto' | 'access_orphan') {
    await env.BOARD_DB.prepare('UPDATE users SET status = ?1 WHERE id = ?2')
        .bind(status, userId)
        .run();
}

export async function getUserById(env: Env, userId: string): Promise<UserRecord | null> {
    const record = await env.BOARD_DB.prepare(
        'SELECT id, pseudonym, pseudonym_normalized, created_at, status FROM users WHERE id = ?1'
    )
        .bind(userId)
        .first<UserRecord>();

    return record ?? null;
}

async function getAccessLinkBySubject(env: Env, subject: string): Promise<UserAccessLink | null> {
    const record = await env.BOARD_DB.prepare(
        'SELECT access_subject, user_id, email FROM user_access_links WHERE access_subject = ?1'
    )
        .bind(subject)
        .first<UserAccessLink>();
    return record ?? null;
}

async function getAccessLinkByUserId(env: Env, userId: string): Promise<UserAccessLink | null> {
    const record = await env.BOARD_DB.prepare(
        'SELECT access_subject, user_id, email FROM user_access_links WHERE user_id = ?1'
    )
        .bind(userId)
        .first<UserAccessLink>();
    return record ?? null;
}

async function upsertAccessLink(
    env: Env,
    subject: string,
    userId: string,
    email: string | null
): Promise<void> {
    const now = Date.now();
    await env.BOARD_DB.prepare(
        `INSERT INTO user_access_links (access_subject, user_id, email, created_at, updated_at)
       VALUES (?1, ?2, ?3, ?4, ?4)
     ON CONFLICT(access_subject) DO UPDATE SET
       user_id = excluded.user_id,
       email = excluded.email,
       updated_at = excluded.updated_at`
    )
        .bind(subject, userId, email, now)
        .run();
}

export async function resolveAccessUser(env: Env, principal: AccessPrincipal): Promise<UserRecord> {
    const subject = principal.subject;
    if (!subject) {
        throw new ApiError(401, { error: 'access subject missing' });
    }

    const existingLink = await getAccessLinkBySubject(env, subject);
    if (existingLink) {
        const user = await getUserById(env, existingLink.user_id);
        if (user) {
            if (user.status === 'access_orphan') {
                await markUserStatus(env, user.id, 'active');
                await emitAccessIdentityEvent(env, 'access.identity_reactivated', {
                    subject,
                    user_id: user.id,
                    email: principal.email ?? existingLink.email ?? null
                });
            }
            if (principal.email && principal.email !== existingLink.email) {
                await upsertAccessLink(env, subject, existingLink.user_id, principal.email);
            }
            const refreshed = await getUserById(env, existingLink.user_id);
            return refreshed ?? user;
        }
    }

    const base = deriveAccessPseudonym(principal);
    const profile = await createUserWithUniquePseudonym(env, base);
    await upsertAccessLink(env, subject, profile.id, principal.email ?? existingLink?.email ?? null);
    const user = await getUserById(env, profile.id);
    if (!user) {
        throw new ApiError(500, { error: 'failed to provision access user' });
    }
    await markUserStatus(env, user.id, 'access_auto');
    await emitAccessIdentityEvent(env, 'access.identity_auto_provisioned', {
        subject,
        user_id: user.id,
        email: principal.email ?? null,
        metadata: { pseudonym: user.pseudonym }
    });
    return user;
}

export async function ensureAccessPrincipalForUser(
    env: Env,
    principal: AccessPrincipal | null,
    userId: string,
    options: { allowReassign?: boolean } = {}
): Promise<void> {
    if (!principal?.subject) {
        return;
    }

    const subject = principal.subject;
    const existingLink = await getAccessLinkBySubject(env, subject);

    if (!existingLink) {
        const linkForUser = await getAccessLinkByUserId(env, userId);
        if (linkForUser && linkForUser.access_subject !== subject) {
            throw new ApiError(403, { error: 'user already linked to another access identity' });
        }
        try {
            await upsertAccessLink(env, subject, userId, principal.email ?? null);
        } catch (error) {
            if (isUniqueConstraintError(error)) {
                throw new ApiError(403, { error: 'access identity already linked' });
            }
            throw error;
        }
        await markUserStatus(env, userId, 'active');
        await emitAccessIdentityEvent(env, 'access.identity_linked', {
            subject,
            user_id: userId,
            email: principal?.email ?? null
        });
        return;
    }

    if (existingLink.user_id !== userId) {
        if (!options.allowReassign) {
            throw new ApiError(403, { error: 'access identity mismatch' });
        }
        const linkForUser = await getAccessLinkByUserId(env, userId);
        if (linkForUser && linkForUser.access_subject !== subject) {
            throw new ApiError(403, { error: 'user already linked to another access identity' });
        }
        const previousUser = await getUserById(env, existingLink.user_id);
        if (previousUser) {
            await markUserStatus(env, previousUser.id, 'access_orphan');
            await emitAccessIdentityEvent(env, 'access.identity_orphaned', {
                subject,
                user_id: previousUser.id
            });
        }
        try {
            await upsertAccessLink(env, subject, userId, principal.email ?? existingLink.email ?? null);
        } catch (error) {
            if (isUniqueConstraintError(error)) {
                throw new ApiError(403, { error: 'access identity already linked' });
            }
            throw error;
        }
        await markUserStatus(env, userId, 'active');
        await emitAccessIdentityEvent(env, 'access.identity_relinked', {
            subject,
            user_id: userId,
            email: principal.email ?? existingLink.email ?? null
        });
        return;
    }

    if (principal.email && principal.email !== existingLink.email) {
        await upsertAccessLink(env, subject, userId, principal.email);
    }
}

type BoardAliasRecord = {
    id: string;
    board_id: string;
    user_id: string;
    alias: string;
    alias_normalized: string;
    created_at: number;
};

export async function listAliasesForUser(env: Env, userId: string, limit = 100): Promise<BoardAlias[]> {
    const { results } = await env.BOARD_DB.prepare(
        'SELECT id, board_id, user_id, alias, alias_normalized, created_at FROM board_aliases WHERE user_id = ? ORDER BY created_at DESC LIMIT ?'
    )
        .bind(userId, Math.max(1, Math.min(limit, 200)))
        .all<BoardAliasRecord>();

    return (results ?? []).map(record => ({
        id: record.id,
        boardId: record.board_id,
        userId: record.user_id,
        alias: record.alias,
        aliasNormalized: record.alias_normalized,
        createdAt: record.created_at
    }));
}

export async function getFollowCounts(env: Env, userId: string): Promise<{ followerCount: number; followingCount: number }> {
    const followerRow = await env.BOARD_DB.prepare('SELECT COUNT(*) AS follower_count FROM follows WHERE following_id = ?')
        .bind(userId)
        .first<{ follower_count: number | null }>();
    const followingRow = await env.BOARD_DB.prepare('SELECT COUNT(*) AS following_count FROM follows WHERE follower_id = ?')
        .bind(userId)
        .first<{ following_count: number | null }>();

    return {
        followerCount: followerRow?.follower_count ?? 0,
        followingCount: followingRow?.following_count ?? 0
    };
}

export async function isFollowing(env: Env, followerId: string, targetId: string): Promise<boolean> {
    const existing = await env.BOARD_DB.prepare(
        'SELECT 1 FROM follows WHERE follower_id = ?1 AND following_id = ?2 LIMIT 1'
    )
        .bind(followerId, targetId)
        .first<number>();
    return Boolean(existing);
}

export async function listFollowingIds(env: Env, userId: string, limit = 50): Promise<string[]> {
    const { results } = await env.BOARD_DB.prepare(
        'SELECT following_id FROM follows WHERE follower_id = ? ORDER BY created_at DESC LIMIT ?'
    )
        .bind(userId, Math.max(1, Math.min(limit, 200)))
        .all<{ following_id: string }>();
    return (results ?? []).map(row => row.following_id);
}

export async function setFollowState(env: Env, followerId: string, targetId: string, follow: boolean): Promise<boolean> {
    if (follow) {
        await env.BOARD_DB.prepare(
            `INSERT INTO follows (follower_id, following_id, created_at)
         VALUES (?1, ?2, ?3)
       ON CONFLICT(follower_id, following_id) DO NOTHING`
        )
            .bind(followerId, targetId, Date.now())
            .run();
        return true;
    }

    await env.BOARD_DB.prepare('DELETE FROM follows WHERE follower_id = ?1 AND following_id = ?2')
        .bind(followerId, targetId)
        .run();
    return false;
}
