import type { Env, UserAccessLink, AccessPrincipal } from '../types';
import { ApiError } from '../types';
import { SESSION_TTL_MS } from '@board-app/shared';
import type { SessionTicket } from '@board-app/shared';
import { parseBearerToken } from '../utils';
import { verifyAccessJwt } from './jwt';

export interface SessionRecord {
    token: string;
    user_id: string;
    created_at: number;
    expires_at: number;
}

export async function issueSessionTicket(env: Env, userId: string): Promise<SessionTicket> {
    const token = crypto.randomUUID().replace(/-/g, '');
    const createdAt = Date.now();
    const expiresAt = createdAt + SESSION_TTL_MS;
    await env.BOARD_DB.prepare(
        `INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?1, ?2, ?3, ?4)`
    )
        .bind(token, userId, createdAt, expiresAt)
        .run();

    return {
        token,
        userId,
        expiresAt
    };
}

export async function getSessionByToken(env: Env, token: string): Promise<SessionRecord | null> {
    const record = await env.BOARD_DB.prepare(
        'SELECT token, user_id, created_at, expires_at FROM sessions WHERE token = ?1'
    )
        .bind(token)
        .first<SessionRecord>();

    if (!record) {
        return null;
    }

    if (record.expires_at < Date.now()) {
        await env.BOARD_DB.prepare('DELETE FROM sessions WHERE token = ?1').bind(token).run();
        return null;
    }

    return record;
}

export async function deleteSessionByToken(env: Env, token: string): Promise<void> {
    await env.BOARD_DB.prepare('DELETE FROM sessions WHERE token = ?1').bind(token).run();
}

export async function getSessionFromRequest(request: Request, env: Env): Promise<SessionRecord> {
    const token = parseBearerToken(request);
    if (!token) {
        throw new ApiError(401, { error: 'authorization required' });
    }

    const session = await getSessionByToken(env, token);
    if (!session) {
        throw new ApiError(401, { error: 'invalid session' });
    }

    return session;
}

export async function ensureSession(request: Request, env: Env, userId: string): Promise<SessionRecord> {
    const accessContext = await verifyAccessJwt(request, env);
    const session = await getSessionFromRequest(request, env);
    if (session.user_id !== userId) {
        throw new ApiError(401, { error: 'invalid session' });
    }

    // Dynamically import to avoid circular dependency
    if (accessContext) {
        const { ensureAccessPrincipalForUser } = await import('./user');
        await ensureAccessPrincipalForUser(env, accessContext, session.user_id);
    }

    return session;
}
