import { Hono } from 'hono';
import type { Env } from '../types';
import { logger } from '../lib/logger';
import { RegisterIdentitySchema } from '@board-app/shared';
import type { RegisterIdentityResponse, CreateSessionRequest, CreateSessionResponse } from '@board-app/shared';
import { normalizeHandle, isUniqueConstraintError, parseCookies } from '../utils';
import { verifyAccessJwt } from '../lib/jwt';
import {
    issueSessionTicket,
    deleteSessionByToken,
    getSessionFromRequest,
    ensureSession
} from '../lib/session';
import {
    createUser,
    ensureAccessPrincipalForUser,
    getUserById,
    userRecordToProfile,
    resolveAccessUser
} from '../lib/user';

const SESSION_COOKIE_NAME = 'boardapp_session_0';

function getSessionTokenFromRequest(request: Request): string | null {
    const auth = request.headers.get('Authorization');
    if (auth && auth.startsWith('Bearer ')) {
        const token = auth.slice(7).trim();
        if (token) {
            return token;
        }
    }

    const cookies = parseCookies(request.headers.get('Cookie'));
    const cookieToken = cookies[SESSION_COOKIE_NAME];
    return cookieToken ? cookieToken : null;
}

const auth = new Hono<{ Bindings: Env }>();

// POST /identity/register
auth.post('/register', async (c) => {
    const env = c.env;
    const request = c.req.raw;

    let payload: unknown;
    try {
        payload = await request.json();
    } catch {
        return c.json({ error: 'Invalid JSON body' }, 400);
    }

    const result = RegisterIdentitySchema.safeParse(payload);
    if (!result.success) {
        return c.json({ error: result.error.issues[0].message }, 400);
    }
    const data = result.data;

    const pseudonym = data.pseudonym.trim();
    const normalized = normalizeHandle(pseudonym);
    if (!normalized) {
        return c.json({ error: 'pseudonym is invalid' }, 400);
    }

    try {
        const accessPrincipal = await verifyAccessJwt(request, env);
        const user = await createUser(env, pseudonym, normalized);
        await ensureAccessPrincipalForUser(env, accessPrincipal, user.id, { allowReassign: true });
        const session = await issueSessionTicket(env, user.id);
        const responseBody: RegisterIdentityResponse = {
            ok: true,
            user,
            session
        };
        return c.json(responseBody, 201);
    } catch (error) {
        if (isUniqueConstraintError(error)) {
            return c.json({ error: 'pseudonym already taken' }, 409);
        }
        logger.error('[identity] Failed to register user', error, { endpoint: '/identity/register' });
        return c.json({ error: 'internal' }, 500);
    }
});

// POST /identity/session
auth.post('/session', async (c) => {
    const env = c.env;
    const request = c.req.raw;

    let payload: CreateSessionRequest;
    try {
        payload = (await request.json()) as CreateSessionRequest;
    } catch {
        return c.json({ error: 'Invalid JSON body' }, 400);
    }

    const userId = payload.userId?.trim();
    if (!userId) {
        const accessPrincipal = await verifyAccessJwt(request, env);
        if (!accessPrincipal?.subject) {
            return c.json({ error: 'userId is required' }, 400);
        }
        const accessUser = await resolveAccessUser(env, accessPrincipal);
        const session = await issueSessionTicket(env, accessUser.id);
        const responseBody: CreateSessionResponse = {
            ok: true,
            session,
            user: userRecordToProfile(accessUser)
        };

        return c.json(responseBody, 201);
    }

    await ensureSession(request, env, userId);

    const session = await issueSessionTicket(env, userId);
    const responseBody: CreateSessionResponse = {
        ok: true,
        session
    };

    return c.json(responseBody, 201);
});

// POST /identity/link
auth.post('/link', async (c) => {
    const env = c.env;
    const request = c.req.raw;

    const session = await getSessionFromRequest(request, env);
    const principal = await verifyAccessJwt(request, env);
    if (principal?.subject) {
        await ensureAccessPrincipalForUser(env, principal, session.user_id, { allowReassign: true });
    }
    const user = await getUserById(env, session.user_id);
    const responseBody = {
        ok: true,
        user: user ? userRecordToProfile(user) : undefined
    };

    return c.json(responseBody, 200);
});

// POST /identity/logout
auth.post('/logout', async (c) => {
    const env = c.env;
    const request = c.req.raw;

    const token = getSessionTokenFromRequest(request);
    if (!token) {
        return new Response(JSON.stringify({ ok: true }), {
            status: 200,
            headers: {
                'Content-Type': 'application/json',
                'Set-Cookie': `${SESSION_COOKIE_NAME}=; Max-Age=0; Path=/; SameSite=Lax`
            }
        });
    }

    await deleteSessionByToken(env, token);

    return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: {
            'Content-Type': 'application/json',
            'Set-Cookie': `${SESSION_COOKIE_NAME}=; Max-Age=0; Path=/; SameSite=Lax`
        }
    });
});

export default auth;
