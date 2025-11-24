import { Hono } from 'hono';
import type { Env } from '../types';
import { ApiError } from '../types';
import { logger } from '../lib/logger';
import { RegisterIdentitySchema } from '@board-app/shared';
import type { RegisterIdentityResponse, CreateSessionRequest, CreateSessionResponse, UserProfile } from '@board-app/shared';
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
    resolveAccessUser,
    getUserByPseudonym,
    verifyRecoveryKey
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

function createSessionCookie(token: string, expiresAt: number): string {
    const maxAge = Math.floor((expiresAt - Date.now()) / 1000);
    return `${SESSION_COOKIE_NAME}=${token}; Max-Age=${maxAge}; Path=/; HttpOnly; Secure; SameSite=Lax`;
}

function createExpiredSessionCookie(): string {
    return `${SESSION_COOKIE_NAME}=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax`;
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
        const responseBody: RegisterIdentityResponse & { recoveryKey?: string } = {
            ok: true,
            user,
            session,
            recoveryKey: user.recoveryKey
        };
        return new Response(JSON.stringify(responseBody), {
            status: 201,
            headers: {
                'Content-Type': 'application/json',
                'Set-Cookie': createSessionCookie(session.token, session.expiresAt)
            }
        });
    } catch (error) {
        if (isUniqueConstraintError(error)) {
            return c.json({ error: 'pseudonym already taken' }, 409);
        }
        logger.error('[identity] Failed to register user', error, { endpoint: '/identity/register' });
        return c.json({ error: 'internal' }, 500);
    }
});

// GET /identity/session
auth.get('/session', async (c) => {
    const env = c.env;
    const request = c.req.raw;

    try {
        const session = await getSessionFromRequest(request, env);
        const user = await getUserById(env, session.user_id);
        if (!user) {
            return c.json({ error: 'user not found' }, 404);
        }

        const responseBody: { ok: boolean; user: UserProfile; session: typeof session } = {
            ok: true,
            user: userRecordToProfile(user),
            session
        };
        return c.json(responseBody, 200);
    } catch {
        // If session is invalid/missing, return 401 so frontend knows to clear state
        return c.json({ error: 'unauthorized' }, 401);
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

        return new Response(JSON.stringify(responseBody), {
            status: 201,
            headers: {
                'Content-Type': 'application/json',
                'Set-Cookie': createSessionCookie(session.token, session.expiresAt)
            }
        });
    }

    await ensureSession(request, env, userId);

    const session = await issueSessionTicket(env, userId);
    const responseBody: CreateSessionResponse = {
        ok: true,
        session
    };

    return new Response(JSON.stringify(responseBody), {
        status: 201,
        headers: {
            'Content-Type': 'application/json',
            'Set-Cookie': createSessionCookie(session.token, session.expiresAt)
        }
    });
});

// POST /identity/link
auth.post('/link', async (c) => {
    const env = c.env;
    const request = c.req.raw;

    try {
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
    } catch (error) {
        // If there's no session, we can't link an identity
        // Return 401 so the frontend knows this operation requires authentication
        if (error instanceof ApiError && error.status === 401) {
            return c.json({ error: 'session required' }, 401);
        }
        // For other errors, log and return 500
        logger.error('[identity] Failed to link access identity', error, { endpoint: '/identity/link' });
        return c.json({ error: 'internal' }, 500);
    }
});

// POST /identity/recover
auth.post('/recover', async (c) => {
    const env = c.env;
    const request = c.req.raw;

    let payload: unknown;
    try {
        payload = await request.json();
    } catch {
        return c.json({ error: 'Invalid JSON body' }, 400);
    }

    const { pseudonym, recoveryKey } = payload as { pseudonym?: string; recoveryKey?: string };

    if (!pseudonym || !recoveryKey) {
        return c.json({ error: 'Pseudonym and Recovery Key are required' }, 400);
    }

    const user = await getUserByPseudonym(env, pseudonym.trim());
    if (!user) {
        // Return generic error to avoid enumeration
        return c.json({ error: 'Invalid identity or recovery key' }, 401);
    }

    const isValid = await verifyRecoveryKey(env, user.id, recoveryKey.trim());
    if (!isValid) {
        return c.json({ error: 'Invalid identity or recovery key' }, 401);
    }

    const session = await issueSessionTicket(env, user.id);
    const responseBody: CreateSessionResponse = {
        ok: true,
        session,
        user: userRecordToProfile(user)
    };

    return new Response(JSON.stringify(responseBody), {
        status: 201,
        headers: {
            'Content-Type': 'application/json',
            'Set-Cookie': createSessionCookie(session.token, session.expiresAt)
        }
    });
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
                'Set-Cookie': createExpiredSessionCookie()
            }
        });
    }

    await deleteSessionByToken(env, token);

    return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: {
            'Content-Type': 'application/json',
            'Set-Cookie': createExpiredSessionCookie()
        }
    });
});

export default auth;
