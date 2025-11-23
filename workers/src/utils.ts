import type { Env } from './types';

const DEFAULT_ALLOWED_ORIGINS = ['http://localhost:3000', 'http://127.0.0.1:3000', 'http://localhost:3002'];

export function withCors(request: Request, response: Response, env: Env): Response {
    const origin = request.headers.get('Origin');
    const allowedOrigins = env.ALLOWED_ORIGINS
        ? env.ALLOWED_ORIGINS.split(',').map(o => o.trim())
        : DEFAULT_ALLOWED_ORIGINS;

    const headers = new Headers(response.headers);
    headers.set('Vary', 'Origin');

    if (origin && allowedOrigins.includes(origin)) {
        headers.set('Access-Control-Allow-Origin', origin);
        headers.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
        headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization, CF-Board-ID, CF-Trace-ID');
        headers.set('Access-Control-Max-Age', '86400');
    }

    return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers
    });
}

export function parseCookies(header: string | null): Record<string, string> {
    if (!header) return {};
    return header.split(';').reduce<Record<string, string>>((acc, part) => {
        const [key, ...rest] = part.trim().split('=');
        if (!key) return acc;
        acc[key] = rest.join('=').trim();
        return acc;
    }, {});
}

export function normalizeHandle(value: string): string {
    return value
        .trim()
        .toLowerCase()
        .replace(/\s+/g, ' ');
}

export function normalizeBoardId(value: string): string {
    return value.trim().toLowerCase();
}

export function parseBoardList(value?: string): Set<string> {
    if (!value) {
        return new Set();
    }
    const entries = value
        .split(',')
        .map(entry => normalizeBoardId(entry))
        .filter(entry => entry.length > 0);
    return new Set(entries);
}

export function isUniqueConstraintError(error: unknown): boolean {
    return error instanceof Error && /UNIQUE constraint failed/i.test(error.message ?? '');
}

export function parseBearerToken(request: Request): string | null {
    const header = request.headers.get('Authorization') ?? request.headers.get('authorization');
    if (!header) return null;
    const match = header.match(/^Bearer\s+(.+)$/i);
    return match ? match[1].trim() : null;
}
