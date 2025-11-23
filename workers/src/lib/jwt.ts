import { ApiError, type Env, type AccessPrincipal, type AccessJwtConfig } from '../types';

const JWKS_CACHE_TTL_MS = 5 * 60 * 1000;
const textEncoder = new TextEncoder();

type CachedJwks = {
    keys: JsonWebKey[];
    fetchedAt: number;
};

const jwksCache = new Map<string, CachedJwks>();
const cryptoKeyCache = new Map<string, CryptoKey>();

export function getAccessJwtConfig(env: Env): AccessJwtConfig | null {
    const issuer = env.ACCESS_JWT_ISSUER?.trim();
    const audience = env.ACCESS_JWT_AUDIENCE?.trim();
    if (!issuer || !audience) {
        return null;
    }

    const jwksUrl = env.ACCESS_JWT_JWKS_URL?.trim();
    return { issuer, audience, jwksUrl: jwksUrl || undefined };
}

function base64UrlToBase64(input: string): string {
    const padded = input.padEnd(Math.ceil(input.length / 4) * 4, '=');
    return padded.replace(/-/g, '+').replace(/_/g, '/');
}

function decodeJwtSegment(segment: string): unknown {
    const base64 = base64UrlToBase64(segment);
    try {
        const json = atob(base64);
        return JSON.parse(json);
    } catch {
        throw new ApiError(401, { error: 'invalid access token' });
    }
}

function base64UrlToUint8Array(segment: string): Uint8Array {
    const base64 = base64UrlToBase64(segment);
    const binary = atob(base64);
    const array = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
        array[i] = binary.charCodeAt(i);
    }
    return array;
}

async function fetchJwks(config: AccessJwtConfig): Promise<JsonWebKey[]> {
    const jwksEndpoint = config.jwksUrl ?? `${config.issuer.replace(/\/$/, '')}/cdn-cgi/access/certs`;
    const cached = jwksCache.get(jwksEndpoint);
    const now = Date.now();
    if (cached && now - cached.fetchedAt < JWKS_CACHE_TTL_MS) {
        return cached.keys;
    }

    const res = await fetch(jwksEndpoint, { cf: { cacheEverything: false } });
    if (!res.ok) {
        throw new ApiError(500, { error: 'failed to load access keys' });
    }
    let body: { keys?: JsonWebKey[] };
    try {
        body = (await res.json()) as { keys?: JsonWebKey[] };
    } catch {
        throw new ApiError(500, { error: 'invalid access keys response' });
    }
    if (!Array.isArray(body.keys) || body.keys.length === 0) {
        throw new ApiError(500, { error: 'no access keys available' });
    }

    jwksCache.set(jwksEndpoint, { keys: body.keys, fetchedAt: now });
    return body.keys;
}

async function getCryptoKeyFromJwks(config: AccessJwtConfig, header: { kid?: string; alg?: string }): Promise<CryptoKey> {
    const kid = header.kid;
    if (!kid) {
        throw new ApiError(401, { error: 'invalid access token header' });
    }

    const jwks = await fetchJwks(config);
    const jwk = jwks.find(key => (key as any).kid === kid);
    if (!jwk) {
        throw new ApiError(401, { error: 'untrusted access key' });
    }

    const cacheKey = `${config.jwksUrl ?? config.issuer}|${kid}`;
    let cryptoKey = cryptoKeyCache.get(cacheKey);
    if (!cryptoKey) {
        if (header.alg && header.alg !== 'RS256') {
            throw new ApiError(401, { error: 'unsupported access token algorithm' });
        }
        cryptoKey = await crypto.subtle.importKey(
            'jwk',
            jwk,
            { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
            false,
            ['verify']
        );
        cryptoKeyCache.set(cacheKey, cryptoKey);
    }

    return cryptoKey;
}

export async function verifyAccessJwt(request: Request, env: Env): Promise<AccessPrincipal | null> {
    const config = getAccessJwtConfig(env);
    if (!config) {
        return null;
    }

    const token =
        request.headers.get('Cf-Access-Jwt-Assertion') ?? request.headers.get('cf-access-jwt-assertion');
    if (!token) {
        return null;
    }

    const parts = token.split('.');
    if (parts.length !== 3) {
        throw new ApiError(401, { error: 'malformed access token' });
    }

    const [headerSegment, payloadSegment, signatureSegment] = parts;
    const header = decodeJwtSegment(headerSegment) as { kid?: string; alg?: string; typ?: string };
    const payload = decodeJwtSegment(payloadSegment) as {
        iss?: string;
        aud?: string | string[];
        exp?: number;
        nbf?: number;
        sub?: string;
        email?: string;
    };

    if (payload.iss !== config.issuer) {
        throw new ApiError(401, { error: 'unauthorized access token issuer' });
    }
    const audience = payload.aud;
    const matchesAudience = Array.isArray(audience)
        ? audience.includes(config.audience)
        : audience === config.audience;
    if (!matchesAudience) {
        throw new ApiError(401, { error: 'unauthorized access token audience' });
    }

    const nowSeconds = Math.floor(Date.now() / 1000);
    if (typeof payload.exp === 'number' && payload.exp < nowSeconds) {
        throw new ApiError(401, { error: 'access token expired' });
    }
    if (typeof payload.nbf === 'number' && payload.nbf > nowSeconds + 60) {
        throw new ApiError(401, { error: 'access token not yet valid' });
    }

    const cryptoKey = await getCryptoKeyFromJwks(config, header);
    const signature = base64UrlToUint8Array(signatureSegment);
    const data = textEncoder.encode(`${headerSegment}.${payloadSegment}`);
    const verified = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', cryptoKey, signature, data);
    if (!verified) {
        throw new ApiError(401, { error: 'invalid access token signature' });
    }

    return {
        subject: payload.sub ?? '',
        email: payload.email
    };
}
