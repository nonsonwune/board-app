import schemaSql from './schema.sql';
import { BoardRoom, type BoardWebSocket } from './board-room';
import type {
  BoardEventPayload,
  BoardFeedResponse,
  BoardPost as SharedBoardPost,
  BoardSummary,
  CreatePostRequest,
  CreatePostResponse,
  RegisterIdentityRequest,
  RegisterIdentityResponse,
  UpsertAliasRequest,
  UpsertAliasResponse,
  GetAliasResponse,
  UpdateReactionRequest,
  UpdateReactionResponse,
  ReactionSummary,
  ReactionAction,
  UserProfile,
  BoardAlias,
  SessionTicket,
  CreateSessionRequest,
  CreateSessionResponse
} from '@board-app/shared';
import { SESSION_TTL_MS } from '@board-app/shared';

type WebSocketRequest = Request & { webSocket?: WebSocket };

export interface Env {
  BOARD_DB: D1Database;
  BOARD_ROOM_DO: DurableObjectNamespace;
  ACCESS_JWT_AUDIENCE?: string;
  ACCESS_JWT_ISSUER?: string;
  ACCESS_JWT_JWKS_URL?: string;
}

const ALLOWED_ORIGINS = ['http://localhost:3000', 'http://127.0.0.1:3000', 'http://localhost:3002'];
const boardRooms = new Map<string, BoardRoom>();
let schemaInitialized = false;
let schemaInitPromise: Promise<void> | null = null;

const PSEUDONYM_MIN = 3;
const PSEUDONYM_MAX = 20;
const ALIAS_MIN = 3;
const ALIAS_MAX = 24;
const JWKS_CACHE_TTL_MS = 5 * 60 * 1000;

const textEncoder = new TextEncoder();

type CachedJwks = {
  keys: JsonWebKey[];
  fetchedAt: number;
};

const jwksCache = new Map<string, CachedJwks>();
const cryptoKeyCache = new Map<string, CryptoKey>();

interface AccessJwtConfig {
  issuer: string;
  audience: string;
  jwksUrl?: string;
}

interface AccessPrincipal {
  subject?: string;
  email?: string;
}

interface UserAccessLink {
  access_subject: string;
  user_id: string;
  email: string | null;
}

class ApiError extends Error {
  status: number;
  body: Record<string, unknown>;

  constructor(status: number, body: Record<string, unknown>) {
    super(typeof body.error === 'string' ? body.error : 'error');
    this.status = status;
    this.body = body;
  }
}

function allowOrigin(origin: string | null) {
  if (!origin) return '*';
  return ALLOWED_ORIGINS.includes(origin) ? origin : '*';
}

function normalizeHandle(value: string) {
  return value
    .trim()
    .toLowerCase()
    .replace(/\s+/g, ' ');
}

function isUniqueConstraintError(error: unknown) {
  return error instanceof Error && /UNIQUE constraint failed/i.test(error.message ?? '');
}

function parseBearerToken(request: Request) {
  const header = request.headers.get('Authorization') ?? request.headers.get('authorization');
  if (!header) return null;
  const match = header.match(/^Bearer\s+(.+)$/i);
  return match ? match[1].trim() : null;
}

function withCors(request: Request, response: Response) {
  const origin = allowOrigin(request.headers.get('Origin'));
  const headers = new Headers(response.headers);
  headers.set('Access-Control-Allow-Origin', origin);
  headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  headers.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  headers.set('Vary', 'Origin');
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers
  });
}

export function __resetSchemaForTests() {
  schemaInitialized = false;
  schemaInitPromise = null;
}

function getAccessJwtConfig(env: Env): AccessJwtConfig | null {
  const issuer = env.ACCESS_JWT_ISSUER?.trim();
  const audience = env.ACCESS_JWT_AUDIENCE?.trim();
  if (!issuer || !audience) {
    return null;
  }

  const jwksUrl = env.ACCESS_JWT_JWKS_URL?.trim();
  return { issuer, audience, jwksUrl: jwksUrl || undefined };
}

function base64UrlToBase64(input: string) {
  const padded = input.padEnd(Math.ceil(input.length / 4) * 4, '=');
  return padded.replace(/-/g, '+').replace(/_/g, '/');
}

function decodeJwtSegment(segment: string): any {
  const base64 = base64UrlToBase64(segment);
  try {
    const json = atob(base64);
    return JSON.parse(json);
  } catch (error) {
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
  } catch (error) {
    throw new ApiError(500, { error: 'invalid access keys response' });
  }
  if (!Array.isArray(body.keys) || body.keys.length === 0) {
    throw new ApiError(500, { error: 'no access keys available' });
  }

  jwksCache.set(jwksEndpoint, { keys: body.keys, fetchedAt: now });
  return body.keys;
}

async function getCryptoKeyFromJwks(config: AccessJwtConfig, header: { kid?: string; alg?: string }) {
  const kid = header.kid;
  if (!kid) {
    throw new ApiError(401, { error: 'invalid access token header' });
  }

  const jwks = await fetchJwks(config);
  const jwk = jwks.find(key => key.kid === kid);
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

async function verifyAccessJwt(request: Request, env: Env): Promise<AccessPrincipal | null> {
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

async function ensureSchema(env: Env) {
  if (schemaInitialized) return;
  if (!schemaInitPromise) {
    schemaInitPromise = (async () => {
      const cleaned = schemaSql
        .replace(/\/\*[\s\S]*?\*\//g, '')
        .replace(/--.*$/gm, '')
        .trim();

      if (!cleaned) {
        throw new Error('schema.sql is empty after stripping comments');
      }

      const statements = cleaned
        .split(/;\s*(?:\r?\n|$)/)
        .map(statement => statement.trim())
        .filter(Boolean)
        .map(statement => (statement.endsWith(';') ? statement : `${statement};`));

      if (statements.length === 0) {
        throw new Error('schema.sql is empty after processing');
      }

      for (const sql of statements) {
        try {
          await env.BOARD_DB.prepare(sql).run();
        } catch (error) {
          console.error('[schema] failed to apply statement', sql);
          throw error;
        }
      }

      const alterStatements = [
        `ALTER TABLE posts ADD COLUMN like_count INTEGER NOT NULL DEFAULT 0`,
        `ALTER TABLE posts ADD COLUMN dislike_count INTEGER NOT NULL DEFAULT 0`,
        `ALTER TABLE posts ADD COLUMN user_id TEXT REFERENCES users(id) ON DELETE SET NULL`,
        `ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT 'active'`
      ];

      for (const sql of alterStatements) {
        try {
          await env.BOARD_DB.prepare(sql).run();
        } catch (error: any) {
          const message = String(error?.message ?? '');
          if (/duplicate column name/i.test(message)) {
            continue;
          }
          if (/no such column/i.test(message)) {
            continue;
          }
          if (/duplicate column/i.test(message)) {
            continue;
          }
          console.warn('[schema] alter statement failed', sql, error);
        }
      }

      schemaInitialized = true;
      console.log('[schema] ready');
    })();
  }
  await schemaInitPromise;
}

function getBoardRoom(boardId: string) {
  let room = boardRooms.get(boardId);
  if (!room) {
    room = new BoardRoom({ boardId });
    boardRooms.set(boardId, room);
  }
  return room;
}

async function persistEvent(env: Env, record: BoardEventPayload, boardId: string) {
  await ensureSchema(env);
  await env.BOARD_DB.prepare(
    `INSERT INTO board_events (id, board_id, event_type, payload, trace_id, created_at)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6)`
  )
    .bind(
      record.id,
      boardId,
      record.event ?? 'message',
      JSON.stringify(record.data ?? null),
      record.traceId ?? 'unknown',
      record.timestamp ?? Date.now()
    )
    .run();
}

async function getOrCreateBoard(env: Env, boardId: string): Promise<BoardRecord> {
  await ensureSchema(env);
  const existing = await env.BOARD_DB.prepare(
    'SELECT id, display_name, description, created_at FROM boards WHERE id = ?1'
  )
    .bind(boardId)
    .first<BoardRecord>();

  if (existing) {
    return existing;
  }

  const createdAt = Date.now();
  const displayName = formatBoardName(boardId);
  await env.BOARD_DB.prepare(
    'INSERT INTO boards (id, display_name, description, created_at) VALUES (?1, ?2, ?3, ?4)'
  )
    .bind(boardId, displayName, null, createdAt)
    .run();

  return {
    id: boardId,
    display_name: displayName,
    description: null,
    created_at: createdAt
  };
}

async function createPost(
  env: Env,
  boardId: string,
  body: string,
  author?: string | null,
  userId?: string | null,
  alias?: string | null,
  pseudonym?: string | null
): Promise<SharedBoardPost> {
  await ensureSchema(env);
  const id = crypto.randomUUID();
  const createdAt = Date.now();
  await env.BOARD_DB.prepare(
    `INSERT INTO posts (id, board_id, user_id, author, body, created_at, reaction_count, like_count, dislike_count)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, 0, 0)`
  )
    .bind(id, boardId, userId ?? null, author ?? null, body, createdAt)
    .run();

  return {
    id,
    boardId,
    userId: userId ?? null,
    author: author ?? null,
    alias: alias ?? author ?? null,
    pseudonym: pseudonym ?? null,
    body,
    createdAt,
    reactionCount: 0,
    likeCount: 0,
    dislikeCount: 0
  };
}

async function listPosts(env: Env, boardId: string, limit: number): Promise<SharedBoardPost[]> {
  await ensureSchema(env);
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
        ba.alias AS board_alias,
        u.pseudonym
       FROM posts p
       LEFT JOIN board_aliases ba
         ON ba.board_id = p.board_id
        AND ba.user_id = p.user_id
       LEFT JOIN users u
         ON u.id = p.user_id
       WHERE p.board_id = ?1
       ORDER BY p.created_at DESC
       LIMIT ?2`
  )
    .bind(boardId, limit)
    .all<PostListRow>();

  return (results ?? []).map(row => ({
    id: row.id,
    boardId: row.board_id,
    userId: row.user_id ?? null,
    author: row.board_alias ?? row.author ?? row.pseudonym ?? null,
    alias: row.board_alias ?? row.author ?? null,
    pseudonym: row.pseudonym ?? null,
    body: row.body,
    createdAt: row.created_at,
    reactionCount: row.reaction_count,
    likeCount: row.like_count,
    dislikeCount: row.dislike_count
  }));
}

async function issueSessionTicket(env: Env, userId: string): Promise<SessionTicket> {
  await ensureSchema(env);
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

async function getSessionByToken(env: Env, token: string): Promise<SessionRecord | null> {
  await ensureSchema(env);
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

async function getSessionFromRequest(request: Request, env: Env): Promise<SessionRecord> {
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

async function ensureSession(request: Request, env: Env, userId: string): Promise<SessionRecord> {
  const accessContext = await verifyAccessJwt(request, env);
  const session = await getSessionFromRequest(request, env);
  if (session.user_id !== userId) {
    throw new ApiError(401, { error: 'invalid session' });
  }

  await ensureAccessPrincipalForUser(env, accessContext, session.user_id);

  return session;
}

async function createUser(
  env: Env,
  pseudonym: string,
  normalized: string,
  status: 'active' | 'access_auto' | 'access_orphan' = 'active'
): Promise<UserProfile> {
  await ensureSchema(env);
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

function deriveAccessPseudonym(principal: AccessPrincipal): string {
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

function userRecordToProfile(user: UserRecord): UserProfile {
  return {
    id: user.id,
    pseudonym: user.pseudonym,
    createdAt: user.created_at
  };
}

async function markUserStatus(env: Env, userId: string, status: 'active' | 'access_auto' | 'access_orphan') {
  await ensureSchema(env);
  await env.BOARD_DB.prepare('UPDATE users SET status = ?1 WHERE id = ?2')
    .bind(status, userId)
    .run();
}

async function getUserById(env: Env, userId: string): Promise<UserRecord | null> {
  await ensureSchema(env);
  const record = await env.BOARD_DB.prepare(
    'SELECT id, pseudonym, pseudonym_normalized, created_at, status FROM users WHERE id = ?1'
  )
    .bind(userId)
    .first<UserRecord>();

  return record ?? null;
}

async function getAccessLinkBySubject(env: Env, subject: string): Promise<UserAccessLink | null> {
  await ensureSchema(env);
  const record = await env.BOARD_DB.prepare(
    'SELECT access_subject, user_id, email FROM user_access_links WHERE access_subject = ?1'
  )
    .bind(subject)
    .first<UserAccessLink>();
  return record ?? null;
}

async function getAccessLinkByUserId(env: Env, userId: string): Promise<UserAccessLink | null> {
  await ensureSchema(env);
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
  await ensureSchema(env);
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

async function resolveAccessUser(env: Env, principal: AccessPrincipal): Promise<UserRecord> {
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
        console.log(
          JSON.stringify({
            event: 'access.identity_reactivated',
            user_id: user.id,
            subject,
            email: principal.email ?? existingLink.email ?? null,
            timestamp: Date.now()
          })
        );
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
  console.log(
    JSON.stringify({
      event: 'access.identity_auto_provisioned',
      user_id: user.id,
      subject,
      email: principal.email ?? null,
      pseudonym: user.pseudonym,
      timestamp: Date.now()
    })
  );
  return user;
}

async function ensureAccessPrincipalForUser(
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
    console.log(
      JSON.stringify({
        event: 'access.identity_linked',
        subject,
        user_id: userId,
        email: principal.email ?? existingLink?.email ?? null,
        timestamp: Date.now()
      })
    );
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
      console.log(
        JSON.stringify({
          event: 'access.identity_orphaned',
          subject,
          user_id: previousUser.id,
          timestamp: Date.now()
        })
      );
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
    console.log(
      JSON.stringify({
        event: 'access.identity_relinked',
        subject,
        user_id: userId,
        email: principal.email ?? existingLink.email ?? null,
        timestamp: Date.now()
      })
    );
    return;
  }

  if (principal.email && principal.email !== existingLink.email) {
    await upsertAccessLink(env, subject, userId, principal.email);
  }
}

async function upsertBoardAlias(
  env: Env,
  boardId: string,
  userId: string,
  alias: string,
  normalized: string
): Promise<BoardAlias> {
  await ensureSchema(env);
  const id = crypto.randomUUID();
  const createdAt = Date.now();

  await env.BOARD_DB.prepare(
    `INSERT INTO board_aliases (id, board_id, user_id, alias, alias_normalized, created_at)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6)
     ON CONFLICT(board_id, user_id) DO UPDATE SET
       alias = excluded.alias,
       alias_normalized = excluded.alias_normalized`
  )
    .bind(id, boardId, userId, alias, normalized, createdAt)
    .run();

  const record = await env.BOARD_DB.prepare(
    'SELECT id, board_id, user_id, alias, alias_normalized, created_at FROM board_aliases WHERE board_id = ?1 AND user_id = ?2'
  )
    .bind(boardId, userId)
    .first<BoardAliasRecord>();

  if (!record) {
    throw new Error('Failed to upsert alias');
  }

  return {
    id: record.id,
    boardId: record.board_id,
    userId: record.user_id,
    alias: record.alias,
    aliasNormalized: record.alias_normalized,
    createdAt: record.created_at
  };
}

async function getBoardAlias(env: Env, boardId: string, userId: string): Promise<BoardAlias | null> {
  await ensureSchema(env);
  const record = await env.BOARD_DB.prepare(
    'SELECT id, board_id, user_id, alias, alias_normalized, created_at FROM board_aliases WHERE board_id = ?1 AND user_id = ?2'
  )
    .bind(boardId, userId)
    .first<BoardAliasRecord>();

  if (!record) return null;

  return {
    id: record.id,
    boardId: record.board_id,
    userId: record.user_id,
    alias: record.alias,
    aliasNormalized: record.alias_normalized,
    createdAt: record.created_at
  };
}

async function applyReaction(
  env: Env,
  boardId: string,
  postId: string,
  userId: string,
  action: ReactionAction
): Promise<ReactionSummary> {
  await ensureSchema(env);

  const post = await env.BOARD_DB.prepare(
    'SELECT id, board_id FROM posts WHERE id = ?1'
  )
    .bind(postId)
    .first<PostBoardRecord>();

  if (!post) {
    throw new Error('Post not found');
  }

  if (post.board_id !== boardId) {
    throw new Error('Post does not belong to board');
  }

  const now = Date.now();

  if (action === 'remove') {
    await env.BOARD_DB.prepare('DELETE FROM reactions WHERE post_id = ?1 AND user_id = ?2')
      .bind(postId, userId)
      .run();
  } else {
    const reactionValue = action === 'like' ? 1 : -1;
    await env.BOARD_DB.prepare(
      `INSERT INTO reactions (id, post_id, board_id, user_id, reaction, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
       ON CONFLICT(post_id, user_id) DO UPDATE SET
         reaction = excluded.reaction,
         created_at = excluded.created_at`
    )
      .bind(crypto.randomUUID(), postId, boardId, userId, reactionValue, now)
      .run();
  }

  const counts = await env.BOARD_DB.prepare(
    `SELECT
        SUM(CASE WHEN reaction = 1 THEN 1 ELSE 0 END) AS like_count,
        SUM(CASE WHEN reaction = -1 THEN 1 ELSE 0 END) AS dislike_count
       FROM reactions
       WHERE post_id = ?1`
  )
    .bind(postId)
    .first<{ like_count: number | null; dislike_count: number | null }>();

  const likeCount = counts?.like_count ?? 0;
  const dislikeCount = counts?.dislike_count ?? 0;
  const total = likeCount + dislikeCount;

  await env.BOARD_DB.prepare(
    `UPDATE posts
        SET like_count = ?1,
            dislike_count = ?2,
            reaction_count = ?3
      WHERE id = ?4`
  )
    .bind(likeCount, dislikeCount, total, postId)
    .run();

  return { total, likeCount, dislikeCount };
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === 'OPTIONS') {
      return withCors(request, new Response(null, { status: 204 }));
    }

    if (url.pathname === '/_health') {
      return new Response('ok', { status: 200 });
    }

    try {
      if (url.pathname === '/identity/session') {
        return withCors(request, await handleCreateSession(request, env));
      }

      if (url.pathname === '/identity/register') {
        return withCors(request, await handleRegisterIdentity(request, env));
      }

      if (url.pathname === '/identity/link') {
        return withCors(request, await handleLinkIdentity(request, env));
      }

      const upgradeHeader = request.headers.get('Upgrade');
      if (url.pathname === '/boards' && upgradeHeader === 'websocket') {
        return handleWebsocket(request, env, ctx, url);
      }

      if (url.pathname.match(/^\/boards\/[^/]+\/aliases$/)) {
        return withCors(request, await handleAlias(request, env, url));
      }

      if (url.pathname.match(/^\/boards\/[^/]+\/events$/)) {
        return await handleEvents(request, env, ctx, url);
      }

      if (url.pathname.match(/^\/boards\/[^/]+\/posts$/)) {
        return withCors(request, await handleCreatePost(request, env, ctx, url));
      }

      if (url.pathname.match(/^\/boards\/[^/]+\/posts\/[^/]+\/reactions$/)) {
        return withCors(request, await handleUpdateReaction(request, env, ctx, url));
      }

      if (url.pathname.match(/^\/boards\/[^/]+\/feed$/)) {
        return withCors(request, await handleFeed(request, env, url));
      }

      return withCors(request, new Response('Not Found', { status: 404 }));
    } catch (error: any) {
      if (error instanceof ApiError) {
        return withCors(
          request,
          new Response(JSON.stringify(error.body), {
            status: error.status,
            headers: { 'Content-Type': 'application/json' }
          })
        );
      }
      console.error('[worker] unexpected error', error);
      return withCors(
        request,
        new Response(JSON.stringify({ error: 'internal' }), {
          status: 500,
          headers: { 'Content-Type': 'application/json' }
        })
      );
    }
  }
};

const __internal = {
  resolveAccessUser,
  ensureAccessPrincipalForUser,
  deriveAccessPseudonym
};

export {
  ensureSchema,
  getOrCreateBoard,
  createPost,
  listPosts,
  persistEvent,
  createUser,
  upsertBoardAlias,
  applyReaction,
  getBoardAlias,
  __internal
};

async function handleWebsocket(request: Request, env: Env, ctx: ExecutionContext, url: URL) {
  const boardId = url.searchParams.get('boardId');
  if (!boardId) {
    return withCors(
      request,
      new Response(JSON.stringify({ error: 'boardId query param required' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      })
    );
  }

  const room = getBoardRoom(boardId);
  const traceId = request.headers.get('cf-ray') ?? crypto.randomUUID();
  const pair = new WebSocketPair();
  const client = pair[0];
  const server = pair[1];

  const closePromise = room.handleConnection(server as unknown as BoardWebSocket, {
    boardId,
    traceId
  });

  closePromise
    .then(() => {
      if (room.getConnectionCount() === 0) {
        boardRooms.delete(boardId);
      }
    })
    .catch(error => {
      console.warn('[worker] websocket close handler error', error);
    });

  return new Response(null, { status: 101, webSocket: client });
}

async function handleEvents(request: Request, env: Env, ctx: ExecutionContext, url: URL) {
  const match = url.pathname.match(/^\/boards\/([^/]+)\/events$/);
  const boardId = decodeURIComponent(match![1]);
  const traceId = request.headers.get('cf-ray') ?? crypto.randomUUID();
  const durableId = env.BOARD_ROOM_DO.idFromName(boardId);
  const stub = env.BOARD_ROOM_DO.get(durableId);

  if (request.method === 'POST') {
    let payload: any;
    try {
      payload = await request.json();
    } catch (error) {
      return withCors(
        request,
        new Response(JSON.stringify({ error: 'Invalid JSON body', trace_id: traceId }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        })
      );
    }

    const response = await stub.fetch('https://board-room.internal/broadcast', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'CF-Board-ID': boardId,
        'CF-Trace-ID': traceId
      },
      body: JSON.stringify(payload)
    });

    const bodyText = await response.text();
    if (response.ok) {
      try {
        const parsed = JSON.parse(bodyText) as { event?: BoardEventPayload };
        const record = parsed.event;
        if (record) {
          const room = getBoardRoom(boardId);
          room.broadcast(
            {
              type: 'event',
              event: record.event,
              data: record.data,
              eventId: record.id,
              trace_id: record.traceId,
              timestamp: record.timestamp
            },
            undefined
          );
          ctx.waitUntil(persistEvent(env, record, boardId));
        }
      } catch (error) {
        console.warn('[worker] failed to parse broadcast response', error);
      }
    }

    return withCors(
      request,
      new Response(bodyText, {
        status: response.status,
        headers: { 'Content-Type': 'application/json' }
      })
    );
  }

  if (request.method === 'GET') {
    const limitParam = Number(url.searchParams.get('limit') ?? '20');
    const limit = Number.isFinite(limitParam) ? Math.max(0, Math.min(limitParam, 100)) : 20;

    await ensureSchema(env);
    const { results } = await env.BOARD_DB.prepare(
      `SELECT id, event_type, payload, trace_id, created_at FROM board_events
         WHERE board_id = ?1
         ORDER BY created_at DESC
         LIMIT ?2`
    )
      .bind(boardId, limit)
      .all<{ id: string; event_type: string; payload: string; trace_id: string; created_at: number }>();

    const events = (results ?? [])
      .map(row => {
        let data: unknown = null;
        try {
          data = row.payload ? JSON.parse(row.payload) : null;
        } catch (error) {
          console.warn('[worker] failed to parse stored payload', error);
        }
        return {
          id: row.id,
          boardId,
          event: row.event_type,
          data,
          traceId: row.trace_id,
          timestamp: row.created_at
        };
      })
      .reverse();

    const room = boardRooms.get(boardId);
    return withCors(
      request,
      new Response(
        JSON.stringify({
          boardId,
          connections: room?.getConnectionCount() ?? 0,
          events
        }),
        {
          status: 200,
          headers: { 'Content-Type': 'application/json' }
        }
      )
    );
  }

  return withCors(
    request,
    new Response(JSON.stringify({ error: 'Unsupported method', trace_id: traceId }), {
      status: 405,
      headers: { 'Content-Type': 'application/json', Allow: 'GET, POST' }
    })
  );
}

async function handleCreatePost(request: Request, env: Env, ctx: ExecutionContext, url: URL): Promise<Response> {
  if (request.method !== 'POST') {
    return new Response(JSON.stringify({ error: 'Method not allowed' }), {
      status: 405,
      headers: { 'Content-Type': 'application/json', Allow: 'POST' }
    });
  }

  const match = url.pathname.match(/^\/boards\/([^/]+)\/posts$/);
  const boardId = decodeURIComponent(match![1]);
  const traceId = request.headers.get('cf-ray') ?? crypto.randomUUID();

  let payload: CreatePostRequest;
  try {
    payload = (await request.json()) as CreatePostRequest;
  } catch (error) {
    return new Response(JSON.stringify({ error: 'Invalid JSON body', trace_id: traceId }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  const body = payload.body?.trim();
  if (!body) {
    return new Response(JSON.stringify({ error: 'body field is required', trace_id: traceId }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  const authorInput = payload.author?.trim()?.slice(0, 64) ?? null;
  const userId = payload.userId?.trim() || null;

  let author = authorInput;
  let user: UserRecord | null = null;
  let aliasRecord: BoardAlias | null = null;
  if (userId) {
    await ensureSession(request, env, userId);
    user = await getUserById(env, userId);
    if (!user) {
      return new Response(JSON.stringify({ error: 'user not found', trace_id: traceId }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    aliasRecord = await getBoardAlias(env, boardId, userId);
    author = aliasRecord?.alias ?? author ?? user.pseudonym;
  }

  const board = await getOrCreateBoard(env, boardId);
  const post = await createPost(
    env,
    board.id,
    body,
    author,
    userId,
    aliasRecord?.alias ?? null,
    user?.pseudonym ?? null
  );

  const room = getBoardRoom(boardId);
  const eventRecord: BoardEventPayload = {
    id: post.id,
    event: 'post.created',
    data: post,
    traceId,
    timestamp: post.createdAt
  };

  room.broadcast(
    {
      type: 'event',
      event: eventRecord.event,
      data: eventRecord.data,
      eventId: eventRecord.id,
      trace_id: eventRecord.traceId,
      timestamp: eventRecord.timestamp
    },
    undefined
  );

  ctx.waitUntil(persistEvent(env, eventRecord, boardId));

  const responseBody: CreatePostResponse = { ok: true, post };
  return new Response(JSON.stringify(responseBody), {
    status: 201,
    headers: { 'Content-Type': 'application/json' }
  });
}

async function handleLinkIdentity(request: Request, env: Env): Promise<Response> {
  if (request.method !== 'POST') {
    return new Response(JSON.stringify({ error: 'Method not allowed' }), {
      status: 405,
      headers: { 'Content-Type': 'application/json', Allow: 'POST' }
    });
  }

  const principal = await verifyAccessJwt(request, env);
  if (!principal?.subject) {
    throw new ApiError(401, { error: 'access token required' });
  }

  const session = await getSessionFromRequest(request, env);
  await ensureAccessPrincipalForUser(env, principal, session.user_id, { allowReassign: true });
  const user = await getUserById(env, session.user_id);
  const responseBody = {
    ok: true,
    user: user ? userRecordToProfile(user) : undefined
  };

  return new Response(JSON.stringify(responseBody), {
    status: 200,
    headers: { 'Content-Type': 'application/json' }
  });
}

async function handleRegisterIdentity(request: Request, env: Env): Promise<Response> {
  if (request.method !== 'POST') {
    return new Response(JSON.stringify({ error: 'Method not allowed' }), {
      status: 405,
      headers: { 'Content-Type': 'application/json', Allow: 'POST' }
    });
  }

  let payload: RegisterIdentityRequest;
  try {
    payload = (await request.json()) as RegisterIdentityRequest;
  } catch (error) {
    return new Response(JSON.stringify({ error: 'Invalid JSON body' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  const raw = payload.pseudonym?.trim();
  if (!raw) {
    return new Response(JSON.stringify({ error: 'pseudonym is required' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  if (raw.length < PSEUDONYM_MIN || raw.length > PSEUDONYM_MAX) {
    return new Response(
      JSON.stringify({
        error: `pseudonym must be between ${PSEUDONYM_MIN} and ${PSEUDONYM_MAX} characters`
      }),
      {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      }
    );
  }

  const normalized = normalizeHandle(raw);
  if (!normalized) {
    return new Response(JSON.stringify({ error: 'pseudonym is invalid' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  try {
    const accessPrincipal = await verifyAccessJwt(request, env);
    const user = await createUser(env, raw, normalized);
    await ensureAccessPrincipalForUser(env, accessPrincipal, user.id, { allowReassign: true });
    const session = await issueSessionTicket(env, user.id);
    const responseBody: RegisterIdentityResponse = {
      ok: true,
      user,
      session
    };
    return new Response(JSON.stringify(responseBody), {
      status: 201,
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    if (isUniqueConstraintError(error)) {
      return new Response(JSON.stringify({ error: 'pseudonym already taken' }), {
        status: 409,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    console.error('[identity] failed to register', error);
    return new Response(JSON.stringify({ error: 'internal' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

async function handleCreateSession(request: Request, env: Env): Promise<Response> {
  if (request.method !== 'POST') {
    throw new ApiError(405, { error: 'Method not allowed' });
  }

  let payload: CreateSessionRequest;
  try {
    payload = (await request.json()) as CreateSessionRequest;
  } catch (error) {
    throw new ApiError(400, { error: 'Invalid JSON body' });
  }

  const userId = payload.userId?.trim();
  if (!userId) {
    const accessPrincipal = await verifyAccessJwt(request, env);
    if (!accessPrincipal?.subject) {
      throw new ApiError(400, { error: 'userId is required' });
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
      headers: { 'Content-Type': 'application/json' }
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
    headers: { 'Content-Type': 'application/json' }
  });
}

async function handleAlias(request: Request, env: Env, url: URL): Promise<Response> {
  if (request.method === 'GET') {
    const match = url.pathname.match(/^\/boards\/([^/]+)\/aliases$/);
    const boardId = decodeURIComponent(match![1]);
    const userId = url.searchParams.get('userId')?.trim();

    if (!userId) {
      return new Response(JSON.stringify({ error: 'userId query param is required' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    await ensureSession(request, env, userId);

    const user = await getUserById(env, userId);
    if (!user) {
      return new Response(JSON.stringify({ error: 'user not found' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    await ensureSchema(env);
    const boardExists = await env.BOARD_DB.prepare('SELECT id FROM boards WHERE id = ?1')
      .bind(boardId)
      .first<{ id: string }>();
    if (!boardExists) {
      return new Response(JSON.stringify({ error: 'board not found' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const alias = await getBoardAlias(env, boardId, userId);
    const responseBody: GetAliasResponse = {
      ok: true,
      alias: alias ?? undefined
    };

    return new Response(JSON.stringify(responseBody), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  if (request.method !== 'POST' && request.method !== 'PUT') {
    return new Response(JSON.stringify({ error: 'Method not allowed' }), {
      status: 405,
      headers: { 'Content-Type': 'application/json', Allow: 'GET, POST, PUT' }
    });
  }

  const match = url.pathname.match(/^\/boards\/([^/]+)\/aliases$/);
  const boardId = decodeURIComponent(match![1]);

  let payload: UpsertAliasRequest;
  try {
    payload = (await request.json()) as UpsertAliasRequest;
  } catch (error) {
    return new Response(JSON.stringify({ error: 'Invalid JSON body' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  const userId = payload.userId?.trim();
  const aliasRaw = payload.alias?.trim();
  if (!userId || !aliasRaw) {
    return new Response(JSON.stringify({ error: 'userId and alias are required' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  await ensureSession(request, env, userId);

  if (aliasRaw.length < ALIAS_MIN || aliasRaw.length > ALIAS_MAX) {
    return new Response(
      JSON.stringify({ error: `alias must be between ${ALIAS_MIN} and ${ALIAS_MAX} characters` }),
      {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      }
    );
  }

  const user = await getUserById(env, userId);
  if (!user) {
    return new Response(JSON.stringify({ error: 'user not found' }), {
      status: 404,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  await getOrCreateBoard(env, boardId);

  const normalized = normalizeHandle(aliasRaw);
  if (!normalized) {
    return new Response(JSON.stringify({ error: 'alias is invalid' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  try {
    const alias = await upsertBoardAlias(env, boardId, userId, aliasRaw, normalized);
    const responseBody: UpsertAliasResponse = {
      ok: true,
      alias
    };
    const status = request.method === 'POST' ? 201 : 200;
    return new Response(JSON.stringify(responseBody), {
      status,
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    if (isUniqueConstraintError(error)) {
      return new Response(JSON.stringify({ error: 'alias already in use on this board' }), {
        status: 409,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    console.error('[alias] failed to upsert', error);
    return new Response(JSON.stringify({ error: 'internal' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

async function handleUpdateReaction(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  url: URL
): Promise<Response> {
  if (request.method !== 'POST') {
    return new Response(JSON.stringify({ error: 'Method not allowed' }), {
      status: 405,
      headers: { 'Content-Type': 'application/json', Allow: 'POST' }
    });
  }

  const match = url.pathname.match(/^\/boards\/([^/]+)\/posts\/([^/]+)\/reactions$/);
  const boardId = decodeURIComponent(match![1]);
  const postId = decodeURIComponent(match![2]);
  const traceId = request.headers.get('cf-ray') ?? crypto.randomUUID();

  let payload: UpdateReactionRequest;
  try {
    payload = (await request.json()) as UpdateReactionRequest;
  } catch (error) {
    return new Response(JSON.stringify({ error: 'Invalid JSON body', trace_id: traceId }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  const userId = payload.userId?.trim();
  if (!userId) {
    return new Response(JSON.stringify({ error: 'userId is required', trace_id: traceId }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  await ensureSession(request, env, userId);

  const action = payload.action;
  if (!action || !['like', 'dislike', 'remove'].includes(action)) {
    return new Response(JSON.stringify({ error: 'action must be like, dislike, or remove', trace_id: traceId }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  const user = await getUserById(env, userId);
  if (!user) {
    return new Response(JSON.stringify({ error: 'user not found', trace_id: traceId }), {
      status: 404,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  try {
    const reactions = await applyReaction(env, boardId, postId, userId, action as ReactionAction);
    const responseBody: UpdateReactionResponse = {
      ok: true,
      boardId,
      postId,
      reactions
    };

    const room = getBoardRoom(boardId);
    const eventRecord: BoardEventPayload = {
      id: crypto.randomUUID(),
      event: 'post.reacted',
      data: {
        postId,
        boardId,
        reactions
      },
      traceId,
      timestamp: Date.now()
    };

    room.broadcast(
      {
        type: 'event',
        event: eventRecord.event,
        data: eventRecord.data,
        eventId: eventRecord.id,
        trace_id: eventRecord.traceId,
        timestamp: eventRecord.timestamp
      },
      undefined
    );

    ctx.waitUntil(persistEvent(env, eventRecord, boardId));

    return new Response(JSON.stringify(responseBody), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    console.error('[reactions] failed to update', error);
    const message = error instanceof Error ? error.message : 'internal';
    const status = message === 'Post not found' || message === 'Post does not belong to board' ? 404 : 500;
    return new Response(JSON.stringify({ error: status === 404 ? message : 'internal', trace_id: traceId }), {
      status,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

async function handleFeed(request: Request, env: Env, url: URL): Promise<Response> {
  const match = url.pathname.match(/^\/boards\/([^/]+)\/feed$/);
  const boardId = decodeURIComponent(match![1]);
  const limitParam = Number(url.searchParams.get('limit') ?? '20');
  const limit = Number.isFinite(limitParam) ? Math.max(0, Math.min(limitParam, 50)) : 20;

  const board = await getOrCreateBoard(env, boardId);
  const posts = await listPosts(env, boardId, limit);
  const room = boardRooms.get(boardId);

  const responseBody: BoardFeedResponse = {
    board: {
      id: board.id,
      displayName: board.display_name,
      description: board.description,
      createdAt: board.created_at
    },
    posts,
    realtimeConnections: room?.getConnectionCount() ?? 0
  };

  return new Response(JSON.stringify(responseBody), {
    status: 200,
    headers: { 'Content-Type': 'application/json' }
  });
}

type BoardEventRecord = BoardEventPayload & { boardId: string };

type BoardRecord = {
  id: string;
  display_name: string;
  description: string | null;
  created_at: number;
};

type PostRecord = {
  id: string;
  board_id: string;
  user_id: string | null;
  author: string | null;
  body: string;
  created_at: number;
  reaction_count: number;
  like_count: number;
  dislike_count: number;
};

type PostListRow = PostRecord & {
  board_alias: string | null;
  pseudonym: string | null;
};

type PostBoardRecord = {
  id: string;
  board_id: string;
};

type UserRecord = {
  id: string;
  pseudonym: string;
  pseudonym_normalized: string;
  created_at: number;
  status: 'active' | 'access_auto' | 'access_orphan';
};

type BoardAliasRecord = {
  id: string;
  board_id: string;
  user_id: string;
  alias: string;
  alias_normalized: string;
  created_at: number;
};

type SessionRecord = {
  token: string;
  user_id: string;
  created_at: number;
  expires_at: number;
};

function formatBoardName(boardId: string) {
  const cleaned = boardId.replace(/[-_]+/g, ' ').trim();
  if (!cleaned) return boardId;
  return cleaned
    .split(' ')
    .filter(Boolean)
    .map(word => word[0]?.toUpperCase() + word.slice(1))
    .join(' ');
}

const EVENTS_STORAGE_KEY = 'board-events';
const MAX_PERSISTED_EVENTS = 100;

export class BoardRoomDO {
  private events: BoardEventRecord[] = [];

  constructor(private readonly state: DurableObjectState) {
    this.state.blockConcurrencyWhile(async () => {
      const stored = await this.state.storage.get<BoardEventRecord[]>(EVENTS_STORAGE_KEY);
      if (stored?.length) {
        this.events = stored;
      }
    });
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const boardId = request.headers.get('CF-Board-ID') ?? this.state.id.toString();
    const traceId = request.headers.get('CF-Trace-ID') ?? crypto.randomUUID();

    if (request.headers.get('Upgrade') === 'websocket' && (url.pathname === '/connect' || url.pathname === '/boards')) {
      const socket = (request as WebSocketRequest).webSocket;
      if (!socket) {
        return new Response('Expected WebSocket upgrade.', { status: 400 });
      }

      const closePromise = this.handleDurableSocket(socket as unknown as BoardWebSocket, boardId, traceId);
      this.state.waitUntil(closePromise);

      return new Response(null, { status: 101, webSocket: socket });
    }

    if (request.method === 'POST' && url.pathname === '/broadcast') {
      let payload: any;
      try {
        payload = await request.json();
      } catch (error) {
        return new Response(JSON.stringify({ error: 'Invalid JSON payload', trace_id: traceId }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        });
      }

      const eventName = typeof payload?.event === 'string' && payload.event.trim() ? payload.event.trim() : 'message';
      const timestamp = Date.now();
      const record: BoardEventRecord = {
        id: crypto.randomUUID(),
        boardId,
        event: eventName,
        data: payload?.data ?? null,
        traceId,
        timestamp
      };

      await this.appendEvent(record);

      return new Response(JSON.stringify({ ok: true, event: record }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    if (request.method === 'GET' && url.pathname === '/state') {
      const limitParam = Number(url.searchParams.get('limit') ?? '20');
      const limit = Number.isFinite(limitParam) ? Math.max(0, Math.min(limitParam, MAX_PERSISTED_EVENTS)) : 20;
      const events = limit === 0 ? [] : this.events.slice(-limit).reverse();

      return new Response(
        JSON.stringify({
          boardId: this.state.id.toString(),
          connections: 0,
          events
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } }
      );
    }

    console.warn('[board-room-do] unmatched request', {
      url: url.toString(),
      method: request.method,
      hasUpgrade: request.headers.get('Upgrade') ?? 'none',
      traceId
    });

    return new Response(JSON.stringify({ error: 'Not Found', trace_id: traceId }), {
      status: 404,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  private handleDurableSocket(socket: BoardWebSocket, boardId: string, traceId: string) {
    socket.accept();
    const keepAlive = setInterval(() => {
      try {
        socket.send(
          JSON.stringify({
            type: 'keepalive',
            boardId,
            timestamp: Date.now()
          })
        );
      } catch {
        clearInterval(keepAlive);
      }
    }, 30_000);

    const close = () => {
      clearInterval(keepAlive);
    };

    socket.addEventListener('close', close);
    socket.addEventListener('error', close);

    socket.send(
      JSON.stringify({
        type: 'ack',
        boardId,
        connectionId: crypto.randomUUID(),
        trace_id: traceId,
        timestamp: Date.now()
      })
    );

    socket.addEventListener('message', event => {
      try {
        const payload = typeof event.data === 'string' ? JSON.parse(event.data) : event.data;
        if (payload?.type === 'ping') {
          socket.send(
            JSON.stringify({
              type: 'pong',
              boardId,
              timestamp: Date.now()
            })
          );
        }
      } catch (err) {
        console.warn('[board-room] message parse failed', err);
      }
    });

    return new Promise<void>(resolve => {
      socket.addEventListener('close', () => resolve(), { once: true });
    });
  }

  private async appendEvent(record: BoardEventRecord) {
    this.events.push(record);
    if (this.events.length > MAX_PERSISTED_EVENTS) {
      this.events.splice(0, this.events.length - MAX_PERSISTED_EVENTS);
    }
    await this.state.storage.put(EVENTS_STORAGE_KEY, this.events);
  }
}
