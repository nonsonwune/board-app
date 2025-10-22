import schemaSql from './schema.sql';
import { BoardRoom, type BoardWebSocket } from './board-room';
import type {
  BoardEventPayload,
  BoardFeedResponse,
  BoardPost as SharedBoardPost,
  BoardSummary,
  CreatePostRequest,
  CreatePostResponse,
  BoardAlias,
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
  BoardAlias
} from '@board-app/shared';

type WebSocketRequest = Request & { webSocket?: WebSocket };

export interface Env {
  BOARD_DB: D1Database;
  BOARD_ROOM_DO: DurableObjectNamespace;
}

const ALLOWED_ORIGINS = ['http://localhost:3000'];
const boardRooms = new Map<string, BoardRoom>();
let schemaInitialized = false;
let schemaInitPromise: Promise<void> | null = null;

const PSEUDONYM_MIN = 3;
const PSEUDONYM_MAX = 20;
const ALIAS_MIN = 3;
const ALIAS_MAX = 24;

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
        `ALTER TABLE posts ADD COLUMN user_id TEXT REFERENCES users(id) ON DELETE SET NULL`
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

async function createUser(env: Env, pseudonym: string, normalized: string): Promise<UserProfile> {
  await ensureSchema(env);
  const id = crypto.randomUUID();
  const createdAt = Date.now();

  await env.BOARD_DB.prepare(
    `INSERT INTO users (id, pseudonym, pseudonym_normalized, created_at)
       VALUES (?1, ?2, ?3, ?4)`
  )
    .bind(id, pseudonym, normalized, createdAt)
    .run();

  return { id, pseudonym, createdAt };
}

async function getUserById(env: Env, userId: string): Promise<UserRecord | null> {
  await ensureSchema(env);
  const record = await env.BOARD_DB.prepare(
    'SELECT id, pseudonym, pseudonym_normalized, created_at FROM users WHERE id = ?1'
  )
    .bind(userId)
    .first<UserRecord>();

  return record ?? null;
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
      if (url.pathname === '/identity/register') {
        return withCors(request, await handleRegisterIdentity(request, env));
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

export {
  ensureSchema,
  getOrCreateBoard,
  createPost,
  listPosts,
  persistEvent,
  createUser,
  upsertBoardAlias,
  applyReaction,
  getBoardAlias
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
    const user = await createUser(env, raw, normalized);
    const responseBody: RegisterIdentityResponse = {
      ok: true,
      user
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
};

type BoardAliasRecord = {
  id: string;
  board_id: string;
  user_id: string;
  alias: string;
  alias_normalized: string;
  created_at: number;
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
