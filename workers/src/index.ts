import { BoardRoom, type BoardWebSocket } from './board-room';
import schemaSql from './schema.sql?raw';
import type {
  BoardEventPayload,
  BoardFeedResponse,
  BoardPost as SharedBoardPost,
  BoardSummary,
  CreatePostRequest,
  CreatePostResponse
} from '@board-app/shared';

export interface Env {
  BOARD_DB: D1Database;
  BOARD_ROOM_DO: DurableObjectNamespace;
}

const ALLOWED_ORIGINS = ['http://localhost:3000'];
const boardRooms = new Map<string, BoardRoom>();
let schemaInitialized = false;

function allowOrigin(origin: string | null) {
  if (!origin) return '*';
  return ALLOWED_ORIGINS.includes(origin) ? origin : '*';
}

function withCors(req: Request, res: Response) {
  const origin = allowOrigin(req.headers.get('Origin'));
  const headers = new Headers(res.headers);
  headers.set('Access-Control-Allow-Origin', origin);
  headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  headers.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  headers.set('Vary', 'Origin');
  return new Response(res.body, {
    status: res.status,
    statusText: res.statusText,
    headers
  });
}

export function __resetSchemaForTests() {
  schemaInitialized = false;
}

async function ensureSchema(env: Env) {
  if (schemaInitialized) return;
  const statements = schemaSql
    .split(';')
    .map(stmt => stmt.trim())
    .filter(Boolean)
    .map(stmt => `${stmt};`);

  for (const sql of statements) {
    console.log('[schema] exec', sql);
    await env.BOARD_DB.exec(sql);
  }

  schemaInitialized = true;
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

async function createPost(env: Env, boardId: string, body: string, author?: string | null): Promise<SharedBoardPost> {
  await ensureSchema(env);
  const id = crypto.randomUUID();
  const createdAt = Date.now();
  await env.BOARD_DB.prepare(
    'INSERT INTO posts (id, board_id, author, body, created_at) VALUES (?1, ?2, ?3, ?4, ?5)'
  )
    .bind(id, boardId, author ?? null, body, createdAt)
    .run();

  return {
    id,
    boardId,
    author: author ?? null,
    body,
    createdAt,
    reactionCount: 0
  };
}

async function listPosts(env: Env, boardId: string, limit: number): Promise<SharedBoardPost[]> {
  await ensureSchema(env);
  const { results } = await env.BOARD_DB.prepare(
    `SELECT id, board_id, author, body, created_at, reaction_count
       FROM posts
       WHERE board_id = ?1
       ORDER BY created_at DESC
       LIMIT ?2`
  )
    .bind(boardId, limit)
    .all<PostRecord>();

  return (results ?? []).map(row => ({
    id: row.id,
    boardId: row.board_id,
    author: row.author,
    body: row.body,
    createdAt: row.created_at,
    reactionCount: row.reaction_count
  }));
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === '/_health') {
      return new Response('ok', { status: 200 });
    }

    if (request.method === 'OPTIONS') {
      return withCors(request, new Response(null, { status: 204 }));
    }

    try {
      const upgradeHeader = request.headers.get('Upgrade');
      if (url.pathname === '/boards' && upgradeHeader === 'websocket') {
        return handleWebsocket(request, env, ctx, url);
      }

      if (url.pathname.match(/^\/boards\/[^/]+\/events$/)) {
        return await handleEvents(request, env, ctx, url);
      }

      if (url.pathname.match(/^\/boards\/[^/]+\/posts$/)) {
        return withCors(request, await handleCreatePost(request, env, ctx, url));
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

  ctx.waitUntil(
    closePromise.then(() => {
      if (room.getConnectionCount() === 0) {
        boardRooms.delete(boardId);
      }
    })
  );

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

  const author = payload.author?.trim()?.slice(0, 64) ?? null;
  const board = await getOrCreateBoard(env, boardId);
  const post = await createPost(env, board.id, body, author);

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
  author: string | null;
  body: string;
  created_at: number;
  reaction_count: number;
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

  private async appendEvent(record: BoardEventRecord) {
    this.events.push(record);
    if (this.events.length > MAX_PERSISTED_EVENTS) {
      this.events.splice(0, this.events.length - MAX_PERSISTED_EVENTS);
    }
    await this.state.storage.put(EVENTS_STORAGE_KEY, this.events);
  }
}

const EVENTS_STORAGE_KEY = 'board-events';
const MAX_PERSISTED_EVENTS = 100;
