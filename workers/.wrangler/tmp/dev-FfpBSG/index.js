var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// dist/index.js
var BoardRoom = class {
  static {
    __name(this, "BoardRoom");
  }
  boardId;
  now;
  keepAliveMs;
  connections = /* @__PURE__ */ new Map();
  constructor(options) {
    this.boardId = options.boardId;
    this.now = options.now ?? (() => Date.now());
    this.keepAliveMs = options.keepAliveMs ?? 3e4;
  }
  handleConnection(socket, metadata) {
    const connectionId = crypto.randomUUID();
    socket.accept();
    const keepAliveHandle = this.startKeepAlive(connectionId, socket, metadata);
    this.connections.set(connectionId, { socket, metadata, keepAliveHandle });
    socket.addEventListener("message", (event) => {
      this.onMessage(connectionId, event);
    });
    socket.addEventListener("error", () => {
      this.disconnect(connectionId, 1011, "socket error");
    });
    socket.addEventListener("close", () => {
      this.disconnect(connectionId, void 0, void 0, { fromRemote: true });
    });
    this.send(socket, {
      type: "ack",
      boardId: metadata.boardId,
      connectionId,
      trace_id: metadata.traceId,
      timestamp: this.now()
    });
    return new Promise((resolve) => {
      const finalise = /* @__PURE__ */ __name(() => resolve(), "finalise");
      socket.addEventListener("close", finalise);
    });
  }
  getConnectionCount() {
    return this.connections.size;
  }
  broadcast(message, excludeConnectionId) {
    for (const [connectionId, entry] of this.connections.entries()) {
      if (connectionId === excludeConnectionId) {
        continue;
      }
      this.send(entry.socket, {
        boardId: entry.metadata.boardId,
        ...message
      });
    }
  }
  onMessage(connectionId, event) {
    const entry = this.connections.get(connectionId);
    if (!entry) {
      return;
    }
    const { socket, metadata } = entry;
    const text = this.decodeMessage(event.data);
    if (!text) {
      this.sendError(socket, metadata.boardId, "unsupported payload");
      return;
    }
    let payload;
    try {
      payload = JSON.parse(text);
    } catch {
      this.sendError(socket, metadata.boardId, "invalid JSON payload");
      return;
    }
    switch (payload?.type) {
      case "ping": {
        this.send(socket, {
          type: "pong",
          boardId: metadata.boardId,
          timestamp: this.now()
        });
        if (payload.closeAfterPong) {
          this.disconnect(connectionId, 1e3, "pong complete");
        }
        return;
      }
      case "broadcast": {
        this.broadcast(
          {
            type: "event",
            trace_id: metadata.traceId,
            origin: connectionId,
            event: payload.event ?? "message",
            data: payload.data ?? null,
            timestamp: this.now()
          },
          payload.echoSelf ? void 0 : connectionId
        );
        return;
      }
      default: {
        this.sendError(socket, metadata.boardId, "unknown message type");
      }
    }
  }
  disconnect(connectionId, code, reason, options = {}) {
    const entry = this.connections.get(connectionId);
    if (!entry) {
      return;
    }
    if (entry.keepAliveHandle) {
      clearInterval(entry.keepAliveHandle);
    }
    this.connections.delete(connectionId);
    if (!options.fromRemote) {
      try {
        entry.socket.close(code, reason);
      } catch (error) {
        console.warn(`[board-room:${this.boardId}] close failed`, error);
      }
    }
  }
  startKeepAlive(connectionId, socket, metadata) {
    if (this.keepAliveMs <= 0) {
      return null;
    }
    const handle = setInterval(() => {
      try {
        this.send(socket, {
          type: "keepalive",
          boardId: metadata.boardId,
          timestamp: this.now()
        });
      } catch (error) {
        console.warn(`[board-room:${this.boardId}] keepalive failed`, error);
        this.disconnect(connectionId, 1011, "keepalive failure");
      }
    }, this.keepAliveMs);
    return handle;
  }
  send(socket, payload) {
    socket.send(JSON.stringify(payload));
  }
  sendError(socket, boardId, message) {
    this.send(socket, {
      type: "error",
      boardId,
      message,
      timestamp: this.now()
    });
  }
  decodeMessage(data) {
    if (typeof data === "string") {
      return data;
    }
    if (data instanceof ArrayBuffer) {
      return new TextDecoder().decode(data);
    }
    if (ArrayBuffer.isView(data)) {
      return new TextDecoder().decode(data.buffer);
    }
    return null;
  }
};
var schema_default = "CREATE TABLE IF NOT EXISTS boards (\n  id TEXT PRIMARY KEY,\n  display_name TEXT NOT NULL,\n  description TEXT,\n  created_at INTEGER NOT NULL\n);\nCREATE TABLE IF NOT EXISTS posts (\n  id TEXT PRIMARY KEY,\n  board_id TEXT NOT NULL REFERENCES boards(id) ON DELETE CASCADE,\n  author TEXT,\n  body TEXT NOT NULL,\n  created_at INTEGER NOT NULL,\n  reaction_count INTEGER NOT NULL DEFAULT 0\n);\nCREATE INDEX IF NOT EXISTS posts_board_created_at_idx ON posts (board_id, created_at DESC);\nCREATE TABLE IF NOT EXISTS board_events (\n  id TEXT PRIMARY KEY,\n  board_id TEXT NOT NULL,\n  event_type TEXT NOT NULL,\n  payload TEXT NOT NULL,\n  trace_id TEXT NOT NULL,\n  created_at INTEGER NOT NULL\n);\nCREATE INDEX IF NOT EXISTS board_events_board_created_at_idx ON board_events (board_id, created_at DESC);\n";
var ALLOWED_ORIGINS = ["http://localhost:3000"];
var boardRooms = /* @__PURE__ */ new Map();
var schemaInitialized = false;
function allowOrigin(origin) {
  if (!origin) return "*";
  return ALLOWED_ORIGINS.includes(origin) ? origin : "*";
}
__name(allowOrigin, "allowOrigin");
function withCors(req, res) {
  const origin = allowOrigin(req.headers.get("Origin"));
  const headers = new Headers(res.headers);
  headers.set("Access-Control-Allow-Origin", origin);
  headers.set("Access-Control-Allow-Headers", "Content-Type, Authorization");
  headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  headers.set("Vary", "Origin");
  return new Response(res.body, {
    status: res.status,
    statusText: res.statusText,
    headers
  });
}
__name(withCors, "withCors");
function __resetSchemaForTests() {
  schemaInitialized = false;
}
__name(__resetSchemaForTests, "__resetSchemaForTests");
async function ensureSchema(env) {
  if (schemaInitialized) return;
  const statements = schema_default.split(";").map((stmt) => stmt.trim()).filter(Boolean).map((stmt) => `${stmt};`);
  for (const sql of statements) {
    console.log("[schema] exec", sql);
    await env.BOARD_DB.exec(sql);
  }
  schemaInitialized = true;
}
__name(ensureSchema, "ensureSchema");
function getBoardRoom(boardId) {
  let room = boardRooms.get(boardId);
  if (!room) {
    room = new BoardRoom({ boardId });
    boardRooms.set(boardId, room);
  }
  return room;
}
__name(getBoardRoom, "getBoardRoom");
async function persistEvent(env, record, boardId) {
  await ensureSchema(env);
  await env.BOARD_DB.prepare(
    `INSERT INTO board_events (id, board_id, event_type, payload, trace_id, created_at)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6)`
  ).bind(
    record.id,
    boardId,
    record.event ?? "message",
    JSON.stringify(record.data ?? null),
    record.traceId ?? "unknown",
    record.timestamp ?? Date.now()
  ).run();
}
__name(persistEvent, "persistEvent");
async function getOrCreateBoard(env, boardId) {
  await ensureSchema(env);
  const existing = await env.BOARD_DB.prepare(
    "SELECT id, display_name, description, created_at FROM boards WHERE id = ?1"
  ).bind(boardId).first();
  if (existing) {
    return existing;
  }
  const createdAt = Date.now();
  const displayName = formatBoardName(boardId);
  await env.BOARD_DB.prepare(
    "INSERT INTO boards (id, display_name, description, created_at) VALUES (?1, ?2, ?3, ?4)"
  ).bind(boardId, displayName, null, createdAt).run();
  return {
    id: boardId,
    display_name: displayName,
    description: null,
    created_at: createdAt
  };
}
__name(getOrCreateBoard, "getOrCreateBoard");
async function createPost(env, boardId, body, author) {
  await ensureSchema(env);
  const id = crypto.randomUUID();
  const createdAt = Date.now();
  await env.BOARD_DB.prepare(
    "INSERT INTO posts (id, board_id, author, body, created_at) VALUES (?1, ?2, ?3, ?4, ?5)"
  ).bind(id, boardId, author ?? null, body, createdAt).run();
  return {
    id,
    boardId,
    author: author ?? null,
    body,
    createdAt,
    reactionCount: 0
  };
}
__name(createPost, "createPost");
async function listPosts(env, boardId, limit) {
  await ensureSchema(env);
  const { results } = await env.BOARD_DB.prepare(
    `SELECT id, board_id, author, body, created_at, reaction_count
       FROM posts
       WHERE board_id = ?1
       ORDER BY created_at DESC
       LIMIT ?2`
  ).bind(boardId, limit).all();
  return (results ?? []).map((row) => ({
    id: row.id,
    boardId: row.board_id,
    author: row.author,
    body: row.body,
    createdAt: row.created_at,
    reactionCount: row.reaction_count
  }));
}
__name(listPosts, "listPosts");
var index_default = {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname === "/_health") {
      return new Response("ok", { status: 200 });
    }
    if (request.method === "OPTIONS") {
      return withCors(request, new Response(null, { status: 204 }));
    }
    try {
      const upgradeHeader = request.headers.get("Upgrade");
      if (url.pathname === "/boards" && upgradeHeader === "websocket") {
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
      return withCors(request, new Response("Not Found", { status: 404 }));
    } catch (error) {
      console.error("[worker] unexpected error", error);
      return withCors(
        request,
        new Response(JSON.stringify({ error: "internal" }), {
          status: 500,
          headers: { "Content-Type": "application/json" }
        })
      );
    }
  }
};
async function handleWebsocket(request, env, ctx, url) {
  const boardId = url.searchParams.get("boardId");
  if (!boardId) {
    return withCors(
      request,
      new Response(JSON.stringify({ error: "boardId query param required" }), {
        status: 400,
        headers: { "Content-Type": "application/json" }
      })
    );
  }
  const room = getBoardRoom(boardId);
  const traceId = request.headers.get("cf-ray") ?? crypto.randomUUID();
  const pair = new WebSocketPair();
  const client = pair[0];
  const server = pair[1];
  const closePromise = room.handleConnection(server, {
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
__name(handleWebsocket, "handleWebsocket");
async function handleEvents(request, env, ctx, url) {
  const match = url.pathname.match(/^\/boards\/([^/]+)\/events$/);
  const boardId = decodeURIComponent(match[1]);
  const traceId = request.headers.get("cf-ray") ?? crypto.randomUUID();
  const durableId = env.BOARD_ROOM_DO.idFromName(boardId);
  const stub = env.BOARD_ROOM_DO.get(durableId);
  if (request.method === "POST") {
    let payload;
    try {
      payload = await request.json();
    } catch (error) {
      return withCors(
        request,
        new Response(JSON.stringify({ error: "Invalid JSON body", trace_id: traceId }), {
          status: 400,
          headers: { "Content-Type": "application/json" }
        })
      );
    }
    const response = await stub.fetch("https://board-room.internal/broadcast", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "CF-Board-ID": boardId,
        "CF-Trace-ID": traceId
      },
      body: JSON.stringify(payload)
    });
    const bodyText = await response.text();
    if (response.ok) {
      try {
        const parsed = JSON.parse(bodyText);
        const record = parsed.event;
        if (record) {
          const room = getBoardRoom(boardId);
          room.broadcast(
            {
              type: "event",
              event: record.event,
              data: record.data,
              eventId: record.id,
              trace_id: record.traceId,
              timestamp: record.timestamp
            },
            void 0
          );
          ctx.waitUntil(persistEvent(env, record, boardId));
        }
      } catch (error) {
        console.warn("[worker] failed to parse broadcast response", error);
      }
    }
    return withCors(
      request,
      new Response(bodyText, {
        status: response.status,
        headers: { "Content-Type": "application/json" }
      })
    );
  }
  if (request.method === "GET") {
    const limitParam = Number(url.searchParams.get("limit") ?? "20");
    const limit = Number.isFinite(limitParam) ? Math.max(0, Math.min(limitParam, 100)) : 20;
    await ensureSchema(env);
    const { results } = await env.BOARD_DB.prepare(
      `SELECT id, event_type, payload, trace_id, created_at FROM board_events
         WHERE board_id = ?1
         ORDER BY created_at DESC
         LIMIT ?2`
    ).bind(boardId, limit).all();
    const events = (results ?? []).map((row) => {
      let data = null;
      try {
        data = row.payload ? JSON.parse(row.payload) : null;
      } catch (error) {
        console.warn("[worker] failed to parse stored payload", error);
      }
      return {
        id: row.id,
        boardId,
        event: row.event_type,
        data,
        traceId: row.trace_id,
        timestamp: row.created_at
      };
    }).reverse();
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
          headers: { "Content-Type": "application/json" }
        }
      )
    );
  }
  return withCors(
    request,
    new Response(JSON.stringify({ error: "Unsupported method", trace_id: traceId }), {
      status: 405,
      headers: { "Content-Type": "application/json", Allow: "GET, POST" }
    })
  );
}
__name(handleEvents, "handleEvents");
async function handleCreatePost(request, env, ctx, url) {
  if (request.method !== "POST") {
    return new Response(JSON.stringify({ error: "Method not allowed" }), {
      status: 405,
      headers: { "Content-Type": "application/json", Allow: "POST" }
    });
  }
  const match = url.pathname.match(/^\/boards\/([^/]+)\/posts$/);
  const boardId = decodeURIComponent(match[1]);
  const traceId = request.headers.get("cf-ray") ?? crypto.randomUUID();
  let payload;
  try {
    payload = await request.json();
  } catch (error) {
    return new Response(JSON.stringify({ error: "Invalid JSON body", trace_id: traceId }), {
      status: 400,
      headers: { "Content-Type": "application/json" }
    });
  }
  const body = payload.body?.trim();
  if (!body) {
    return new Response(JSON.stringify({ error: "body field is required", trace_id: traceId }), {
      status: 400,
      headers: { "Content-Type": "application/json" }
    });
  }
  const author = payload.author?.trim()?.slice(0, 64) ?? null;
  const board = await getOrCreateBoard(env, boardId);
  const post = await createPost(env, board.id, body, author);
  const room = getBoardRoom(boardId);
  const eventRecord = {
    id: post.id,
    event: "post.created",
    data: post,
    traceId,
    timestamp: post.createdAt
  };
  room.broadcast(
    {
      type: "event",
      event: eventRecord.event,
      data: eventRecord.data,
      eventId: eventRecord.id,
      trace_id: eventRecord.traceId,
      timestamp: eventRecord.timestamp
    },
    void 0
  );
  ctx.waitUntil(persistEvent(env, eventRecord, boardId));
  const responseBody = { ok: true, post };
  return new Response(JSON.stringify(responseBody), {
    status: 201,
    headers: { "Content-Type": "application/json" }
  });
}
__name(handleCreatePost, "handleCreatePost");
async function handleFeed(request, env, url) {
  const match = url.pathname.match(/^\/boards\/([^/]+)\/feed$/);
  const boardId = decodeURIComponent(match[1]);
  const limitParam = Number(url.searchParams.get("limit") ?? "20");
  const limit = Number.isFinite(limitParam) ? Math.max(0, Math.min(limitParam, 50)) : 20;
  const board = await getOrCreateBoard(env, boardId);
  const posts = await listPosts(env, boardId, limit);
  const room = boardRooms.get(boardId);
  const responseBody = {
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
    headers: { "Content-Type": "application/json" }
  });
}
__name(handleFeed, "handleFeed");
function formatBoardName(boardId) {
  const cleaned = boardId.replace(/[-_]+/g, " ").trim();
  if (!cleaned) return boardId;
  return cleaned.split(" ").filter(Boolean).map((word) => word[0]?.toUpperCase() + word.slice(1)).join(" ");
}
__name(formatBoardName, "formatBoardName");
var BoardRoomDO = class {
  static {
    __name(this, "BoardRoomDO");
  }
  constructor(state) {
    this.state = state;
    this.state.blockConcurrencyWhile(async () => {
      const stored = await this.state.storage.get(EVENTS_STORAGE_KEY);
      if (stored?.length) {
        this.events = stored;
      }
    });
  }
  events = [];
  async fetch(request) {
    const url = new URL(request.url);
    const boardId = request.headers.get("CF-Board-ID") ?? this.state.id.toString();
    const traceId = request.headers.get("CF-Trace-ID") ?? crypto.randomUUID();
    if (request.method === "POST" && url.pathname === "/broadcast") {
      let payload;
      try {
        payload = await request.json();
      } catch (error) {
        return new Response(JSON.stringify({ error: "Invalid JSON payload", trace_id: traceId }), {
          status: 400,
          headers: { "Content-Type": "application/json" }
        });
      }
      const eventName = typeof payload?.event === "string" && payload.event.trim() ? payload.event.trim() : "message";
      const timestamp = Date.now();
      const record = {
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
        headers: { "Content-Type": "application/json" }
      });
    }
    if (request.method === "GET" && url.pathname === "/state") {
      const limitParam = Number(url.searchParams.get("limit") ?? "20");
      const limit = Number.isFinite(limitParam) ? Math.max(0, Math.min(limitParam, MAX_PERSISTED_EVENTS)) : 20;
      const events = limit === 0 ? [] : this.events.slice(-limit).reverse();
      return new Response(
        JSON.stringify({
          boardId: this.state.id.toString(),
          connections: 0,
          events
        }),
        { status: 200, headers: { "Content-Type": "application/json" } }
      );
    }
    console.warn("[board-room-do] unmatched request", {
      url: url.toString(),
      method: request.method,
      hasUpgrade: request.headers.get("Upgrade") ?? "none",
      traceId
    });
    return new Response(JSON.stringify({ error: "Not Found", trace_id: traceId }), {
      status: 404,
      headers: { "Content-Type": "application/json" }
    });
  }
  async appendEvent(record) {
    this.events.push(record);
    if (this.events.length > MAX_PERSISTED_EVENTS) {
      this.events.splice(0, this.events.length - MAX_PERSISTED_EVENTS);
    }
    await this.state.storage.put(EVENTS_STORAGE_KEY, this.events);
  }
};
var EVENTS_STORAGE_KEY = "board-events";
var MAX_PERSISTED_EVENTS = 100;

// ../node_modules/.pnpm/wrangler@4.44.0_@cloudflare+workers-types@4.20251014.0/node_modules/wrangler/templates/middleware/middleware-ensure-req-body-drained.ts
var drainBody = /* @__PURE__ */ __name(async (request, env, _ctx, middlewareCtx) => {
  try {
    return await middlewareCtx.next(request, env);
  } finally {
    try {
      if (request.body !== null && !request.bodyUsed) {
        const reader = request.body.getReader();
        while (!(await reader.read()).done) {
        }
      }
    } catch (e) {
      console.error("Failed to drain the unused request body.", e);
    }
  }
}, "drainBody");
var middleware_ensure_req_body_drained_default = drainBody;

// ../node_modules/.pnpm/wrangler@4.44.0_@cloudflare+workers-types@4.20251014.0/node_modules/wrangler/templates/middleware/middleware-miniflare3-json-error.ts
function reduceError(e) {
  return {
    name: e?.name,
    message: e?.message ?? String(e),
    stack: e?.stack,
    cause: e?.cause === void 0 ? void 0 : reduceError(e.cause)
  };
}
__name(reduceError, "reduceError");
var jsonError = /* @__PURE__ */ __name(async (request, env, _ctx, middlewareCtx) => {
  try {
    return await middlewareCtx.next(request, env);
  } catch (e) {
    const error = reduceError(e);
    return Response.json(error, {
      status: 500,
      headers: { "MF-Experimental-Error-Stack": "true" }
    });
  }
}, "jsonError");
var middleware_miniflare3_json_error_default = jsonError;

// .wrangler/tmp/bundle-a05v49/middleware-insertion-facade.js
var __INTERNAL_WRANGLER_MIDDLEWARE__ = [
  middleware_ensure_req_body_drained_default,
  middleware_miniflare3_json_error_default
];
var middleware_insertion_facade_default = index_default;

// ../node_modules/.pnpm/wrangler@4.44.0_@cloudflare+workers-types@4.20251014.0/node_modules/wrangler/templates/middleware/common.ts
var __facade_middleware__ = [];
function __facade_register__(...args) {
  __facade_middleware__.push(...args.flat());
}
__name(__facade_register__, "__facade_register__");
function __facade_invokeChain__(request, env, ctx, dispatch, middlewareChain) {
  const [head, ...tail] = middlewareChain;
  const middlewareCtx = {
    dispatch,
    next(newRequest, newEnv) {
      return __facade_invokeChain__(newRequest, newEnv, ctx, dispatch, tail);
    }
  };
  return head(request, env, ctx, middlewareCtx);
}
__name(__facade_invokeChain__, "__facade_invokeChain__");
function __facade_invoke__(request, env, ctx, dispatch, finalMiddleware) {
  return __facade_invokeChain__(request, env, ctx, dispatch, [
    ...__facade_middleware__,
    finalMiddleware
  ]);
}
__name(__facade_invoke__, "__facade_invoke__");

// .wrangler/tmp/bundle-a05v49/middleware-loader.entry.ts
var __Facade_ScheduledController__ = class ___Facade_ScheduledController__ {
  constructor(scheduledTime, cron, noRetry) {
    this.scheduledTime = scheduledTime;
    this.cron = cron;
    this.#noRetry = noRetry;
  }
  static {
    __name(this, "__Facade_ScheduledController__");
  }
  #noRetry;
  noRetry() {
    if (!(this instanceof ___Facade_ScheduledController__)) {
      throw new TypeError("Illegal invocation");
    }
    this.#noRetry();
  }
};
function wrapExportedHandler(worker) {
  if (__INTERNAL_WRANGLER_MIDDLEWARE__ === void 0 || __INTERNAL_WRANGLER_MIDDLEWARE__.length === 0) {
    return worker;
  }
  for (const middleware of __INTERNAL_WRANGLER_MIDDLEWARE__) {
    __facade_register__(middleware);
  }
  const fetchDispatcher = /* @__PURE__ */ __name(function(request, env, ctx) {
    if (worker.fetch === void 0) {
      throw new Error("Handler does not export a fetch() function.");
    }
    return worker.fetch(request, env, ctx);
  }, "fetchDispatcher");
  return {
    ...worker,
    fetch(request, env, ctx) {
      const dispatcher = /* @__PURE__ */ __name(function(type, init) {
        if (type === "scheduled" && worker.scheduled !== void 0) {
          const controller = new __Facade_ScheduledController__(
            Date.now(),
            init.cron ?? "",
            () => {
            }
          );
          return worker.scheduled(controller, env, ctx);
        }
      }, "dispatcher");
      return __facade_invoke__(request, env, ctx, dispatcher, fetchDispatcher);
    }
  };
}
__name(wrapExportedHandler, "wrapExportedHandler");
function wrapWorkerEntrypoint(klass) {
  if (__INTERNAL_WRANGLER_MIDDLEWARE__ === void 0 || __INTERNAL_WRANGLER_MIDDLEWARE__.length === 0) {
    return klass;
  }
  for (const middleware of __INTERNAL_WRANGLER_MIDDLEWARE__) {
    __facade_register__(middleware);
  }
  return class extends klass {
    #fetchDispatcher = /* @__PURE__ */ __name((request, env, ctx) => {
      this.env = env;
      this.ctx = ctx;
      if (super.fetch === void 0) {
        throw new Error("Entrypoint class does not define a fetch() function.");
      }
      return super.fetch(request);
    }, "#fetchDispatcher");
    #dispatcher = /* @__PURE__ */ __name((type, init) => {
      if (type === "scheduled" && super.scheduled !== void 0) {
        const controller = new __Facade_ScheduledController__(
          Date.now(),
          init.cron ?? "",
          () => {
          }
        );
        return super.scheduled(controller);
      }
    }, "#dispatcher");
    fetch(request) {
      return __facade_invoke__(
        request,
        this.env,
        this.ctx,
        this.#dispatcher,
        this.#fetchDispatcher
      );
    }
  };
}
__name(wrapWorkerEntrypoint, "wrapWorkerEntrypoint");
var WRAPPED_ENTRY;
if (typeof middleware_insertion_facade_default === "object") {
  WRAPPED_ENTRY = wrapExportedHandler(middleware_insertion_facade_default);
} else if (typeof middleware_insertion_facade_default === "function") {
  WRAPPED_ENTRY = wrapWorkerEntrypoint(middleware_insertion_facade_default);
}
var middleware_loader_entry_default = WRAPPED_ENTRY;
export {
  BoardRoomDO,
  __INTERNAL_WRANGLER_MIDDLEWARE__,
  __resetSchemaForTests,
  middleware_loader_entry_default as default
};
//# sourceMappingURL=index.js.map
