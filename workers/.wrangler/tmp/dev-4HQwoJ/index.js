var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// dist/index.js
var schema_default = "CREATE TABLE IF NOT EXISTS boards (\n  id TEXT PRIMARY KEY,\n  display_name TEXT NOT NULL,\n  description TEXT,\n  created_at INTEGER NOT NULL\n);\nCREATE TABLE IF NOT EXISTS posts (\n  id TEXT PRIMARY KEY,\n  board_id TEXT NOT NULL REFERENCES boards(id) ON DELETE CASCADE,\n  user_id TEXT REFERENCES users(id) ON DELETE SET NULL,\n  author TEXT,\n  body TEXT NOT NULL,\n  created_at INTEGER NOT NULL,\n  reaction_count INTEGER NOT NULL DEFAULT 0,\n  like_count INTEGER NOT NULL DEFAULT 0,\n  dislike_count INTEGER NOT NULL DEFAULT 0\n);\nCREATE INDEX IF NOT EXISTS posts_board_created_at_idx ON posts (board_id, created_at DESC);\nCREATE TABLE IF NOT EXISTS board_events (\n  id TEXT PRIMARY KEY,\n  board_id TEXT NOT NULL,\n  event_type TEXT NOT NULL,\n  payload TEXT NOT NULL,\n  trace_id TEXT NOT NULL,\n  created_at INTEGER NOT NULL\n);\nCREATE INDEX IF NOT EXISTS board_events_board_created_at_idx ON board_events (board_id, created_at DESC);\nCREATE TABLE IF NOT EXISTS sessions (\n  token TEXT PRIMARY KEY,\n  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,\n  created_at INTEGER NOT NULL,\n  expires_at INTEGER NOT NULL\n);\nCREATE INDEX IF NOT EXISTS sessions_user_expires_idx ON sessions (user_id, expires_at DESC);\nCREATE TABLE IF NOT EXISTS users (\n  id TEXT PRIMARY KEY,\n  pseudonym TEXT NOT NULL UNIQUE,\n  pseudonym_normalized TEXT NOT NULL UNIQUE,\n  created_at INTEGER NOT NULL,\n  status TEXT NOT NULL DEFAULT 'active'\n);\nCREATE TABLE IF NOT EXISTS user_access_links (\n  access_subject TEXT PRIMARY KEY,\n  user_id TEXT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,\n  email TEXT,\n  created_at INTEGER NOT NULL,\n  updated_at INTEGER NOT NULL\n);\nCREATE TABLE IF NOT EXISTS board_aliases (\n  id TEXT PRIMARY KEY,\n  board_id TEXT NOT NULL,\n  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,\n  alias TEXT NOT NULL,\n  alias_normalized TEXT NOT NULL,\n  created_at INTEGER NOT NULL,\n  UNIQUE(board_id, alias_normalized),\n  UNIQUE(board_id, user_id)\n);\nCREATE TABLE IF NOT EXISTS reactions (\n  id TEXT PRIMARY KEY,\n  post_id TEXT NOT NULL REFERENCES posts(id) ON DELETE CASCADE,\n  board_id TEXT NOT NULL,\n  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,\n  reaction INTEGER NOT NULL,\n  created_at INTEGER NOT NULL,\n  UNIQUE(post_id, user_id)\n);\n";
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
      const payload = {
        boardId: entry.metadata.boardId,
        ...message
      };
      const serialized = JSON.stringify(payload);
      setTimeout(() => {
        try {
          entry.socket.send(serialized);
        } catch (error) {
          console.warn(`[board-room:${this.boardId}] broadcast failed`, error);
          this.disconnect(connectionId, 1011, "broadcast failure");
        }
      }, 0);
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
var SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1e3;
var ALLOWED_ORIGINS = ["http://localhost:3000", "http://127.0.0.1:3000", "http://localhost:3002"];
var boardRooms = /* @__PURE__ */ new Map();
var schemaInitialized = false;
var schemaInitPromise = null;
var PSEUDONYM_MIN = 3;
var PSEUDONYM_MAX = 20;
var ALIAS_MIN = 3;
var ALIAS_MAX = 24;
var JWKS_CACHE_TTL_MS = 5 * 60 * 1e3;
var textEncoder = new TextEncoder();
var jwksCache = /* @__PURE__ */ new Map();
var cryptoKeyCache = /* @__PURE__ */ new Map();
var ApiError = class extends Error {
  static {
    __name(this, "ApiError");
  }
  status;
  body;
  constructor(status, body) {
    super(typeof body.error === "string" ? body.error : "error");
    this.status = status;
    this.body = body;
  }
};
function allowOrigin(origin) {
  if (!origin) return "*";
  return ALLOWED_ORIGINS.includes(origin) ? origin : "*";
}
__name(allowOrigin, "allowOrigin");
function normalizeHandle(value) {
  return value.trim().toLowerCase().replace(/\s+/g, " ");
}
__name(normalizeHandle, "normalizeHandle");
function isUniqueConstraintError(error) {
  return error instanceof Error && /UNIQUE constraint failed/i.test(error.message ?? "");
}
__name(isUniqueConstraintError, "isUniqueConstraintError");
function parseBearerToken(request) {
  const header = request.headers.get("Authorization") ?? request.headers.get("authorization");
  if (!header) return null;
  const match = header.match(/^Bearer\s+(.+)$/i);
  return match ? match[1].trim() : null;
}
__name(parseBearerToken, "parseBearerToken");
function withCors(request, response) {
  const origin = allowOrigin(request.headers.get("Origin"));
  const headers = new Headers(response.headers);
  headers.set("Access-Control-Allow-Origin", origin);
  headers.set("Access-Control-Allow-Headers", "Content-Type, Authorization");
  headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  headers.set("Vary", "Origin");
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers
  });
}
__name(withCors, "withCors");
function __resetSchemaForTests() {
  schemaInitialized = false;
  schemaInitPromise = null;
}
__name(__resetSchemaForTests, "__resetSchemaForTests");
function getAccessJwtConfig(env) {
  const issuer = env.ACCESS_JWT_ISSUER?.trim();
  const audience = env.ACCESS_JWT_AUDIENCE?.trim();
  if (!issuer || !audience) {
    return null;
  }
  const jwksUrl = env.ACCESS_JWT_JWKS_URL?.trim();
  return { issuer, audience, jwksUrl: jwksUrl || void 0 };
}
__name(getAccessJwtConfig, "getAccessJwtConfig");
function base64UrlToBase64(input) {
  const padded = input.padEnd(Math.ceil(input.length / 4) * 4, "=");
  return padded.replace(/-/g, "+").replace(/_/g, "/");
}
__name(base64UrlToBase64, "base64UrlToBase64");
function decodeJwtSegment(segment) {
  const base64 = base64UrlToBase64(segment);
  try {
    const json = atob(base64);
    return JSON.parse(json);
  } catch (error) {
    throw new ApiError(401, { error: "invalid access token" });
  }
}
__name(decodeJwtSegment, "decodeJwtSegment");
function base64UrlToUint8Array(segment) {
  const base64 = base64UrlToBase64(segment);
  const binary = atob(base64);
  const array = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    array[i] = binary.charCodeAt(i);
  }
  return array;
}
__name(base64UrlToUint8Array, "base64UrlToUint8Array");
async function fetchJwks(config) {
  const jwksEndpoint = config.jwksUrl ?? `${config.issuer.replace(/\/$/, "")}/cdn-cgi/access/certs`;
  const cached = jwksCache.get(jwksEndpoint);
  const now = Date.now();
  if (cached && now - cached.fetchedAt < JWKS_CACHE_TTL_MS) {
    return cached.keys;
  }
  const res = await fetch(jwksEndpoint, { cf: { cacheEverything: false } });
  if (!res.ok) {
    throw new ApiError(500, { error: "failed to load access keys" });
  }
  let body;
  try {
    body = await res.json();
  } catch (error) {
    throw new ApiError(500, { error: "invalid access keys response" });
  }
  if (!Array.isArray(body.keys) || body.keys.length === 0) {
    throw new ApiError(500, { error: "no access keys available" });
  }
  jwksCache.set(jwksEndpoint, { keys: body.keys, fetchedAt: now });
  return body.keys;
}
__name(fetchJwks, "fetchJwks");
async function getCryptoKeyFromJwks(config, header) {
  const kid = header.kid;
  if (!kid) {
    throw new ApiError(401, { error: "invalid access token header" });
  }
  const jwks = await fetchJwks(config);
  const jwk = jwks.find((key) => key.kid === kid);
  if (!jwk) {
    throw new ApiError(401, { error: "untrusted access key" });
  }
  const cacheKey = `${config.jwksUrl ?? config.issuer}|${kid}`;
  let cryptoKey = cryptoKeyCache.get(cacheKey);
  if (!cryptoKey) {
    if (header.alg && header.alg !== "RS256") {
      throw new ApiError(401, { error: "unsupported access token algorithm" });
    }
    cryptoKey = await crypto.subtle.importKey(
      "jwk",
      jwk,
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["verify"]
    );
    cryptoKeyCache.set(cacheKey, cryptoKey);
  }
  return cryptoKey;
}
__name(getCryptoKeyFromJwks, "getCryptoKeyFromJwks");
async function verifyAccessJwt(request, env) {
  const config = getAccessJwtConfig(env);
  if (!config) {
    return null;
  }
  const token = request.headers.get("Cf-Access-Jwt-Assertion") ?? request.headers.get("cf-access-jwt-assertion");
  if (!token) {
    return null;
  }
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new ApiError(401, { error: "malformed access token" });
  }
  const [headerSegment, payloadSegment, signatureSegment] = parts;
  const header = decodeJwtSegment(headerSegment);
  const payload = decodeJwtSegment(payloadSegment);
  if (payload.iss !== config.issuer) {
    throw new ApiError(401, { error: "unauthorized access token issuer" });
  }
  const audience = payload.aud;
  const matchesAudience = Array.isArray(audience) ? audience.includes(config.audience) : audience === config.audience;
  if (!matchesAudience) {
    throw new ApiError(401, { error: "unauthorized access token audience" });
  }
  const nowSeconds = Math.floor(Date.now() / 1e3);
  if (typeof payload.exp === "number" && payload.exp < nowSeconds) {
    throw new ApiError(401, { error: "access token expired" });
  }
  if (typeof payload.nbf === "number" && payload.nbf > nowSeconds + 60) {
    throw new ApiError(401, { error: "access token not yet valid" });
  }
  const cryptoKey = await getCryptoKeyFromJwks(config, header);
  const signature = base64UrlToUint8Array(signatureSegment);
  const data = textEncoder.encode(`${headerSegment}.${payloadSegment}`);
  const verified = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", cryptoKey, signature, data);
  if (!verified) {
    throw new ApiError(401, { error: "invalid access token signature" });
  }
  return {
    subject: payload.sub ?? "",
    email: payload.email
  };
}
__name(verifyAccessJwt, "verifyAccessJwt");
async function ensureSchema(env) {
  if (schemaInitialized) return;
  if (!schemaInitPromise) {
    schemaInitPromise = (async () => {
      const cleaned = schema_default.replace(/\/\*[\s\S]*?\*\//g, "").replace(/--.*$/gm, "").trim();
      if (!cleaned) {
        throw new Error("schema.sql is empty after stripping comments");
      }
      const statements = cleaned.split(/;\s*(?:\r?\n|$)/).map((statement) => statement.trim()).filter(Boolean).map((statement) => statement.endsWith(";") ? statement : `${statement};`);
      if (statements.length === 0) {
        throw new Error("schema.sql is empty after processing");
      }
      for (const sql of statements) {
        try {
          await env.BOARD_DB.prepare(sql).run();
        } catch (error) {
          console.error("[schema] failed to apply statement", sql);
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
        } catch (error) {
          const message = String(error?.message ?? "");
          if (/duplicate column name/i.test(message)) {
            continue;
          }
          if (/no such column/i.test(message)) {
            continue;
          }
          if (/duplicate column/i.test(message)) {
            continue;
          }
          console.warn("[schema] alter statement failed", sql, error);
        }
      }
      schemaInitialized = true;
      console.log("[schema] ready");
    })();
  }
  await schemaInitPromise;
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
async function createPost(env, boardId, body, author, userId, alias, pseudonym) {
  await ensureSchema(env);
  const id = crypto.randomUUID();
  const createdAt = Date.now();
  await env.BOARD_DB.prepare(
    `INSERT INTO posts (id, board_id, user_id, author, body, created_at, reaction_count, like_count, dislike_count)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, 0, 0)`
  ).bind(id, boardId, userId ?? null, author ?? null, body, createdAt).run();
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
__name(createPost, "createPost");
async function listPosts(env, boardId, limit) {
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
  ).bind(boardId, limit).all();
  return (results ?? []).map((row) => ({
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
__name(listPosts, "listPosts");
async function issueSessionTicket(env, userId) {
  await ensureSchema(env);
  const token = crypto.randomUUID().replace(/-/g, "");
  const createdAt = Date.now();
  const expiresAt = createdAt + SESSION_TTL_MS;
  await env.BOARD_DB.prepare(
    `INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?1, ?2, ?3, ?4)`
  ).bind(token, userId, createdAt, expiresAt).run();
  return {
    token,
    userId,
    expiresAt
  };
}
__name(issueSessionTicket, "issueSessionTicket");
async function getSessionByToken(env, token) {
  await ensureSchema(env);
  const record = await env.BOARD_DB.prepare(
    "SELECT token, user_id, created_at, expires_at FROM sessions WHERE token = ?1"
  ).bind(token).first();
  if (!record) {
    return null;
  }
  if (record.expires_at < Date.now()) {
    await env.BOARD_DB.prepare("DELETE FROM sessions WHERE token = ?1").bind(token).run();
    return null;
  }
  return record;
}
__name(getSessionByToken, "getSessionByToken");
async function getSessionFromRequest(request, env) {
  const token = parseBearerToken(request);
  if (!token) {
    throw new ApiError(401, { error: "authorization required" });
  }
  const session = await getSessionByToken(env, token);
  if (!session) {
    throw new ApiError(401, { error: "invalid session" });
  }
  return session;
}
__name(getSessionFromRequest, "getSessionFromRequest");
async function ensureSession(request, env, userId) {
  const accessContext = await verifyAccessJwt(request, env);
  const session = await getSessionFromRequest(request, env);
  if (session.user_id !== userId) {
    throw new ApiError(401, { error: "invalid session" });
  }
  await ensureAccessPrincipalForUser(env, accessContext, session.user_id);
  return session;
}
__name(ensureSession, "ensureSession");
async function createUser(env, pseudonym, normalized, status = "active") {
  await ensureSchema(env);
  const id = crypto.randomUUID();
  const createdAt = Date.now();
  await env.BOARD_DB.prepare(
    `INSERT INTO users (id, pseudonym, pseudonym_normalized, created_at, status)
       VALUES (?1, ?2, ?3, ?4, ?5)`
  ).bind(id, pseudonym, normalized, createdAt, status).run();
  return { id, pseudonym, createdAt };
}
__name(createUser, "createUser");
async function createUserWithUniquePseudonym(env, basePseudonym) {
  let attempt = 0;
  while (attempt < 10) {
    const suffix = attempt === 0 ? "" : `-${attempt}`;
    let candidate = `${basePseudonym}${suffix}`.slice(0, PSEUDONYM_MAX);
    if (candidate.length < PSEUDONYM_MIN) {
      candidate = candidate.padEnd(PSEUDONYM_MIN, "x");
    }
    const normalized = normalizeHandle(candidate);
    if (!normalized) {
      attempt += 1;
      continue;
    }
    try {
      return await createUser(env, candidate, normalized, "access_auto");
    } catch (error) {
      if (isUniqueConstraintError(error)) {
        attempt += 1;
        continue;
      }
      throw error;
    }
  }
  throw new ApiError(500, { error: "failed to create unique pseudonym" });
}
__name(createUserWithUniquePseudonym, "createUserWithUniquePseudonym");
function deriveAccessPseudonym(principal) {
  const emailLocal = principal?.email?.split("@")[0] ?? "";
  const subjectFragment = principal?.subject?.split("/").at(-1) ?? principal?.subject ?? "";
  const source = emailLocal || subjectFragment;
  let cleaned = source.replace(/[^a-zA-Z0-9]+/g, " ").trim();
  if (!cleaned) {
    cleaned = "Board User";
  }
  let base = cleaned.split(" ").filter(Boolean).map((word) => word[0]?.toUpperCase() + word.slice(1)).join(" ").slice(0, PSEUDONYM_MAX);
  if (base.length < PSEUDONYM_MIN) {
    base = `${base} User`.trim().slice(0, PSEUDONYM_MAX);
  }
  if (base.length < PSEUDONYM_MIN) {
    base = base.padEnd(PSEUDONYM_MIN, "x");
  }
  return base;
}
__name(deriveAccessPseudonym, "deriveAccessPseudonym");
function userRecordToProfile(user) {
  return {
    id: user.id,
    pseudonym: user.pseudonym,
    createdAt: user.created_at
  };
}
__name(userRecordToProfile, "userRecordToProfile");
async function markUserStatus(env, userId, status) {
  await ensureSchema(env);
  await env.BOARD_DB.prepare("UPDATE users SET status = ?1 WHERE id = ?2").bind(status, userId).run();
}
__name(markUserStatus, "markUserStatus");
async function getUserById(env, userId) {
  await ensureSchema(env);
  const record = await env.BOARD_DB.prepare(
    "SELECT id, pseudonym, pseudonym_normalized, created_at, status FROM users WHERE id = ?1"
  ).bind(userId).first();
  return record ?? null;
}
__name(getUserById, "getUserById");
async function getAccessLinkBySubject(env, subject) {
  await ensureSchema(env);
  const record = await env.BOARD_DB.prepare(
    "SELECT access_subject, user_id, email FROM user_access_links WHERE access_subject = ?1"
  ).bind(subject).first();
  return record ?? null;
}
__name(getAccessLinkBySubject, "getAccessLinkBySubject");
async function getAccessLinkByUserId(env, userId) {
  await ensureSchema(env);
  const record = await env.BOARD_DB.prepare(
    "SELECT access_subject, user_id, email FROM user_access_links WHERE user_id = ?1"
  ).bind(userId).first();
  return record ?? null;
}
__name(getAccessLinkByUserId, "getAccessLinkByUserId");
async function upsertAccessLink(env, subject, userId, email) {
  await ensureSchema(env);
  const now = Date.now();
  await env.BOARD_DB.prepare(
    `INSERT INTO user_access_links (access_subject, user_id, email, created_at, updated_at)
       VALUES (?1, ?2, ?3, ?4, ?4)
     ON CONFLICT(access_subject) DO UPDATE SET
       user_id = excluded.user_id,
       email = excluded.email,
       updated_at = excluded.updated_at`
  ).bind(subject, userId, email, now).run();
}
__name(upsertAccessLink, "upsertAccessLink");
async function resolveAccessUser(env, principal) {
  const subject = principal.subject;
  if (!subject) {
    throw new ApiError(401, { error: "access subject missing" });
  }
  const existingLink = await getAccessLinkBySubject(env, subject);
  if (existingLink) {
    const user2 = await getUserById(env, existingLink.user_id);
    if (user2) {
      if (user2.status === "access_orphan") {
        await markUserStatus(env, user2.id, "active");
        console.log(
          JSON.stringify({
            event: "access.identity_reactivated",
            user_id: user2.id,
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
      return refreshed ?? user2;
    }
  }
  const base = deriveAccessPseudonym(principal);
  const profile = await createUserWithUniquePseudonym(env, base);
  await upsertAccessLink(env, subject, profile.id, principal.email ?? existingLink?.email ?? null);
  const user = await getUserById(env, profile.id);
  if (!user) {
    throw new ApiError(500, { error: "failed to provision access user" });
  }
  await markUserStatus(env, user.id, "access_auto");
  console.log(
    JSON.stringify({
      event: "access.identity_auto_provisioned",
      user_id: user.id,
      subject,
      email: principal.email ?? null,
      pseudonym: user.pseudonym,
      timestamp: Date.now()
    })
  );
  return user;
}
__name(resolveAccessUser, "resolveAccessUser");
async function ensureAccessPrincipalForUser(env, principal, userId, options = {}) {
  if (!principal?.subject) {
    return;
  }
  const subject = principal.subject;
  const existingLink = await getAccessLinkBySubject(env, subject);
  if (!existingLink) {
    const linkForUser = await getAccessLinkByUserId(env, userId);
    if (linkForUser && linkForUser.access_subject !== subject) {
      throw new ApiError(403, { error: "user already linked to another access identity" });
    }
    try {
      await upsertAccessLink(env, subject, userId, principal.email ?? null);
    } catch (error) {
      if (isUniqueConstraintError(error)) {
        throw new ApiError(403, { error: "access identity already linked" });
      }
      throw error;
    }
    await markUserStatus(env, userId, "active");
    console.log(
      JSON.stringify({
        event: "access.identity_linked",
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
      throw new ApiError(403, { error: "access identity mismatch" });
    }
    const linkForUser = await getAccessLinkByUserId(env, userId);
    if (linkForUser && linkForUser.access_subject !== subject) {
      throw new ApiError(403, { error: "user already linked to another access identity" });
    }
    const previousUser = await getUserById(env, existingLink.user_id);
    if (previousUser) {
      await markUserStatus(env, previousUser.id, "access_orphan");
      console.log(
        JSON.stringify({
          event: "access.identity_orphaned",
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
        throw new ApiError(403, { error: "access identity already linked" });
      }
      throw error;
    }
    await markUserStatus(env, userId, "active");
    console.log(
      JSON.stringify({
        event: "access.identity_relinked",
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
__name(ensureAccessPrincipalForUser, "ensureAccessPrincipalForUser");
async function upsertBoardAlias(env, boardId, userId, alias, normalized) {
  await ensureSchema(env);
  const id = crypto.randomUUID();
  const createdAt = Date.now();
  await env.BOARD_DB.prepare(
    `INSERT INTO board_aliases (id, board_id, user_id, alias, alias_normalized, created_at)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6)
     ON CONFLICT(board_id, user_id) DO UPDATE SET
       alias = excluded.alias,
       alias_normalized = excluded.alias_normalized`
  ).bind(id, boardId, userId, alias, normalized, createdAt).run();
  const record = await env.BOARD_DB.prepare(
    "SELECT id, board_id, user_id, alias, alias_normalized, created_at FROM board_aliases WHERE board_id = ?1 AND user_id = ?2"
  ).bind(boardId, userId).first();
  if (!record) {
    throw new Error("Failed to upsert alias");
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
__name(upsertBoardAlias, "upsertBoardAlias");
async function getBoardAlias(env, boardId, userId) {
  await ensureSchema(env);
  const record = await env.BOARD_DB.prepare(
    "SELECT id, board_id, user_id, alias, alias_normalized, created_at FROM board_aliases WHERE board_id = ?1 AND user_id = ?2"
  ).bind(boardId, userId).first();
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
__name(getBoardAlias, "getBoardAlias");
async function applyReaction(env, boardId, postId, userId, action) {
  await ensureSchema(env);
  const post = await env.BOARD_DB.prepare(
    "SELECT id, board_id FROM posts WHERE id = ?1"
  ).bind(postId).first();
  if (!post) {
    throw new Error("Post not found");
  }
  if (post.board_id !== boardId) {
    throw new Error("Post does not belong to board");
  }
  const now = Date.now();
  if (action === "remove") {
    await env.BOARD_DB.prepare("DELETE FROM reactions WHERE post_id = ?1 AND user_id = ?2").bind(postId, userId).run();
  } else {
    const reactionValue = action === "like" ? 1 : -1;
    await env.BOARD_DB.prepare(
      `INSERT INTO reactions (id, post_id, board_id, user_id, reaction, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
       ON CONFLICT(post_id, user_id) DO UPDATE SET
         reaction = excluded.reaction,
         created_at = excluded.created_at`
    ).bind(crypto.randomUUID(), postId, boardId, userId, reactionValue, now).run();
  }
  const counts = await env.BOARD_DB.prepare(
    `SELECT
        SUM(CASE WHEN reaction = 1 THEN 1 ELSE 0 END) AS like_count,
        SUM(CASE WHEN reaction = -1 THEN 1 ELSE 0 END) AS dislike_count
       FROM reactions
       WHERE post_id = ?1`
  ).bind(postId).first();
  const likeCount = counts?.like_count ?? 0;
  const dislikeCount = counts?.dislike_count ?? 0;
  const total = likeCount + dislikeCount;
  await env.BOARD_DB.prepare(
    `UPDATE posts
        SET like_count = ?1,
            dislike_count = ?2,
            reaction_count = ?3
      WHERE id = ?4`
  ).bind(likeCount, dislikeCount, total, postId).run();
  return { total, likeCount, dislikeCount };
}
__name(applyReaction, "applyReaction");
var index_default = {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (request.method === "OPTIONS") {
      return withCors(request, new Response(null, { status: 204 }));
    }
    if (url.pathname === "/_health") {
      return new Response("ok", { status: 200 });
    }
    try {
      if (url.pathname === "/identity/session") {
        return withCors(request, await handleCreateSession(request, env));
      }
      if (url.pathname === "/identity/register") {
        return withCors(request, await handleRegisterIdentity(request, env));
      }
      if (url.pathname === "/identity/link") {
        return withCors(request, await handleLinkIdentity(request, env));
      }
      const upgradeHeader = request.headers.get("Upgrade");
      if (url.pathname === "/boards" && upgradeHeader === "websocket") {
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
      return withCors(request, new Response("Not Found", { status: 404 }));
    } catch (error) {
      if (error instanceof ApiError) {
        return withCors(
          request,
          new Response(JSON.stringify(error.body), {
            status: error.status,
            headers: { "Content-Type": "application/json" }
          })
        );
      }
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
var __internal = {
  resolveAccessUser,
  ensureAccessPrincipalForUser,
  deriveAccessPseudonym
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
  closePromise.then(() => {
    if (room.getConnectionCount() === 0) {
      boardRooms.delete(boardId);
    }
  }).catch((error) => {
    console.warn("[worker] websocket close handler error", error);
  });
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
  const authorInput = payload.author?.trim()?.slice(0, 64) ?? null;
  const userId = payload.userId?.trim() || null;
  let author = authorInput;
  let user = null;
  let aliasRecord = null;
  if (userId) {
    await ensureSession(request, env, userId);
    user = await getUserById(env, userId);
    if (!user) {
      return new Response(JSON.stringify({ error: "user not found", trace_id: traceId }), {
        status: 404,
        headers: { "Content-Type": "application/json" }
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
async function handleLinkIdentity(request, env) {
  if (request.method !== "POST") {
    return new Response(JSON.stringify({ error: "Method not allowed" }), {
      status: 405,
      headers: { "Content-Type": "application/json", Allow: "POST" }
    });
  }
  const principal = await verifyAccessJwt(request, env);
  if (!principal?.subject) {
    throw new ApiError(401, { error: "access token required" });
  }
  const session = await getSessionFromRequest(request, env);
  await ensureAccessPrincipalForUser(env, principal, session.user_id, { allowReassign: true });
  const user = await getUserById(env, session.user_id);
  const responseBody = {
    ok: true,
    user: user ? userRecordToProfile(user) : void 0
  };
  return new Response(JSON.stringify(responseBody), {
    status: 200,
    headers: { "Content-Type": "application/json" }
  });
}
__name(handleLinkIdentity, "handleLinkIdentity");
async function handleRegisterIdentity(request, env) {
  if (request.method !== "POST") {
    return new Response(JSON.stringify({ error: "Method not allowed" }), {
      status: 405,
      headers: { "Content-Type": "application/json", Allow: "POST" }
    });
  }
  let payload;
  try {
    payload = await request.json();
  } catch (error) {
    return new Response(JSON.stringify({ error: "Invalid JSON body" }), {
      status: 400,
      headers: { "Content-Type": "application/json" }
    });
  }
  const raw = payload.pseudonym?.trim();
  if (!raw) {
    return new Response(JSON.stringify({ error: "pseudonym is required" }), {
      status: 400,
      headers: { "Content-Type": "application/json" }
    });
  }
  if (raw.length < PSEUDONYM_MIN || raw.length > PSEUDONYM_MAX) {
    return new Response(
      JSON.stringify({
        error: `pseudonym must be between ${PSEUDONYM_MIN} and ${PSEUDONYM_MAX} characters`
      }),
      {
        status: 400,
        headers: { "Content-Type": "application/json" }
      }
    );
  }
  const normalized = normalizeHandle(raw);
  if (!normalized) {
    return new Response(JSON.stringify({ error: "pseudonym is invalid" }), {
      status: 400,
      headers: { "Content-Type": "application/json" }
    });
  }
  try {
    const accessPrincipal = await verifyAccessJwt(request, env);
    const user = await createUser(env, raw, normalized);
    await ensureAccessPrincipalForUser(env, accessPrincipal, user.id, { allowReassign: true });
    const session = await issueSessionTicket(env, user.id);
    const responseBody = {
      ok: true,
      user,
      session
    };
    return new Response(JSON.stringify(responseBody), {
      status: 201,
      headers: { "Content-Type": "application/json" }
    });
  } catch (error) {
    if (isUniqueConstraintError(error)) {
      return new Response(JSON.stringify({ error: "pseudonym already taken" }), {
        status: 409,
        headers: { "Content-Type": "application/json" }
      });
    }
    console.error("[identity] failed to register", error);
    return new Response(JSON.stringify({ error: "internal" }), {
      status: 500,
      headers: { "Content-Type": "application/json" }
    });
  }
}
__name(handleRegisterIdentity, "handleRegisterIdentity");
async function handleCreateSession(request, env) {
  if (request.method !== "POST") {
    throw new ApiError(405, { error: "Method not allowed" });
  }
  let payload;
  try {
    payload = await request.json();
  } catch (error) {
    throw new ApiError(400, { error: "Invalid JSON body" });
  }
  const userId = payload.userId?.trim();
  if (!userId) {
    const accessPrincipal = await verifyAccessJwt(request, env);
    if (!accessPrincipal?.subject) {
      throw new ApiError(400, { error: "userId is required" });
    }
    const accessUser = await resolveAccessUser(env, accessPrincipal);
    const session2 = await issueSessionTicket(env, accessUser.id);
    const responseBody2 = {
      ok: true,
      session: session2,
      user: userRecordToProfile(accessUser)
    };
    return new Response(JSON.stringify(responseBody2), {
      status: 201,
      headers: { "Content-Type": "application/json" }
    });
  }
  await ensureSession(request, env, userId);
  const session = await issueSessionTicket(env, userId);
  const responseBody = {
    ok: true,
    session
  };
  return new Response(JSON.stringify(responseBody), {
    status: 201,
    headers: { "Content-Type": "application/json" }
  });
}
__name(handleCreateSession, "handleCreateSession");
async function handleAlias(request, env, url) {
  if (request.method === "GET") {
    const match2 = url.pathname.match(/^\/boards\/([^/]+)\/aliases$/);
    const boardId2 = decodeURIComponent(match2[1]);
    const userId2 = url.searchParams.get("userId")?.trim();
    if (!userId2) {
      return new Response(JSON.stringify({ error: "userId query param is required" }), {
        status: 400,
        headers: { "Content-Type": "application/json" }
      });
    }
    await ensureSession(request, env, userId2);
    const user2 = await getUserById(env, userId2);
    if (!user2) {
      return new Response(JSON.stringify({ error: "user not found" }), {
        status: 404,
        headers: { "Content-Type": "application/json" }
      });
    }
    await ensureSchema(env);
    const boardExists = await env.BOARD_DB.prepare("SELECT id FROM boards WHERE id = ?1").bind(boardId2).first();
    if (!boardExists) {
      return new Response(JSON.stringify({ error: "board not found" }), {
        status: 404,
        headers: { "Content-Type": "application/json" }
      });
    }
    const alias = await getBoardAlias(env, boardId2, userId2);
    const responseBody = {
      ok: true,
      alias: alias ?? void 0
    };
    return new Response(JSON.stringify(responseBody), {
      status: 200,
      headers: { "Content-Type": "application/json" }
    });
  }
  if (request.method !== "POST" && request.method !== "PUT") {
    return new Response(JSON.stringify({ error: "Method not allowed" }), {
      status: 405,
      headers: { "Content-Type": "application/json", Allow: "GET, POST, PUT" }
    });
  }
  const match = url.pathname.match(/^\/boards\/([^/]+)\/aliases$/);
  const boardId = decodeURIComponent(match[1]);
  let payload;
  try {
    payload = await request.json();
  } catch (error) {
    return new Response(JSON.stringify({ error: "Invalid JSON body" }), {
      status: 400,
      headers: { "Content-Type": "application/json" }
    });
  }
  const userId = payload.userId?.trim();
  const aliasRaw = payload.alias?.trim();
  if (!userId || !aliasRaw) {
    return new Response(JSON.stringify({ error: "userId and alias are required" }), {
      status: 400,
      headers: { "Content-Type": "application/json" }
    });
  }
  await ensureSession(request, env, userId);
  if (aliasRaw.length < ALIAS_MIN || aliasRaw.length > ALIAS_MAX) {
    return new Response(
      JSON.stringify({ error: `alias must be between ${ALIAS_MIN} and ${ALIAS_MAX} characters` }),
      {
        status: 400,
        headers: { "Content-Type": "application/json" }
      }
    );
  }
  const user = await getUserById(env, userId);
  if (!user) {
    return new Response(JSON.stringify({ error: "user not found" }), {
      status: 404,
      headers: { "Content-Type": "application/json" }
    });
  }
  await getOrCreateBoard(env, boardId);
  const normalized = normalizeHandle(aliasRaw);
  if (!normalized) {
    return new Response(JSON.stringify({ error: "alias is invalid" }), {
      status: 400,
      headers: { "Content-Type": "application/json" }
    });
  }
  try {
    const alias = await upsertBoardAlias(env, boardId, userId, aliasRaw, normalized);
    const responseBody = {
      ok: true,
      alias
    };
    const status = request.method === "POST" ? 201 : 200;
    return new Response(JSON.stringify(responseBody), {
      status,
      headers: { "Content-Type": "application/json" }
    });
  } catch (error) {
    if (isUniqueConstraintError(error)) {
      return new Response(JSON.stringify({ error: "alias already in use on this board" }), {
        status: 409,
        headers: { "Content-Type": "application/json" }
      });
    }
    console.error("[alias] failed to upsert", error);
    return new Response(JSON.stringify({ error: "internal" }), {
      status: 500,
      headers: { "Content-Type": "application/json" }
    });
  }
}
__name(handleAlias, "handleAlias");
async function handleUpdateReaction(request, env, ctx, url) {
  if (request.method !== "POST") {
    return new Response(JSON.stringify({ error: "Method not allowed" }), {
      status: 405,
      headers: { "Content-Type": "application/json", Allow: "POST" }
    });
  }
  const match = url.pathname.match(/^\/boards\/([^/]+)\/posts\/([^/]+)\/reactions$/);
  const boardId = decodeURIComponent(match[1]);
  const postId = decodeURIComponent(match[2]);
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
  const userId = payload.userId?.trim();
  if (!userId) {
    return new Response(JSON.stringify({ error: "userId is required", trace_id: traceId }), {
      status: 400,
      headers: { "Content-Type": "application/json" }
    });
  }
  await ensureSession(request, env, userId);
  const action = payload.action;
  if (!action || !["like", "dislike", "remove"].includes(action)) {
    return new Response(JSON.stringify({ error: "action must be like, dislike, or remove", trace_id: traceId }), {
      status: 400,
      headers: { "Content-Type": "application/json" }
    });
  }
  const user = await getUserById(env, userId);
  if (!user) {
    return new Response(JSON.stringify({ error: "user not found", trace_id: traceId }), {
      status: 404,
      headers: { "Content-Type": "application/json" }
    });
  }
  try {
    const reactions = await applyReaction(env, boardId, postId, userId, action);
    const responseBody = {
      ok: true,
      boardId,
      postId,
      reactions
    };
    const room = getBoardRoom(boardId);
    const eventRecord = {
      id: crypto.randomUUID(),
      event: "post.reacted",
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
    return new Response(JSON.stringify(responseBody), {
      status: 200,
      headers: { "Content-Type": "application/json" }
    });
  } catch (error) {
    console.error("[reactions] failed to update", error);
    const message = error instanceof Error ? error.message : "internal";
    const status = message === "Post not found" || message === "Post does not belong to board" ? 404 : 500;
    return new Response(JSON.stringify({ error: status === 404 ? message : "internal", trace_id: traceId }), {
      status,
      headers: { "Content-Type": "application/json" }
    });
  }
}
__name(handleUpdateReaction, "handleUpdateReaction");
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
var EVENTS_STORAGE_KEY = "board-events";
var MAX_PERSISTED_EVENTS = 100;
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
    if (request.headers.get("Upgrade") === "websocket" && (url.pathname === "/connect" || url.pathname === "/boards")) {
      const socket = request.webSocket;
      if (!socket) {
        return new Response("Expected WebSocket upgrade.", { status: 400 });
      }
      const closePromise = this.handleDurableSocket(socket, boardId, traceId);
      this.state.waitUntil(closePromise);
      return new Response(null, { status: 101, webSocket: socket });
    }
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
  handleDurableSocket(socket, boardId, traceId) {
    socket.accept();
    const keepAlive = setInterval(() => {
      try {
        socket.send(
          JSON.stringify({
            type: "keepalive",
            boardId,
            timestamp: Date.now()
          })
        );
      } catch {
        clearInterval(keepAlive);
      }
    }, 3e4);
    const close = /* @__PURE__ */ __name(() => {
      clearInterval(keepAlive);
    }, "close");
    socket.addEventListener("close", close);
    socket.addEventListener("error", close);
    socket.send(
      JSON.stringify({
        type: "ack",
        boardId,
        connectionId: crypto.randomUUID(),
        trace_id: traceId,
        timestamp: Date.now()
      })
    );
    socket.addEventListener("message", (event) => {
      try {
        const payload = typeof event.data === "string" ? JSON.parse(event.data) : event.data;
        if (payload?.type === "ping") {
          socket.send(
            JSON.stringify({
              type: "pong",
              boardId,
              timestamp: Date.now()
            })
          );
        }
      } catch (err) {
        console.warn("[board-room] message parse failed", err);
      }
    });
    return new Promise((resolve) => {
      socket.addEventListener("close", () => resolve(), { once: true });
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

// .wrangler/tmp/bundle-utjSdA/middleware-insertion-facade.js
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

// .wrangler/tmp/bundle-utjSdA/middleware-loader.entry.ts
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
  __internal,
  __resetSchemaForTests,
  applyReaction,
  createPost,
  createUser,
  middleware_loader_entry_default as default,
  ensureSchema,
  getBoardAlias,
  getOrCreateBoard,
  listPosts,
  persistEvent,
  upsertBoardAlias
};
//# sourceMappingURL=index.js.map
