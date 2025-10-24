var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// dist/index.js
var schema_default = "CREATE TABLE IF NOT EXISTS boards (\n  id TEXT PRIMARY KEY,\n  display_name TEXT NOT NULL,\n  description TEXT,\n  created_at INTEGER NOT NULL,\n  radius_meters INTEGER NOT NULL DEFAULT 1500,\n  radius_state TEXT,\n  radius_updated_at INTEGER,\n  phase_mode TEXT NOT NULL DEFAULT 'default',\n  text_only INTEGER NOT NULL DEFAULT 0,\n  latitude REAL,\n  longitude REAL\n);\nCREATE TABLE IF NOT EXISTS board_metrics (\n  board_id TEXT PRIMARY KEY REFERENCES boards(id) ON DELETE CASCADE,\n  snapshot_at INTEGER NOT NULL,\n  active_connections INTEGER NOT NULL DEFAULT 0,\n  posts_last_hour INTEGER NOT NULL DEFAULT 0,\n  posts_last_day INTEGER NOT NULL DEFAULT 0,\n  posts_prev_day INTEGER NOT NULL DEFAULT 0,\n  last_post_at INTEGER\n);\nCREATE TABLE IF NOT EXISTS posts (\n  id TEXT PRIMARY KEY,\n  board_id TEXT NOT NULL REFERENCES boards(id) ON DELETE CASCADE,\n  user_id TEXT REFERENCES users(id) ON DELETE SET NULL,\n  author TEXT,\n  body TEXT NOT NULL,\n  created_at INTEGER NOT NULL,\n  reaction_count INTEGER NOT NULL DEFAULT 0,\n  like_count INTEGER NOT NULL DEFAULT 0,\n  dislike_count INTEGER NOT NULL DEFAULT 0\n);\nCREATE INDEX IF NOT EXISTS posts_board_created_at_idx ON posts (board_id, created_at DESC);\nCREATE TABLE IF NOT EXISTS board_events (\n  id TEXT PRIMARY KEY,\n  board_id TEXT NOT NULL,\n  event_type TEXT NOT NULL,\n  payload TEXT NOT NULL,\n  trace_id TEXT NOT NULL,\n  created_at INTEGER NOT NULL\n);\nCREATE INDEX IF NOT EXISTS board_events_board_created_at_idx ON board_events (board_id, created_at DESC);\nCREATE TABLE IF NOT EXISTS dead_zone_alerts (\n  id TEXT PRIMARY KEY,\n  board_id TEXT NOT NULL REFERENCES boards(id) ON DELETE CASCADE,\n  streak INTEGER NOT NULL,\n  post_count INTEGER NOT NULL,\n  threshold INTEGER NOT NULL,\n  window_start INTEGER NOT NULL,\n  window_end INTEGER NOT NULL,\n  window_ms INTEGER NOT NULL,\n  triggered_at INTEGER NOT NULL,\n  alert_level TEXT NOT NULL DEFAULT 'dead_zone',\n  trace_id TEXT NOT NULL,\n  created_at INTEGER NOT NULL\n);\nCREATE INDEX IF NOT EXISTS dead_zone_alerts_board_triggered_at_idx ON dead_zone_alerts (board_id, triggered_at DESC);\nCREATE TABLE IF NOT EXISTS access_identity_events (\n  id TEXT PRIMARY KEY,\n  event_type TEXT NOT NULL,\n  subject TEXT NOT NULL,\n  user_id TEXT,\n  email TEXT,\n  trace_id TEXT,\n  metadata TEXT,\n  created_at INTEGER NOT NULL\n);\nCREATE INDEX IF NOT EXISTS access_identity_events_event_created_idx ON access_identity_events (event_type, created_at DESC);\nCREATE TABLE IF NOT EXISTS sessions (\n  token TEXT PRIMARY KEY,\n  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,\n  created_at INTEGER NOT NULL,\n  expires_at INTEGER NOT NULL\n);\nCREATE INDEX IF NOT EXISTS sessions_user_expires_idx ON sessions (user_id, expires_at DESC);\nCREATE TABLE IF NOT EXISTS users (\n  id TEXT PRIMARY KEY,\n  pseudonym TEXT NOT NULL UNIQUE,\n  pseudonym_normalized TEXT NOT NULL UNIQUE,\n  created_at INTEGER NOT NULL,\n  status TEXT NOT NULL DEFAULT 'active'\n);\nCREATE TABLE IF NOT EXISTS user_access_links (\n  access_subject TEXT PRIMARY KEY,\n  user_id TEXT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,\n  email TEXT,\n  created_at INTEGER NOT NULL,\n  updated_at INTEGER NOT NULL\n);\nCREATE TABLE IF NOT EXISTS board_aliases (\n  id TEXT PRIMARY KEY,\n  board_id TEXT NOT NULL,\n  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,\n  alias TEXT NOT NULL,\n  alias_normalized TEXT NOT NULL,\n  created_at INTEGER NOT NULL,\n  UNIQUE(board_id, alias_normalized),\n  UNIQUE(board_id, user_id)\n);\n\nCREATE TABLE IF NOT EXISTS replies (\n  id TEXT PRIMARY KEY,\n  post_id TEXT NOT NULL REFERENCES posts(id) ON DELETE CASCADE,\n  board_id TEXT NOT NULL,\n  user_id TEXT REFERENCES users(id) ON DELETE SET NULL,\n  author TEXT,\n  body TEXT NOT NULL,\n  created_at INTEGER NOT NULL\n);\n\nCREATE INDEX IF NOT EXISTS replies_post_created_at_idx ON replies (post_id, created_at ASC);\nCREATE TABLE IF NOT EXISTS reactions (\n  id TEXT PRIMARY KEY,\n  post_id TEXT NOT NULL REFERENCES posts(id) ON DELETE CASCADE,\n  board_id TEXT NOT NULL,\n  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,\n  reaction INTEGER NOT NULL,\n  created_at INTEGER NOT NULL,\n  UNIQUE(post_id, user_id)\n);\n\nCREATE TABLE IF NOT EXISTS follows (\n  follower_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,\n  following_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,\n  created_at INTEGER NOT NULL,\n  PRIMARY KEY (follower_id, following_id)\n);\n\nCREATE INDEX IF NOT EXISTS follows_following_idx ON follows (following_id);\n";
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
    let rawPayload;
    try {
      rawPayload = JSON.parse(text);
    } catch {
      this.sendError(socket, metadata.boardId, "invalid JSON payload");
      return;
    }
    const payload = typeof rawPayload === "object" && rawPayload !== null ? rawPayload : {};
    switch (payload["type"]) {
      case "ping": {
        this.send(socket, {
          type: "pong",
          boardId: metadata.boardId,
          timestamp: this.now()
        });
        if (payload["closeAfterPong"]) {
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
            event: typeof payload["event"] === "string" ? payload["event"] : "message",
            data: payload["data"] ?? null,
            timestamp: this.now()
          },
          payload["echoSelf"] ? void 0 : connectionId
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
function getAdaptiveRadius(state, inputs, config) {
  const minimum = Math.max(100, config.minimumMeters ?? 250);
  const maximum = Math.max(minimum, config.maximumMeters ?? 2e3);
  const expansionStep = Math.max(50, config.expansionStepMeters ?? 150);
  const contractionStep = Math.max(50, config.contractionStepMeters ?? 150);
  const initial = clamp(config.initialMeters ?? 1500, minimum, maximum);
  const currentState = state ? { ...state } : {
    currentMeters: initial,
    lastExpandedAt: null,
    lastContractedAt: null
  };
  const { postsInWindow, freshThreshold, staleThreshold, now } = inputs;
  if (postsInWindow >= freshThreshold) {
    if (currentState.currentMeters > minimum && (currentState.lastContractedAt === null || now - currentState.lastContractedAt > 15 * 60 * 1e3)) {
      currentState.currentMeters = Math.max(minimum, currentState.currentMeters - contractionStep);
      currentState.lastContractedAt = now;
    }
    return currentState;
  }
  if (postsInWindow <= staleThreshold) {
    if (currentState.currentMeters < maximum && (currentState.lastExpandedAt === null || now - currentState.lastExpandedAt > 30 * 60 * 1e3)) {
      currentState.currentMeters = Math.min(maximum, currentState.currentMeters + expansionStep);
      currentState.lastExpandedAt = now;
    }
  }
  return currentState;
}
__name(getAdaptiveRadius, "getAdaptiveRadius");
function clamp(value, min, max) {
  return Math.min(Math.max(value, min), max);
}
__name(clamp, "clamp");
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
var TIME_DECAY_HALF_LIFE_MS = 24 * 60 * 60 * 1e3;
var VELOCITY_DECAY_MS = 90 * 60 * 1e3;
var VELOCITY_RATE_SATURATION = 5;
var WILSON_Z = 1.96;
var ADAPTIVE_RADIUS_WINDOW_MS = 2 * 60 * 60 * 1e3;
var ADAPTIVE_RADIUS_FRESH_THRESHOLD = 8;
var ADAPTIVE_RADIUS_STALE_THRESHOLD = 4;
var ALLOWED_IMAGE_TYPES = /* @__PURE__ */ new Set(["image/jpeg", "image/png", "image/webp"]);
var MAX_IMAGE_COUNT = 4;
var MAX_IMAGE_SIZE_BYTES = 3 * 1024 * 1024;
var BOARD_METRICS_STALE_MS = 5 * 60 * 1e3;
var SESSION_COOKIE_NAME = "boardapp_session_0";
var DEFAULT_BOARD_COORDS = {
  "demo-board": { latitude: 37.7749, longitude: -122.4194 },
  "campus-north": { latitude: 40.1036, longitude: -88.2272 },
  "smoke-board": { latitude: 34.0522, longitude: -118.2437 }
};
var textEncoder = new TextEncoder();
var phaseOneConfigCache = /* @__PURE__ */ new WeakMap();
function normalizeBoardId(value) {
  return value.trim().toLowerCase();
}
__name(normalizeBoardId, "normalizeBoardId");
function parseBoardList(value) {
  if (!value) {
    return /* @__PURE__ */ new Set();
  }
  const entries = value.split(",").map((entry) => normalizeBoardId(entry)).filter((entry) => entry.length > 0);
  return new Set(entries);
}
__name(parseBoardList, "parseBoardList");
function parseCookies(header) {
  if (!header) return {};
  return header.split(";").reduce((acc, part) => {
    const [key, ...rest] = part.trim().split("=");
    if (!key) return acc;
    acc[key] = rest.join("=").trim();
    return acc;
  }, {});
}
__name(parseCookies, "parseCookies");
function getSessionTokenFromRequest(request) {
  const auth = request.headers.get("Authorization");
  if (auth && auth.startsWith("Bearer ")) {
    const token = auth.slice(7).trim();
    if (token) {
      return token;
    }
  }
  const cookies = parseCookies(request.headers.get("Cookie"));
  const cookieToken = cookies[SESSION_COOKIE_NAME];
  return cookieToken ? cookieToken : null;
}
__name(getSessionTokenFromRequest, "getSessionTokenFromRequest");
function requirePhaseAdmin(request, env) {
  const token = (request.headers.get("Authorization") ?? "").replace(/^Bearer\s+/i, "");
  if (!env.PHASE_ADMIN_TOKEN || token !== env.PHASE_ADMIN_TOKEN) {
    throw new ApiError(401, { error: "unauthorized phase admin request" });
  }
}
__name(requirePhaseAdmin, "requirePhaseAdmin");
function isImageUploadsEnabled(env) {
  return (env.ENABLE_IMAGE_UPLOADS ?? "").toLowerCase() === "true";
}
__name(isImageUploadsEnabled, "isImageUploadsEnabled");
function getPhaseOneConfig(env) {
  const cached = phaseOneConfigCache.get(env);
  if (cached) {
    return cached;
  }
  const boards = parseBoardList(env.PHASE_ONE_BOARDS);
  const textOnlyBoards = parseBoardList(env.PHASE_ONE_TEXT_ONLY_BOARDS ?? env.PHASE_ONE_BOARDS);
  const radiusRaw = Number(env.PHASE_ONE_RADIUS_METERS ?? "1500");
  const radiusMeters = Number.isFinite(radiusRaw) && radiusRaw > 0 ? Math.max(250, Math.min(radiusRaw, 5e3)) : 1500;
  const config = {
    boards,
    textOnlyBoards,
    radiusMeters
  };
  phaseOneConfigCache.set(env, config);
  return config;
}
__name(getPhaseOneConfig, "getPhaseOneConfig");
var jwksCache = /* @__PURE__ */ new Map();
var cryptoKeyCache = /* @__PURE__ */ new Map();
var DEAD_ZONE_WINDOW_MS = 2 * 60 * 60 * 1e3;
var DEAD_ZONE_MIN_POSTS = 3;
var DEAD_ZONE_STREAK_THRESHOLD = 3;
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
  } catch {
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
function calculateWilsonScore(likeCount, dislikeCount) {
  const total = likeCount + dislikeCount;
  if (total === 0) {
    return 0;
  }
  const z = WILSON_Z;
  const phat = likeCount / total;
  const denominator = 1 + z ** 2 / total;
  const centreAdjustment = phat + z ** 2 / (2 * total);
  const adjustedStd = z * Math.sqrt((phat * (1 - phat) + z ** 2 / (4 * total)) / total);
  const score = (centreAdjustment - adjustedStd) / denominator;
  return Number.isFinite(score) ? Math.max(0, score) : 0;
}
__name(calculateWilsonScore, "calculateWilsonScore");
function calculateTimeDecay(createdAt, now) {
  const ageMs = Math.max(0, now - createdAt);
  if (ageMs === 0) {
    return 1;
  }
  const decay = Math.exp(-Math.log(2) * ageMs / TIME_DECAY_HALF_LIFE_MS);
  return Number.isFinite(decay) ? decay : 0;
}
__name(calculateTimeDecay, "calculateTimeDecay");
function calculateVelocityBoost(reactionCount, createdAt, now) {
  if (reactionCount <= 0) {
    return 0;
  }
  const ageMs = Math.max(1e3, now - createdAt);
  const ageMinutes = ageMs / 6e4;
  const reactionsPerMinute = reactionCount / Math.max(ageMinutes, 1 / 60);
  const normalizedRate = Math.min(reactionsPerMinute / VELOCITY_RATE_SATURATION, 1);
  const freshness = Math.exp(-ageMs / VELOCITY_DECAY_MS);
  const boost = normalizedRate * freshness;
  return Number.isFinite(boost) ? boost : 0;
}
__name(calculateVelocityBoost, "calculateVelocityBoost");
function calculateHotRank(likeCount, dislikeCount, reactionCount, createdAt, now) {
  const wilson = calculateWilsonScore(likeCount, dislikeCount);
  const timeDecay = calculateTimeDecay(createdAt, now);
  const velocityBonus = calculateVelocityBoost(reactionCount, createdAt, now);
  const authorBonus = 1;
  const base = 0.5 * timeDecay + 0.45 * wilson + 0.05 * authorBonus;
  return base + velocityBonus * 0.15;
}
__name(calculateHotRank, "calculateHotRank");
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
  } catch {
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
        `ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT 'active'`,
        `ALTER TABLE boards ADD COLUMN radius_meters INTEGER NOT NULL DEFAULT 1500`,
        `ALTER TABLE boards ADD COLUMN radius_state TEXT`,
        `ALTER TABLE boards ADD COLUMN radius_updated_at INTEGER`,
        `ALTER TABLE boards ADD COLUMN phase_mode TEXT NOT NULL DEFAULT 'default'`,
        `ALTER TABLE boards ADD COLUMN text_only INTEGER NOT NULL DEFAULT 0`,
        `ALTER TABLE boards ADD COLUMN latitude REAL`,
        `ALTER TABLE boards ADD COLUMN longitude REAL`
      ];
      for (const sql of alterStatements) {
        try {
          await env.BOARD_DB.prepare(sql).run();
        } catch (error) {
          const message = error instanceof Error ? error.message : String(error);
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
    "SELECT id, display_name, description, created_at, radius_meters, radius_state, radius_updated_at, phase_mode, text_only, latitude, longitude FROM boards WHERE id = ?1"
  ).bind(boardId).first();
  if (existing) {
    const normalizedId = normalizeBoardId(boardId);
    const defaultLocation2 = DEFAULT_BOARD_COORDS[normalizedId];
    if (defaultLocation2 && (existing.latitude == null || existing.longitude == null)) {
      await env.BOARD_DB.prepare("UPDATE boards SET latitude = ?1, longitude = ?2 WHERE id = ?3").bind(defaultLocation2.latitude, defaultLocation2.longitude, boardId).run();
      existing.latitude = defaultLocation2.latitude;
      existing.longitude = defaultLocation2.longitude;
    }
    return existing;
  }
  const createdAt = Date.now();
  const displayName = formatBoardName(boardId);
  const radiusState = { currentMeters: 1500, lastExpandedAt: null, lastContractedAt: null };
  const defaultLocation = DEFAULT_BOARD_COORDS[normalizeBoardId(boardId)] ?? null;
  await env.BOARD_DB.prepare(
    "INSERT INTO boards (id, display_name, description, created_at, radius_meters, radius_state, radius_updated_at, phase_mode, text_only, latitude, longitude) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)"
  ).bind(
    boardId,
    displayName,
    null,
    createdAt,
    radiusState.currentMeters,
    JSON.stringify(radiusState),
    createdAt,
    "default",
    0,
    defaultLocation?.latitude ?? null,
    defaultLocation?.longitude ?? null
  ).run();
  return {
    id: boardId,
    display_name: displayName,
    description: null,
    created_at: createdAt,
    radius_meters: radiusState.currentMeters,
    radius_state: JSON.stringify(radiusState),
    radius_updated_at: createdAt,
    phase_mode: "default",
    text_only: 0,
    latitude: defaultLocation?.latitude ?? null,
    longitude: defaultLocation?.longitude ?? null
  };
}
__name(getOrCreateBoard, "getOrCreateBoard");
async function createPost(env, boardId, body, author, userId, alias, pseudonym, images, boardName) {
  await ensureSchema(env);
  const id = crypto.randomUUID();
  const createdAt = Date.now();
  await env.BOARD_DB.prepare(
    `INSERT INTO posts (id, board_id, user_id, author, body, created_at, reaction_count, like_count, dislike_count)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, 0, 0)`
  ).bind(id, boardId, userId ?? null, author ?? null, body, createdAt).run();
  const hotRank = calculateHotRank(0, 0, 0, createdAt, createdAt);
  return {
    id,
    boardId,
    boardName: boardName ?? null,
    userId: userId ?? null,
    author: author ?? null,
    alias: alias ?? author ?? null,
    pseudonym: pseudonym ?? null,
    body,
    createdAt,
    reactionCount: 0,
    likeCount: 0,
    dislikeCount: 0,
    replyCount: 0,
    hotRank,
    images: images && images.length > 0 ? images : void 0
  };
}
__name(createPost, "createPost");
async function createReply(env, options) {
  await ensureSchema(env);
  const exists = await env.BOARD_DB.prepare(
    "SELECT 1 FROM posts WHERE id = ?1 AND board_id = ?2"
  ).bind(options.postId, options.board.id).first();
  if (!exists) {
    throw new ApiError(404, { error: "post not found" });
  }
  const id = crypto.randomUUID();
  const createdAt = Date.now();
  await env.BOARD_DB.prepare(
    "INSERT INTO replies (id, post_id, board_id, user_id, author, body, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"
  ).bind(id, options.postId, options.board.id, options.user?.id ?? null, options.author, options.body, createdAt).run();
  return {
    id,
    postId: options.postId,
    boardId: options.board.id,
    userId: options.user?.id ?? null,
    author: options.author,
    alias: options.alias,
    pseudonym: options.user?.pseudonym ?? null,
    body: options.body,
    createdAt
  };
}
__name(createReply, "createReply");
async function listReplies(env, boardId, postId, options) {
  await ensureSchema(env);
  const limit = options.limit ?? 50;
  let cursorCreatedAt = 0;
  let cursorId = "";
  if (options.cursor) {
    const [timestamp, id] = options.cursor.split(":");
    cursorCreatedAt = Number(timestamp) || 0;
    cursorId = id ?? "";
  }
  const rows = await env.BOARD_DB.prepare(
    `SELECT
        r.id,
        r.post_id,
        r.board_id,
        r.user_id,
        r.author,
        r.body,
        r.created_at,
        a.alias AS board_alias,
        u.pseudonym AS pseudonym
       FROM replies r
       LEFT JOIN board_aliases a ON a.board_id = r.board_id AND a.user_id = r.user_id
       LEFT JOIN users u ON u.id = r.user_id
      WHERE r.board_id = ?1
        AND r.post_id = ?2
        AND (
          r.created_at > ?3
          OR (r.created_at = ?3 AND r.id > ?4)
        )
      ORDER BY r.created_at ASC, r.id ASC
      LIMIT ?5`
  ).bind(boardId, postId, cursorCreatedAt, cursorId, limit).all();
  const replies = rows.results?.map(mapReplyRowToReply) ?? [];
  let nextCursor = null;
  if (rows.results && rows.results.length === limit) {
    const last = rows.results[rows.results.length - 1];
    nextCursor = `${last.created_at}:${last.id}`;
  }
  return { replies, cursor: nextCursor };
}
__name(listReplies, "listReplies");
async function listPosts(env, boardId, limit, options = {}) {
  await ensureSchema(env);
  const now = options.now ?? Date.now();
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
        COALESCE(r.reply_count, 0) AS reply_count,
        b.display_name AS board_name,
        ba.alias AS board_alias,
        u.pseudonym
       FROM posts p
       LEFT JOIN board_aliases ba
         ON ba.board_id = p.board_id
        AND ba.user_id = p.user_id
       LEFT JOIN users u
         ON u.id = p.user_id
       LEFT JOIN boards b
         ON b.id = p.board_id
       LEFT JOIN (
         SELECT post_id, COUNT(*) AS reply_count
           FROM replies
          GROUP BY post_id
       ) r
         ON r.post_id = p.id
       WHERE p.board_id = ?1
       ORDER BY p.created_at DESC
       LIMIT ?2`
  ).bind(boardId, limit).all();
  return (results ?? []).map((row) => mapPostRowToBoardPost(row, now)).sort((a, b) => {
    const rankDelta = (b.hotRank ?? 0) - (a.hotRank ?? 0);
    if (Math.abs(rankDelta) > 1e-6) {
      return rankDelta;
    }
    return b.createdAt - a.createdAt;
  });
}
__name(listPosts, "listPosts");
function mapPostRowToBoardPost(row, now) {
  const likeCount = row.like_count ?? 0;
  const dislikeCount = row.dislike_count ?? 0;
  const reactionCount = row.reaction_count ?? likeCount + dislikeCount;
  const replyCount = row.reply_count ?? 0;
  const hotRank = calculateHotRank(likeCount, dislikeCount, reactionCount, row.created_at, now);
  return {
    id: row.id,
    boardId: row.board_id,
    boardName: row.board_name ?? null,
    userId: row.user_id ?? null,
    author: row.board_alias ?? row.author ?? row.pseudonym ?? null,
    alias: row.board_alias ?? row.author ?? null,
    pseudonym: row.pseudonym ?? null,
    body: row.body,
    createdAt: row.created_at,
    reactionCount,
    likeCount,
    dislikeCount,
    replyCount,
    hotRank
  };
}
__name(mapPostRowToBoardPost, "mapPostRowToBoardPost");
function parsePostCursor(cursor) {
  if (!cursor) {
    return null;
  }
  const [timestamp, id] = cursor.split(":");
  const createdAt = Number(timestamp);
  if (!Number.isFinite(createdAt) || !id) {
    return null;
  }
  return { createdAt, id };
}
__name(parsePostCursor, "parsePostCursor");
function extractTrendingTopics(posts, limit = 5) {
  const hashtagRegex = /#[\p{L}0-9_-]+/gu;
  const counts = /* @__PURE__ */ new Map();
  for (const post of posts) {
    const matches = post.body.match(hashtagRegex);
    if (!matches) continue;
    for (const rawTag of matches) {
      const normalized = rawTag.toLowerCase();
      const entry = counts.get(normalized);
      if (entry) {
        entry.count += 1;
      } else {
        counts.set(normalized, { count: 1, label: rawTag });
      }
    }
  }
  return Array.from(counts.values()).sort((a, b) => b.count - a.count).slice(0, limit).map((entry) => entry.label);
}
__name(extractTrendingTopics, "extractTrendingTopics");
function calculateInfluenceScore(posts) {
  if (!posts.length) {
    return 0;
  }
  let positive = 0;
  let negative = 0;
  for (const post of posts) {
    positive += post.likeCount ?? 0;
    positive += (post.replyCount ?? 0) * 0.5;
    negative += (post.dislikeCount ?? 0) * 0.7;
  }
  const raw = positive - negative;
  const normalized = Math.max(0, Math.min(1, raw / (posts.length * 12 + 12)));
  return Number(normalized.toFixed(2));
}
__name(calculateInfluenceScore, "calculateInfluenceScore");
async function listUserPosts(env, userId, limit, options = {}) {
  await ensureSchema(env);
  const now = options.now ?? Date.now();
  const cappedLimit = Math.max(1, Math.min(limit, 50));
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
        COALESCE(r.reply_count, 0) AS reply_count,
        b.display_name AS board_name,
        ba.alias AS board_alias,
        u.pseudonym
       FROM posts p
       LEFT JOIN board_aliases ba
         ON ba.board_id = p.board_id
        AND ba.user_id = p.user_id
       LEFT JOIN users u
         ON u.id = p.user_id
       LEFT JOIN boards b
         ON b.id = p.board_id
       LEFT JOIN (
         SELECT post_id, COUNT(*) AS reply_count
           FROM replies
          GROUP BY post_id
       ) r
         ON r.post_id = p.id
      WHERE p.user_id = ?
      ORDER BY p.created_at DESC, p.id DESC
      LIMIT ?`
  ).bind(userId, cappedLimit).all();
  return (results ?? []).map((row) => mapPostRowToBoardPost(row, now));
}
__name(listUserPosts, "listUserPosts");
async function listFollowingPosts(env, followerId, options = {}) {
  await ensureSchema(env);
  const now = options.now ?? Date.now();
  const limit = Math.max(1, Math.min(options.limit ?? 20, 50));
  const cursor = parsePostCursor(options.cursor);
  const cursorCreatedAt = cursor?.createdAt ?? Number.MAX_SAFE_INTEGER;
  const cursorId = cursor?.id ?? "\uFFFF";
  const sql = `SELECT
        p.id,
        p.board_id,
        p.user_id,
        p.author,
        p.body,
        p.created_at,
        p.reaction_count,
        p.like_count,
        p.dislike_count,
        COALESCE(r.reply_count, 0) AS reply_count,
        b.display_name AS board_name,
        ba.alias AS board_alias,
       u.pseudonym
       FROM posts p
       LEFT JOIN board_aliases ba
         ON ba.board_id = p.board_id
        AND ba.user_id = p.user_id
       LEFT JOIN users u
         ON u.id = p.user_id
       LEFT JOIN boards b
         ON b.id = p.board_id
       LEFT JOIN (
         SELECT post_id, COUNT(*) AS reply_count
           FROM replies
          GROUP BY post_id
       ) r
         ON r.post_id = p.id
      WHERE p.user_id IS NOT NULL
        AND p.user_id IN (SELECT following_id FROM follows WHERE follower_id = ?1)
        AND (p.created_at < ?2 OR (p.created_at = ?2 AND p.id < ?3))
      ORDER BY p.created_at DESC, p.id DESC
      LIMIT ?4`;
  const { results } = await env.BOARD_DB.prepare(sql).bind(followerId, cursorCreatedAt, cursorId, limit + 1).all();
  const rows = results ?? [];
  const posts = rows.slice(0, limit).map((row) => mapPostRowToBoardPost(row, now));
  const hasMore = rows.length > limit;
  const nextCursor = hasMore && rows[limit - 1] ? `${rows[limit - 1].created_at}:${rows[limit - 1].id}` : null;
  return { posts, cursor: nextCursor, hasMore };
}
__name(listFollowingPosts, "listFollowingPosts");
async function computeBoardMetrics(env, board, now) {
  const hourAgo = now - 60 * 60 * 1e3;
  const dayAgo = now - 24 * 60 * 60 * 1e3;
  const twoDaysAgo = now - 48 * 60 * 60 * 1e3;
  const stats = await env.BOARD_DB.prepare(
    `SELECT
        SUM(CASE WHEN created_at >= ?2 THEN 1 ELSE 0 END) AS posts_last_hour,
        SUM(CASE WHEN created_at >= ?3 THEN 1 ELSE 0 END) AS posts_last_day,
        SUM(CASE WHEN created_at >= ?4 AND created_at < ?3 THEN 1 ELSE 0 END) AS posts_prev_day,
        MAX(created_at) AS last_post_at
       FROM posts
       WHERE board_id = ?1`
  ).bind(board.id, hourAgo, dayAgo, twoDaysAgo).first();
  const room = boardRooms.get(board.id);
  const activeConnections = room?.getConnectionCount() ?? 0;
  return {
    boardId: board.id,
    snapshotAt: now,
    activeConnections,
    postsLastHour: stats?.posts_last_hour ?? 0,
    postsLastDay: stats?.posts_last_day ?? 0,
    postsPrevDay: stats?.posts_prev_day ?? 0,
    lastPostAt: stats?.last_post_at ?? null
  };
}
__name(computeBoardMetrics, "computeBoardMetrics");
async function upsertBoardMetrics(env, snapshot) {
  await env.BOARD_DB.prepare(
    `INSERT INTO board_metrics (
        board_id,
        snapshot_at,
        active_connections,
        posts_last_hour,
        posts_last_day,
        posts_prev_day,
        last_post_at
      ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
      ON CONFLICT(board_id) DO UPDATE SET
        snapshot_at = excluded.snapshot_at,
        active_connections = excluded.active_connections,
        posts_last_hour = excluded.posts_last_hour,
        posts_last_day = excluded.posts_last_day,
        posts_prev_day = excluded.posts_prev_day,
        last_post_at = excluded.last_post_at`
  ).bind(
    snapshot.boardId,
    snapshot.snapshotAt,
    snapshot.activeConnections,
    snapshot.postsLastHour,
    snapshot.postsLastDay,
    snapshot.postsPrevDay,
    snapshot.lastPostAt
  ).run();
}
__name(upsertBoardMetrics, "upsertBoardMetrics");
async function snapshotBoardMetrics(env, options = {}) {
  await ensureSchema(env);
  const now = options.now ?? Date.now();
  const { results } = await env.BOARD_DB.prepare(
    "SELECT id, display_name, description, created_at, radius_meters, radius_state, radius_updated_at, phase_mode, text_only FROM boards"
  ).all();
  const boards = results ?? [];
  for (const board of boards) {
    const snapshot = await computeBoardMetrics(env, board, now);
    await upsertBoardMetrics(env, snapshot);
  }
}
__name(snapshotBoardMetrics, "snapshotBoardMetrics");
async function listBoardsCatalog(env, options = {}) {
  await ensureSchema(env);
  const limitRaw = options.limit ?? 12;
  const limit = Math.max(1, Math.min(limitRaw, 50));
  const { results } = await env.BOARD_DB.prepare(
    `SELECT
        id,
        display_name,
        description,
        created_at,
        radius_meters,
        radius_updated_at,
        phase_mode,
        text_only
      FROM boards
      ORDER BY created_at ASC
      LIMIT ?1`
  ).bind(limit).all();
  const rows = results ?? [];
  const now = Date.now();
  const enriched = await Promise.all(
    rows.map(async (record) => {
      const boardId = record.id;
      const metricsRow = await env.BOARD_DB.prepare(
        `SELECT board_id, snapshot_at, active_connections, posts_last_hour, posts_last_day, posts_prev_day, last_post_at
           FROM board_metrics
          WHERE board_id = ?1`
      ).bind(boardId).first();
      let snapshot = metricsRow ? {
        boardId: metricsRow.board_id,
        snapshotAt: metricsRow.snapshot_at,
        activeConnections: metricsRow.active_connections,
        postsLastHour: metricsRow.posts_last_hour,
        postsLastDay: metricsRow.posts_last_day,
        postsPrevDay: metricsRow.posts_prev_day,
        lastPostAt: metricsRow.last_post_at ?? null
      } : null;
      if (!snapshot || now - snapshot.snapshotAt > BOARD_METRICS_STALE_MS) {
        snapshot = await computeBoardMetrics(env, record, now);
        await upsertBoardMetrics(env, snapshot);
      }
      const liveConnections = boardRooms.get(boardId)?.getConnectionCount();
      const activeConnections = liveConnections ?? snapshot.activeConnections;
      const postsLastDay = snapshot.postsLastDay;
      const postsPrevDay = snapshot.postsPrevDay;
      const trend = postsPrevDay > 0 ? (postsLastDay - postsPrevDay) / postsPrevDay * 100 : postsLastDay > 0 ? 100 : null;
      const radiusMeters = record.radius_meters ?? void 0;
      const radiusLabel = radiusMeters ? `${Math.round(radiusMeters).toLocaleString()} m radius` : null;
      return {
        id: boardId,
        displayName: record.display_name,
        description: record.description,
        createdAt: record.created_at,
        radiusMeters,
        radiusUpdatedAt: record.radius_updated_at ?? null,
        phaseMode: record.phase_mode === "phase1" ? "phase1" : "default",
        textOnly: Boolean(record.text_only),
        activeConnections,
        postsLastHour: snapshot.postsLastHour,
        postsLastDay,
        postsTrend24Hr: trend,
        radiusLabel,
        lastPostAt: snapshot.lastPostAt,
        latitude: record.latitude ?? null,
        longitude: record.longitude ?? null
      };
    })
  );
  return enriched;
}
__name(listBoardsCatalog, "listBoardsCatalog");
async function searchBoardPosts(env, options = {}) {
  await ensureSchema(env);
  const now = options.now ?? Date.now();
  const limit = Math.max(1, Math.min(options.limit ?? 20, 50));
  const cursor = parsePostCursor(options.cursor);
  const windowMs = options.windowMs ?? 7 * 24 * 60 * 60 * 1e3;
  const minReactions = options.minReactions ?? 10;
  const extendedWindowMs = Math.max(windowMs, 30 * 24 * 60 * 60 * 1e3);
  const earliest = now - extendedWindowMs;
  const boardParam = options.boardId ?? null;
  const likeParam = options.query?.trim() ? `%${options.query.trim().replace(/[%_]/g, (match) => `\\${match}`)}%` : null;
  const cursorCreatedAt = cursor?.createdAt ?? Number.MAX_SAFE_INTEGER;
  const cursorId = cursor?.id ?? "\uFFFF";
  const sql = `SELECT
        p.id,
        p.board_id,
        p.user_id,
        p.author,
        p.body,
        p.created_at,
        p.reaction_count,
        p.like_count,
        p.dislike_count,
        COALESCE(r.reply_count, 0) AS reply_count,
        b.display_name AS board_name,
        ba.alias AS board_alias,
       u.pseudonym
       FROM posts p
       LEFT JOIN board_aliases ba
         ON ba.board_id = p.board_id
        AND ba.user_id = p.user_id
       LEFT JOIN users u
         ON u.id = p.user_id
       LEFT JOIN boards b
         ON b.id = p.board_id
       LEFT JOIN (
         SELECT post_id, COUNT(*) AS reply_count
           FROM replies
          GROUP BY post_id
       ) r
         ON r.post_id = p.id
      WHERE p.created_at >= ?1
        AND (?2 IS NULL OR p.board_id = ?2)
        AND (?3 IS NULL OR p.body LIKE ?3)
        AND (p.created_at < ?4 OR (p.created_at = ?4 AND p.id < ?5))
      ORDER BY p.created_at DESC, p.id DESC
      LIMIT ?6`;
  const { results } = await env.BOARD_DB.prepare(sql).bind(earliest, boardParam, likeParam, cursorCreatedAt, cursorId, limit + 1).all();
  const rows = results ?? [];
  const filtered = rows.filter((row) => row.created_at >= now - windowMs || (row.reaction_count ?? 0) >= minReactions).slice(0, limit);
  const posts = filtered.map((row) => mapPostRowToBoardPost(row, now));
  const hasMore = rows.length > limit;
  let anchor;
  if (hasMore) {
    anchor = rows[limit - 1];
  } else if (filtered.length > 0) {
    anchor = filtered[filtered.length - 1];
  }
  const nextCursor = hasMore && anchor ? `${anchor.created_at}:${anchor.id}` : null;
  return { posts, cursor: nextCursor, hasMore };
}
__name(searchBoardPosts, "searchBoardPosts");
async function getFollowCounts(env, userId) {
  await ensureSchema(env);
  const followerRow = await env.BOARD_DB.prepare("SELECT COUNT(*) AS follower_count FROM follows WHERE following_id = ?").bind(userId).first();
  const followingRow = await env.BOARD_DB.prepare("SELECT COUNT(*) AS following_count FROM follows WHERE follower_id = ?").bind(userId).first();
  return {
    followerCount: followerRow?.follower_count ?? 0,
    followingCount: followingRow?.following_count ?? 0
  };
}
__name(getFollowCounts, "getFollowCounts");
async function isFollowing(env, followerId, targetId) {
  await ensureSchema(env);
  const existing = await env.BOARD_DB.prepare(
    "SELECT 1 FROM follows WHERE follower_id = ?1 AND following_id = ?2 LIMIT 1"
  ).bind(followerId, targetId).first();
  return Boolean(existing);
}
__name(isFollowing, "isFollowing");
async function listFollowingIds(env, userId, limit = 50) {
  await ensureSchema(env);
  const { results } = await env.BOARD_DB.prepare(
    "SELECT following_id FROM follows WHERE follower_id = ? ORDER BY created_at DESC LIMIT ?"
  ).bind(userId, Math.max(1, Math.min(limit, 200))).all();
  return (results ?? []).map((row) => row.following_id);
}
__name(listFollowingIds, "listFollowingIds");
async function setFollowState(env, followerId, targetId, follow) {
  await ensureSchema(env);
  if (follow) {
    await env.BOARD_DB.prepare(
      `INSERT INTO follows (follower_id, following_id, created_at)
         VALUES (?1, ?2, ?3)
       ON CONFLICT(follower_id, following_id) DO NOTHING`
    ).bind(followerId, targetId, Date.now()).run();
    return true;
  }
  await env.BOARD_DB.prepare("DELETE FROM follows WHERE follower_id = ?1 AND following_id = ?2").bind(followerId, targetId).run();
  return false;
}
__name(setFollowState, "setFollowState");
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
async function deleteSessionByToken(env, token) {
  await ensureSchema(env);
  await env.BOARD_DB.prepare("DELETE FROM sessions WHERE token = ?1").bind(token).run();
}
__name(deleteSessionByToken, "deleteSessionByToken");
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
        await emitAccessIdentityEvent(env, "access.identity_reactivated", {
          subject,
          user_id: user2.id,
          email: principal.email ?? existingLink.email ?? null
        });
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
  await emitAccessIdentityEvent(env, "access.identity_auto_provisioned", {
    subject,
    user_id: user.id,
    email: principal.email ?? null,
    metadata: { pseudonym: user.pseudonym }
  });
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
    await emitAccessIdentityEvent(env, "access.identity_linked", {
      subject,
      user_id: userId,
      email: principal.email ?? existingLink?.email ?? null
    });
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
      await emitAccessIdentityEvent(env, "access.identity_orphaned", {
        subject,
        user_id: previousUser.id
      });
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
    await emitAccessIdentityEvent(env, "access.identity_relinked", {
      subject,
      user_id: userId,
      email: principal.email ?? existingLink.email ?? null
    });
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
async function listAliasesForUser(env, userId, limit = 100) {
  await ensureSchema(env);
  const { results } = await env.BOARD_DB.prepare(
    "SELECT id, board_id, user_id, alias, alias_normalized, created_at FROM board_aliases WHERE user_id = ? ORDER BY created_at DESC LIMIT ?"
  ).bind(userId, Math.max(1, Math.min(limit, 200))).all();
  return (results ?? []).map((record) => ({
    id: record.id,
    boardId: record.board_id,
    userId: record.user_id,
    alias: record.alias,
    aliasNormalized: record.alias_normalized,
    createdAt: record.created_at
  }));
}
__name(listAliasesForUser, "listAliasesForUser");
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
async function recordAccessIdentityEvent(env, event) {
  await ensureSchema(env);
  const id = crypto.randomUUID();
  const createdAt = event.createdAt ?? Date.now();
  await env.BOARD_DB.prepare(
    `INSERT INTO access_identity_events (id, event_type, subject, user_id, email, trace_id, metadata, created_at)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)`
  ).bind(
    id,
    event.eventType,
    event.subject,
    event.userId ?? null,
    event.email ?? null,
    event.traceId ?? null,
    event.metadata ? JSON.stringify(event.metadata) : null,
    createdAt
  ).run();
}
__name(recordAccessIdentityEvent, "recordAccessIdentityEvent");
async function emitAccessIdentityEvent(env, eventType, payload) {
  const timestamp = Date.now();
  const { subject, user_id, email, trace_id, metadata } = payload;
  const rest = {
    ...metadata ?? {}
  };
  console.log(
    JSON.stringify({
      event: eventType,
      subject,
      user_id: user_id ?? null,
      email: email ?? null,
      trace_id: trace_id ?? null,
      ...rest,
      timestamp
    })
  );
  await recordAccessIdentityEvent(env, {
    eventType,
    subject,
    userId: user_id ?? null,
    email: email ?? null,
    traceId: trace_id ?? null,
    metadata: Object.keys(rest).length > 0 ? rest : null,
    createdAt: timestamp
  });
}
__name(emitAccessIdentityEvent, "emitAccessIdentityEvent");
async function getLatestFreshnessSnapshot(env, boardId) {
  const record = await env.BOARD_DB.prepare(
    `SELECT payload FROM board_events
       WHERE board_id = ?1 AND event_type = ?2
       ORDER BY created_at DESC
       LIMIT 1`
  ).bind(boardId, "board.freshness").first();
  if (!record?.payload) {
    return null;
  }
  try {
    return JSON.parse(record.payload);
  } catch (error) {
    console.warn("[metrics] failed to parse previous freshness payload", error);
    return null;
  }
}
__name(getLatestFreshnessSnapshot, "getLatestFreshnessSnapshot");
async function recordDeadZoneAlert(env, snapshot, options) {
  await ensureSchema(env);
  const id = crypto.randomUUID();
  const { windowMs, timestamp, traceId } = options;
  await env.BOARD_DB.prepare(
    `INSERT INTO dead_zone_alerts (
        id, board_id, streak, post_count, threshold, window_start, window_end, window_ms, triggered_at, alert_level, trace_id, created_at
      ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)`
  ).bind(
    id,
    snapshot.boardId,
    snapshot.deadZoneStreak,
    snapshot.postCount,
    snapshot.threshold,
    snapshot.windowStart,
    snapshot.windowEnd,
    windowMs,
    timestamp,
    snapshot.status,
    traceId,
    timestamp
  ).run();
}
__name(recordDeadZoneAlert, "recordDeadZoneAlert");
async function detectDeadZones(env, options = {}) {
  await ensureSchema(env);
  const now = options.now ?? Date.now();
  const windowMs = options.windowMs ?? DEAD_ZONE_WINDOW_MS;
  const minPosts = options.minPosts ?? DEAD_ZONE_MIN_POSTS;
  const streakThreshold = options.streakThreshold ?? DEAD_ZONE_STREAK_THRESHOLD;
  const windowStart = now - windowMs;
  const boardRows = await env.BOARD_DB.prepare("SELECT id FROM boards ORDER BY id ASC").all();
  const boards = boardRows?.results ?? [];
  const snapshots = [];
  const alerts = [];
  for (const board of boards) {
    const boardId = board.id;
    const countRow = await env.BOARD_DB.prepare(
      `SELECT COUNT(*) AS post_count
         FROM posts
        WHERE board_id = ?1
          AND created_at >= ?2`
    ).bind(boardId, windowStart).first();
    const postCount = countRow?.post_count ?? 0;
    const status = postCount >= minPosts ? "healthy" : "dead_zone";
    const lastPostRow = await env.BOARD_DB.prepare(
      `SELECT MAX(created_at) AS last_post_at
         FROM posts
        WHERE board_id = ?1`
    ).bind(boardId).first();
    const previous = await getLatestFreshnessSnapshot(env, boardId);
    const previousStreak = typeof previous?.deadZoneStreak === "number" ? previous.deadZoneStreak : 0;
    const previousStatus = previous?.status;
    let deadZoneStreak = 0;
    if (status === "dead_zone") {
      deadZoneStreak = previousStatus === "dead_zone" ? previousStreak + 1 : 1;
    }
    const alertTriggered = status === "dead_zone" && deadZoneStreak >= streakThreshold;
    const traceId = crypto.randomUUID();
    const snapshot = {
      boardId,
      status,
      postCount,
      windowStart,
      windowEnd: now,
      threshold: minPosts,
      deadZoneStreak,
      alertTriggered,
      lastPostAt: lastPostRow?.last_post_at ?? null
    };
    const eventRecord = {
      id: crypto.randomUUID(),
      event: "board.freshness",
      data: snapshot,
      traceId,
      timestamp: now
    };
    await persistEvent(env, eventRecord, boardId);
    console.log(
      JSON.stringify({
        event: "board.freshness_sample",
        board_id: boardId,
        status,
        post_count: postCount,
        window_start: windowStart,
        window_end: now,
        dead_zone_streak: deadZoneStreak,
        alert_triggered: alertTriggered,
        last_post_at: snapshot.lastPostAt,
        trace_id: traceId
      })
    );
    if (alertTriggered) {
      alerts.push(snapshot);
      await recordDeadZoneAlert(env, snapshot, { windowMs, timestamp: now, traceId });
      const alertEvent = {
        id: crypto.randomUUID(),
        event: "board.dead_zone_triggered",
        data: {
          boardId,
          streak: deadZoneStreak,
          postCount,
          threshold: minPosts,
          windowStart,
          windowEnd: now,
          windowMs,
          traceId
        },
        traceId,
        timestamp: now
      };
      await persistEvent(env, alertEvent, boardId);
      console.log(
        JSON.stringify({
          event: "board.dead_zone_triggered",
          board_id: boardId,
          streak: deadZoneStreak,
          post_count: postCount,
          threshold: minPosts,
          window_ms: windowMs,
          timestamp: now,
          trace_id: traceId
        })
      );
    }
    snapshots.push(snapshot);
  }
  return {
    ok: true,
    windowStart,
    windowEnd: now,
    threshold: minPosts,
    streakThreshold,
    results: snapshots,
    alerts
  };
}
__name(detectDeadZones, "detectDeadZones");
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
      if (url.pathname === "/identity/logout") {
        return withCors(request, await handleLogout(request, env));
      }
      const upgradeHeader = request.headers.get("Upgrade");
      if (url.pathname === "/boards" && upgradeHeader === "websocket") {
        return handleWebsocket(request, env, ctx, url);
      }
      if (url.pathname === "/boards/catalog") {
        return withCors(request, await handleBoardsCatalog(request, env, url));
      }
      if (url.pathname.match(/^\/boards\/[^/]+\/phase$/)) {
        return withCors(request, await handlePhaseSettings(request, env, url));
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
      if (url.pathname.match(/^\/boards\/[^/]+\/posts\/[^/]+\/replies$/)) {
        return withCors(request, await handleReplies(request, env, ctx, url));
      }
      if (url.pathname.match(/^\/boards\/[^/]+\/feed$/)) {
        return withCors(request, await handleFeed(request, env, url));
      }
      if (url.pathname === "/follow") {
        return withCors(request, await handleFollow(request, env));
      }
      if (url.pathname === "/following/feed") {
        return withCors(request, await handleFollowingFeed(request, env, url));
      }
      if (url.pathname === "/search/posts") {
        return withCors(request, await handleSearchPosts(request, env, url));
      }
      if (url.pathname.match(/^\/profiles\/[^/]+$/)) {
        return withCors(request, await handleProfile(request, env, url));
      }
      if (url.pathname === "/metrics/dead-zones") {
        if (request.method !== "GET") {
          return withCors(request, new Response(JSON.stringify({ error: "method not allowed" }), {
            status: 405,
            headers: { "Content-Type": "application/json" }
          }));
        }
        const report = await detectDeadZones(env);
        return withCors(
          request,
          new Response(JSON.stringify(report), {
            status: 200,
            headers: { "Content-Type": "application/json" }
          })
        );
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
  },
  async scheduled(event, env) {
    const runTraceId = crypto.randomUUID();
    const scheduledTime = typeof event.scheduledTime === "number" ? event.scheduledTime : Date.now();
    try {
      const report = await detectDeadZones(env, { now: scheduledTime });
      console.log(
        JSON.stringify({
          event: "board.dead_zone_scheduled_run",
          trace_id: runTraceId,
          window_start: report.windowStart,
          window_end: report.windowEnd,
          boards_scanned: report.results.length,
          alerts_emitted: report.alerts.length,
          cron: typeof event.cron === "string" ? event.cron : null
        })
      );
      await snapshotBoardMetrics(env, { now: scheduledTime });
    } catch (error) {
      console.error("[worker] scheduled maintenance failure", error);
      if (typeof event.noRetry === "function") {
        event.noRetry();
      }
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
    } catch {
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
  } catch {
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
  const phaseConfig = getPhaseOneConfig(env);
  const normalizedBoardId = normalizeBoardId(boardId);
  const boardTextOnly = Boolean(board.text_only);
  const isTextOnly = boardTextOnly || phaseConfig.textOnlyBoards.has(normalizedBoardId);
  const uploadsEnabled = isImageUploadsEnabled(env);
  const rawImages = Array.isArray(payload.images) ? payload.images : [];
  let sanitizedImages = null;
  if (rawImages.length > 0) {
    if (isTextOnly) {
      return new Response(JSON.stringify({ error: "images are disabled for this board", trace_id: traceId }), {
        status: 403,
        headers: { "Content-Type": "application/json" }
      });
    }
    if (!uploadsEnabled) {
      return new Response(JSON.stringify({ error: "image uploads are currently disabled", trace_id: traceId }), {
        status: 403,
        headers: { "Content-Type": "application/json" }
      });
    }
    if (rawImages.length > MAX_IMAGE_COUNT) {
      return new Response(
        JSON.stringify({ error: `maximum of ${MAX_IMAGE_COUNT} images per post`, trace_id: traceId }),
        {
          status: 400,
          headers: { "Content-Type": "application/json" }
        }
      );
    }
    sanitizedImages = [];
    const seen = /* @__PURE__ */ new Set();
    for (let index = 0; index < rawImages.length; index += 1) {
      const image = rawImages[index];
      if (!image || typeof image !== "object") {
        return new Response(JSON.stringify({ error: `invalid image payload at index ${index}`, trace_id: traceId }), {
          status: 400,
          headers: { "Content-Type": "application/json" }
        });
      }
      const name = typeof image.name === "string" ? image.name.trim() : "";
      const type = typeof image.type === "string" ? image.type.toLowerCase() : "";
      const size = typeof image.size === "number" ? image.size : NaN;
      if (!name) {
        return new Response(JSON.stringify({ error: `image name required at index ${index}`, trace_id: traceId }), {
          status: 400,
          headers: { "Content-Type": "application/json" }
        });
      }
      if (!ALLOWED_IMAGE_TYPES.has(type)) {
        return new Response(JSON.stringify({ error: `unsupported image type at index ${index}`, trace_id: traceId }), {
          status: 400,
          headers: { "Content-Type": "application/json" }
        });
      }
      if (!Number.isFinite(size) || size <= 0 || size > MAX_IMAGE_SIZE_BYTES) {
        return new Response(JSON.stringify({ error: `image too large at index ${index}`, trace_id: traceId }), {
          status: 400,
          headers: { "Content-Type": "application/json" }
        });
      }
      const id = typeof image.id === "string" ? image.id.trim() : void 0;
      const checksum = typeof image.checksum === "string" ? image.checksum.trim() : void 0;
      const dedupeKey = id ?? checksum;
      if (dedupeKey) {
        if (seen.has(dedupeKey)) {
          return new Response(JSON.stringify({ error: `duplicate image reference ${dedupeKey}`, trace_id: traceId }), {
            status: 400,
            headers: { "Content-Type": "application/json" }
          });
        }
        seen.add(dedupeKey);
      }
      sanitizedImages.push({
        id: id || void 0,
        name,
        type,
        size,
        width: typeof image.width === "number" && image.width > 0 ? image.width : void 0,
        height: typeof image.height === "number" && image.height > 0 ? image.height : void 0,
        checksum: checksum || void 0
      });
    }
  }
  const imageRefs = sanitizedImages ? sanitizedImages.map((image) => image.id ?? image.checksum ?? image.name) : void 0;
  const post = await createPost(
    env,
    board.id,
    body,
    author,
    userId,
    aliasRecord?.alias ?? null,
    user?.pseudonym ?? null,
    imageRefs,
    board.display_name ?? null
  );
  const postWithImages = imageRefs && imageRefs.length > 0 ? { ...post, images: imageRefs } : post;
  const room = getBoardRoom(boardId);
  const eventRecord = {
    id: post.id,
    event: "post.created",
    data: postWithImages,
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
  const responseBody = { ok: true, post: postWithImages };
  return new Response(JSON.stringify(responseBody), {
    status: 201,
    headers: { "Content-Type": "application/json" }
  });
}
__name(handleCreatePost, "handleCreatePost");
async function handleReplies(request, env, ctx, url) {
  const match = url.pathname.match(/^\/boards\/([^/]+)\/posts\/([^/]+)\/replies$/);
  if (!match) {
    throw new ApiError(404, { error: "not found" });
  }
  const boardId = decodeURIComponent(match[1]);
  const postId = decodeURIComponent(match[2]);
  if (request.method === "GET") {
    const urlCursor = url.searchParams.get("cursor") ?? null;
    const limitParam = Number(url.searchParams.get("limit") ?? "50");
    const limit = Number.isFinite(limitParam) && limitParam > 0 ? Math.min(limitParam, 100) : 50;
    const { replies, cursor } = await listReplies(env, boardId, postId, { limit, cursor: urlCursor });
    const response2 = {
      ok: true,
      postId,
      replies,
      cursor,
      hasMore: Boolean(cursor)
    };
    return new Response(JSON.stringify(response2), {
      status: 200,
      headers: { "Content-Type": "application/json" }
    });
  }
  if (request.method !== "POST") {
    return new Response(JSON.stringify({ error: "method not allowed" }), {
      status: 405,
      headers: { "Content-Type": "application/json" }
    });
  }
  const traceId = request.headers.get("cf-ray") ?? crypto.randomUUID();
  let payload;
  try {
    payload = await request.json();
  } catch {
    throw new ApiError(400, { error: "invalid JSON payload", trace_id: traceId });
  }
  const body = payload.body?.trim();
  if (!body) {
    throw new ApiError(400, { error: "reply body required", trace_id: traceId });
  }
  if (body.length > 300) {
    throw new ApiError(400, { error: "reply body must be 300 characters or fewer", trace_id: traceId });
  }
  const userId = payload.userId?.trim() || null;
  const authorInput = payload.author?.trim()?.slice(0, 64) ?? null;
  let author = authorInput;
  let user = null;
  let aliasRecord = null;
  if (userId) {
    await ensureSession(request, env, userId);
    user = await getUserById(env, userId);
    if (!user) {
      throw new ApiError(404, { error: "user not found", trace_id: traceId });
    }
    aliasRecord = await getBoardAlias(env, boardId, userId);
    author = aliasRecord?.alias ?? author ?? user.pseudonym;
  }
  const board = await getOrCreateBoard(env, boardId);
  const reply = await createReply(env, {
    board,
    postId,
    body,
    author,
    user,
    alias: aliasRecord?.alias ?? null
  });
  ctx.waitUntil(
    persistEvent(env, {
      id: crypto.randomUUID(),
      boardId,
      event: "reply.created",
      data: reply,
      traceId,
      timestamp: Date.now()
    }, boardId)
  );
  const response = { ok: true, reply };
  return new Response(JSON.stringify(response), {
    status: 201,
    headers: { "Content-Type": "application/json" }
  });
}
__name(handleReplies, "handleReplies");
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
async function handleLogout(request, env) {
  if (request.method !== "POST") {
    return new Response(JSON.stringify({ error: "Method not allowed" }), {
      status: 405,
      headers: { "Content-Type": "application/json", Allow: "POST" }
    });
  }
  const token = getSessionTokenFromRequest(request);
  if (!token) {
    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        "Set-Cookie": `${SESSION_COOKIE_NAME}=; Max-Age=0; Path=/; SameSite=Lax`
      }
    });
  }
  await deleteSessionByToken(env, token);
  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: {
      "Content-Type": "application/json",
      "Set-Cookie": `${SESSION_COOKIE_NAME}=; Max-Age=0; Path=/; SameSite=Lax`
    }
  });
}
__name(handleLogout, "handleLogout");
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
  } catch {
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
  } catch {
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
async function handlePhaseSettings(request, env, url) {
  const match = url.pathname.match(/^\/boards\/([^/]+)\/phase$/);
  const boardId = decodeURIComponent(match[1]);
  requirePhaseAdmin(request, env);
  const board = await getOrCreateBoard(env, boardId);
  let existingState = null;
  if (board.radius_state) {
    try {
      existingState = JSON.parse(board.radius_state);
    } catch (error) {
      console.warn("[phase] failed to parse stored radius state", error);
    }
  }
  if (request.method === "GET") {
    return new Response(
      JSON.stringify({
        boardId,
        phaseMode: board.phase_mode === "phase1" ? "phase1" : "default",
        textOnly: Boolean(board.text_only),
        radiusMeters: board.radius_meters ?? existingState?.currentMeters ?? 1500
      }),
      {
        status: 200,
        headers: { "Content-Type": "application/json" }
      }
    );
  }
  if (request.method !== "PUT" && request.method !== "PATCH") {
    return new Response(JSON.stringify({ error: "method not allowed" }), {
      status: 405,
      headers: { "Content-Type": "application/json" }
    });
  }
  let payloadRaw;
  try {
    payloadRaw = await request.json();
  } catch {
    throw new ApiError(400, { error: "invalid JSON payload" });
  }
  const payload = typeof payloadRaw === "object" && payloadRaw !== null ? payloadRaw : {};
  const phaseMode = payload["phaseMode"] === "phase1" ? "phase1" : "default";
  const textOnly = Boolean(payload["textOnly"]);
  const radiusInput = Number(payload["radiusMeters"]);
  const requestedRadius = Number.isFinite(radiusInput) && radiusInput > 0 ? Math.max(250, Math.min(radiusInput, 5e3)) : null;
  const latitudeInput = Number(payload["latitude"]);
  const hasLatitude = Number.isFinite(latitudeInput);
  const longitudeInput = Number(payload["longitude"]);
  const hasLongitude = Number.isFinite(longitudeInput);
  const nextRadiusMeters = phaseMode === "phase1" ? requestedRadius ?? existingState?.currentMeters ?? board.radius_meters ?? 1500 : board.radius_meters ?? existingState?.currentMeters ?? 1500;
  const nextRadiusState = phaseMode === "phase1" ? {
    currentMeters: nextRadiusMeters,
    lastExpandedAt: existingState?.lastExpandedAt ?? null,
    lastContractedAt: existingState?.lastContractedAt ?? null
  } : existingState ?? {
    currentMeters: nextRadiusMeters,
    lastExpandedAt: null,
    lastContractedAt: null
  };
  const now = Date.now();
  await env.BOARD_DB.prepare(
    `UPDATE boards
        SET phase_mode = ?1,
            text_only = ?2,
            radius_meters = ?3,
            radius_state = ?4,
            radius_updated_at = ?5,
            latitude = COALESCE(?6, latitude),
            longitude = COALESCE(?7, longitude)
      WHERE id = ?8`
  ).bind(
    phaseMode,
    textOnly ? 1 : 0,
    nextRadiusMeters,
    JSON.stringify(nextRadiusState),
    now,
    hasLatitude ? latitudeInput : null,
    hasLongitude ? longitudeInput : null,
    boardId
  ).run();
  board.phase_mode = phaseMode;
  board.text_only = textOnly ? 1 : 0;
  board.radius_meters = nextRadiusMeters;
  board.radius_state = JSON.stringify(nextRadiusState);
  board.radius_updated_at = now;
  if (hasLatitude) {
    board.latitude = latitudeInput;
  }
  if (hasLongitude) {
    board.longitude = longitudeInput;
  }
  return new Response(
    JSON.stringify({
      boardId,
      phaseMode,
      textOnly,
      radiusMeters: nextRadiusMeters,
      latitude: board.latitude ?? null,
      longitude: board.longitude ?? null
    }),
    {
      status: 200,
      headers: { "Content-Type": "application/json" }
    }
  );
}
__name(handlePhaseSettings, "handlePhaseSettings");
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
  } catch {
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
  } catch {
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
async function handleFollow(request, env) {
  if (request.method !== "POST") {
    return new Response(JSON.stringify({ error: "method not allowed" }), {
      status: 405,
      headers: { "Content-Type": "application/json", Allow: "POST" }
    });
  }
  const session = await getSessionFromRequest(request, env);
  const followerId = session.user_id;
  let payload;
  try {
    payload = await request.json();
  } catch {
    throw new ApiError(400, { error: "invalid JSON body" });
  }
  const targetUserId = payload?.targetUserId?.trim();
  if (!targetUserId) {
    throw new ApiError(400, { error: "targetUserId is required" });
  }
  if (targetUserId === followerId) {
    throw new ApiError(400, { error: "cannot follow yourself" });
  }
  const target = await getUserById(env, targetUserId);
  if (!target) {
    throw new ApiError(404, { error: "target user not found" });
  }
  const follow = payload.action !== "unfollow";
  const following = await setFollowState(env, followerId, targetUserId, follow);
  const targetCounts = await getFollowCounts(env, targetUserId);
  const viewerCounts = followerId === targetUserId ? targetCounts : await getFollowCounts(env, followerId);
  const body = {
    ok: true,
    following,
    followerCount: targetCounts.followerCount,
    followingCount: viewerCounts.followingCount
  };
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "Content-Type": "application/json" }
  });
}
__name(handleFollow, "handleFollow");
async function handleFollowingFeed(request, env, url) {
  if (request.method !== "GET") {
    return new Response(JSON.stringify({ error: "method not allowed" }), {
      status: 405,
      headers: { "Content-Type": "application/json", Allow: "GET" }
    });
  }
  const session = await getSessionFromRequest(request, env);
  const limitParam = Number(url.searchParams.get("limit") ?? "20");
  const limit = Number.isFinite(limitParam) ? limitParam : 20;
  const cursor = url.searchParams.get("cursor");
  const feed = await listFollowingPosts(env, session.user_id, { limit, cursor });
  const response = {
    ok: true,
    posts: feed.posts,
    cursor: feed.cursor,
    hasMore: feed.hasMore
  };
  return new Response(JSON.stringify(response), {
    status: 200,
    headers: { "Content-Type": "application/json" }
  });
}
__name(handleFollowingFeed, "handleFollowingFeed");
async function handleBoardsCatalog(request, env, url) {
  if (request.method !== "GET") {
    return new Response(JSON.stringify({ error: "method not allowed" }), {
      status: 405,
      headers: { "Content-Type": "application/json", Allow: "GET" }
    });
  }
  const limitParam = Number(url.searchParams.get("limit") ?? "12");
  const limit = Number.isFinite(limitParam) ? limitParam : 12;
  const boards = await listBoardsCatalog(env, { limit });
  const response = {
    ok: true,
    boards
  };
  return new Response(JSON.stringify(response), {
    status: 200,
    headers: { "Content-Type": "application/json" }
  });
}
__name(handleBoardsCatalog, "handleBoardsCatalog");
async function handleSearchPosts(request, env, url) {
  if (request.method !== "GET") {
    return new Response(JSON.stringify({ error: "method not allowed" }), {
      status: 405,
      headers: { "Content-Type": "application/json", Allow: "GET" }
    });
  }
  const boardId = url.searchParams.get("boardId");
  const query = url.searchParams.get("q");
  const limitParam = Number(url.searchParams.get("limit") ?? "20");
  const limit = Number.isFinite(limitParam) ? limitParam : 20;
  const cursor = url.searchParams.get("cursor");
  const windowParam = Number(url.searchParams.get("windowMs") ?? "0");
  const windowMs = Number.isFinite(windowParam) && windowParam > 0 ? windowParam : void 0;
  const search = await searchBoardPosts(env, {
    boardId,
    query,
    limit,
    cursor,
    windowMs
  });
  let topics = [];
  if (boardId) {
    const trendingSource = await listPosts(env, boardId, 40);
    topics = extractTrendingTopics(trendingSource, 6);
  } else if (!query) {
    topics = extractTrendingTopics(search.posts, 6);
  }
  const response = {
    ok: true,
    posts: search.posts,
    cursor: search.cursor,
    hasMore: search.hasMore,
    topics
  };
  return new Response(JSON.stringify(response), {
    status: 200,
    headers: { "Content-Type": "application/json" }
  });
}
__name(handleSearchPosts, "handleSearchPosts");
async function handleProfile(request, env, url) {
  if (request.method !== "GET") {
    return new Response(JSON.stringify({ error: "method not allowed" }), {
      status: 405,
      headers: { "Content-Type": "application/json", Allow: "GET" }
    });
  }
  const match = url.pathname.match(/^\/profiles\/([^/]+)$/);
  if (!match) {
    throw new ApiError(404, { error: "not found" });
  }
  const profileUserId = decodeURIComponent(match[1]);
  const user = await getUserById(env, profileUserId);
  if (!user) {
    throw new ApiError(404, { error: "user not found" });
  }
  let viewerId = null;
  const token = parseBearerToken(request);
  if (token) {
    const session = await getSessionByToken(env, token);
    if (session && session.expires_at >= Date.now()) {
      viewerId = session.user_id;
    }
  }
  const [posts, aliases, counts] = await Promise.all([
    listUserPosts(env, profileUserId, 15),
    listAliasesForUser(env, profileUserId, 30),
    getFollowCounts(env, profileUserId)
  ]);
  const influence = calculateInfluenceScore(posts);
  const followingIds = await listFollowingIds(env, profileUserId, 100);
  const viewerFollows = viewerId ? await isFollowing(env, viewerId, profileUserId) : false;
  const response = {
    ok: true,
    user: {
      id: user.id,
      pseudonym: user.pseudonym,
      createdAt: user.created_at,
      influence,
      followerCount: counts.followerCount,
      followingCount: counts.followingCount
    },
    aliases,
    recentPosts: posts,
    followingIds,
    viewerFollows
  };
  return new Response(JSON.stringify(response), {
    status: 200,
    headers: { "Content-Type": "application/json" }
  });
}
__name(handleProfile, "handleProfile");
async function handleFeed(request, env, url) {
  const match = url.pathname.match(/^\/boards\/([^/]+)\/feed$/);
  const boardId = decodeURIComponent(match[1]);
  const limitParam = Number(url.searchParams.get("limit") ?? "20");
  const limit = Number.isFinite(limitParam) ? Math.max(0, Math.min(limitParam, 50)) : 20;
  const board = await getOrCreateBoard(env, boardId);
  const phaseConfig = getPhaseOneConfig(env);
  const normalizedBoardId = normalizeBoardId(boardId);
  const boardPhaseMode = board.phase_mode === "phase1";
  const boardTextOnly = Boolean(board.text_only);
  const isPhaseOne = boardPhaseMode || phaseConfig.boards.has(normalizedBoardId);
  const isTextOnly = boardTextOnly || phaseConfig.textOnlyBoards.has(normalizedBoardId);
  const phaseOneRadius = boardPhaseMode ? board.radius_meters ?? phaseConfig.radiusMeters : phaseConfig.radiusMeters;
  const now = Date.now();
  const posts = await listPosts(env, boardId, limit, { now });
  const postsInWindowRow = await env.BOARD_DB.prepare(
    `SELECT COUNT(*) AS post_count
       FROM posts
      WHERE board_id = ?1
        AND created_at >= ?2`
  ).bind(boardId, now - ADAPTIVE_RADIUS_WINDOW_MS).first();
  const postsInWindow = postsInWindowRow?.post_count ?? 0;
  let storedRadiusState = null;
  if (board.radius_state) {
    try {
      storedRadiusState = JSON.parse(board.radius_state);
    } catch (error) {
      console.warn("[board] failed to parse radius state", error);
    }
  }
  if (!storedRadiusState) {
    const currentMeters = typeof board.radius_meters === "number" && !Number.isNaN(board.radius_meters) ? board.radius_meters : 1500;
    storedRadiusState = {
      currentMeters,
      lastExpandedAt: null,
      lastContractedAt: null
    };
  }
  let adaptiveState;
  if (isPhaseOne) {
    adaptiveState = {
      currentMeters: phaseOneRadius,
      lastExpandedAt: storedRadiusState.lastExpandedAt,
      lastContractedAt: storedRadiusState.lastContractedAt
    };
  } else {
    adaptiveState = getAdaptiveRadius(
      storedRadiusState,
      {
        postsInWindow,
        freshThreshold: ADAPTIVE_RADIUS_FRESH_THRESHOLD,
        staleThreshold: ADAPTIVE_RADIUS_STALE_THRESHOLD,
        now
      },
      {
        minimumMeters: 250,
        maximumMeters: 2e3,
        contractionStepMeters: 150,
        expansionStepMeters: 200,
        initialMeters: storedRadiusState.currentMeters
      }
    );
  }
  const stateChanged = Math.round(adaptiveState.currentMeters) !== Math.round(board.radius_meters ?? adaptiveState.currentMeters) || JSON.stringify(storedRadiusState) !== JSON.stringify(adaptiveState);
  if (stateChanged) {
    await env.BOARD_DB.prepare(
      `UPDATE boards
          SET radius_meters = ?1,
              radius_state = ?2,
              radius_updated_at = ?3
        WHERE id = ?4`
    ).bind(adaptiveState.currentMeters, JSON.stringify(adaptiveState), now, boardId).run();
    board.radius_meters = adaptiveState.currentMeters;
    board.radius_state = JSON.stringify(adaptiveState);
    board.radius_updated_at = now;
  }
  const room = boardRooms.get(boardId);
  const responseBody = {
    board: {
      id: board.id,
      displayName: board.display_name,
      description: board.description,
      createdAt: board.created_at,
      radiusMeters: board.radius_meters ?? adaptiveState.currentMeters,
      radiusUpdatedAt: board.radius_updated_at ?? null,
      phaseMode: isPhaseOne ? "phase1" : "default",
      textOnly: isTextOnly,
      latitude: board.latitude ?? null,
      longitude: board.longitude ?? null
    },
    posts,
    realtimeConnections: room?.getConnectionCount() ?? 0,
    spaces: buildBoardSpaces(posts)
  };
  return new Response(JSON.stringify(responseBody), {
    status: 200,
    headers: { "Content-Type": "application/json" }
  });
}
__name(handleFeed, "handleFeed");
function mapReplyRowToReply(row) {
  return {
    id: row.id,
    postId: row.post_id,
    boardId: row.board_id,
    userId: row.user_id,
    author: row.author,
    alias: row.board_alias,
    pseudonym: row.pseudonym,
    body: row.body,
    createdAt: row.created_at
  };
}
__name(mapReplyRowToReply, "mapReplyRowToReply");
function buildBoardSpaces(posts) {
  const base = [
    { id: "home", label: "Home", type: "default" },
    { id: "student-life", label: "Student Life", type: "default" },
    { id: "events", label: "Events", type: "events" },
    { id: "sports", label: "Sports", type: "default" }
  ];
  const hashtagRegex = /#[\p{L}0-9_-]+/gu;
  const counts = /* @__PURE__ */ new Map();
  for (const post of posts) {
    const matches = post.body.match(hashtagRegex);
    if (!matches) continue;
    for (const tag of matches) {
      const normalized = tag.toLowerCase();
      counts.set(normalized, (counts.get(normalized) ?? 0) + 1);
    }
  }
  const dynamic = Array.from(counts.entries()).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([tag, count]) => ({
    id: `topic-${tag.slice(1).toLowerCase()}`,
    label: tag,
    type: "topic",
    metadata: { count, topic: tag }
  }));
  const seen = /* @__PURE__ */ new Set();
  return [...base, ...dynamic].filter((space) => {
    if (seen.has(space.id)) return false;
    seen.add(space.id);
    return true;
  });
}
__name(buildBoardSpaces, "buildBoardSpaces");
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
      let rawPayload;
      try {
        rawPayload = await request.json();
      } catch {
        return new Response(JSON.stringify({ error: "Invalid JSON payload", trace_id: traceId }), {
          status: 400,
          headers: { "Content-Type": "application/json" }
        });
      }
      const payload = typeof rawPayload === "object" && rawPayload !== null ? rawPayload : {};
      const eventField = payload["event"];
      const eventName = typeof eventField === "string" && eventField.trim() ? eventField.trim() : "message";
      const timestamp = Date.now();
      const record = {
        id: crypto.randomUUID(),
        boardId,
        event: eventName,
        data: payload["data"] ?? null,
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

// .wrangler/tmp/bundle-IsAnpi/middleware-insertion-facade.js
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

// .wrangler/tmp/bundle-IsAnpi/middleware-loader.entry.ts
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
  createReply,
  createUser,
  middleware_loader_entry_default as default,
  detectDeadZones,
  ensureSchema,
  getBoardAlias,
  getFollowCounts,
  getOrCreateBoard,
  isFollowing,
  listAliasesForUser,
  listBoardsCatalog,
  listFollowingIds,
  listFollowingPosts,
  listPosts,
  listUserPosts,
  persistEvent,
  searchBoardPosts,
  setFollowState,
  snapshotBoardMetrics,
  upsertBoardAlias
};
//# sourceMappingURL=index.js.map
