import { Hono } from 'hono';
import { cors } from 'hono/cors';
import authRoutes from './routes/auth';
import boardsRoutes from './routes/boards';
import postsRoutes from './routes/posts';
import usersRoutes from './routes/users';
import { BoardRoom, type BoardWebSocket } from './board-room';
import {
  getBoardRoom,
  detectDeadZones,
  snapshotBoardMetrics,
  persistEvent,
  boardRooms
} from './lib/board';
import { BoardRoomDO } from './durable-objects/board-room';
import {
  resolveAccessUser,
  ensureAccessPrincipalForUser,
  deriveAccessPseudonym
} from './lib/user';
import {
  getSessionFromRequest
} from './lib/session';

export { BoardRoomDO } from './durable-objects/board-room';


type WebSocketRequest = Request & { webSocket?: WebSocket };

export interface Env {
  BOARD_DB: D1Database;
  BOARD_ROOM_DO: DurableObjectNamespace;
  ACCESS_JWT_AUDIENCE?: string;
  ACCESS_JWT_ISSUER?: string;
  ACCESS_JWT_JWKS_URL?: string;
  PHASE_ONE_BOARDS?: string;
  PHASE_ONE_TEXT_ONLY_BOARDS?: string;
  PHASE_ONE_RADIUS_METERS?: string;
  PHASE_ADMIN_TOKEN?: string;
  ENABLE_IMAGE_UPLOADS?: string;
  ALLOWED_ORIGINS?: string;
}


const DEFAULT_ALLOWED_ORIGINS = ['http://localhost:3000', 'http://127.0.0.1:3000', 'http://localhost:3002'];

class ApiError extends Error {
  status: number;
  body: Record<string, unknown>;

  constructor(status: number, body: Record<string, unknown>) {
    super(typeof body.error === 'string' ? body.error : 'error');
    this.status = status;
    this.body = body;
  }
}

function withCors(request: Request, response: Response, env: Env) {
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


export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    // Health check endpoint
    if (url.pathname === '/' || url.pathname === '/health') {
      return new Response(JSON.stringify({
        status: 'ok',
        service: 'board-app-workers',
        version: '1.0.0',
        timestamp: new Date().toISOString()
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Configure CORS middleware
    const allowedOrigins = env.ALLOWED_ORIGINS
      ? env.ALLOWED_ORIGINS.split(',').map(o => o.trim())
      : DEFAULT_ALLOWED_ORIGINS;

    const corsMiddleware = cors({
      origin: (origin) => {
        return allowedOrigins.includes(origin) ? origin : allowedOrigins[0];
      },
      allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
      allowHeaders: ['Content-Type', 'Authorization', 'CF-Board-ID', 'CF-Trace-ID'],
      maxAge: 86400,
      credentials: true
    });

    // Use Hono for /identity/* routes
    if (url.pathname.startsWith('/identity')) {
      const app = new Hono<{ Bindings: Env }>();
      app.use('*', corsMiddleware);
      app.route('/', authRoutes);
      return app.fetch(request, env, ctx);
    }

    // Use Hono for /boards/* routes (excluding websocket)
    const upgradeHeader = request.headers.get('Upgrade');
    if (url.pathname.startsWith('/boards') && upgradeHeader !== 'websocket') {
      const app = new Hono<{ Bindings: Env }>();
      app.use('*', corsMiddleware);
      app.route('/boards', boardsRoutes);
      return app.fetch(request, env, ctx);
    }

    // Use Hono for /following/* and /search/* routes (Posts)
    if (url.pathname.startsWith('/following') || url.pathname.startsWith('/search')) {
      const app = new Hono<{ Bindings: Env }>();
      app.use('*', corsMiddleware);
      app.route('/', postsRoutes);
      return app.fetch(request, env, ctx);
    }

    // Use Hono for /profiles/* and /follow routes (Users)
    if (url.pathname.startsWith('/profiles') || url.pathname === '/follow') {
      const app = new Hono<{ Bindings: Env }>();
      app.use('*', corsMiddleware);
      app.route('/', usersRoutes);
      return app.fetch(request, env, ctx);
    }

    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 204, headers: {
          'Access-Control-Allow-Origin': request.headers.get('Origin') || allowedOrigins[0],
          'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization, CF-Board-ID, CF-Trace-ID',
          'Access-Control-Max-Age': '86400',
          'Access-Control-Allow-Credentials': 'true',
          'Vary': 'Origin'
        }
      });
    }

    if (url.pathname === '/boards' && upgradeHeader === 'websocket') {
      return handleWebsocket(request, env, ctx, url);
    }

    try {
      if (url.pathname === '/metrics/dead-zones') {
        if (request.method !== 'GET') {
          return new Response(JSON.stringify({ error: 'method not allowed' }), {
            status: 405,
            headers: { 'Content-Type': 'application/json' }
          });
        }
        const report = await detectDeadZones(env);
        return new Response(JSON.stringify(report), {
          status: 200,
          headers: { 'Content-Type': 'application/json' }
        });
      }

      return new Response('Not Found', { status: 404 });
    } catch (error: unknown) {
      if (error instanceof ApiError) {
        return new Response(JSON.stringify(error.body), {
          status: error.status,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      console.error('[worker] unexpected error', error);
      return new Response(JSON.stringify({ error: 'internal' }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  },
  async scheduled(event: ScheduledController, env: Env): Promise<void> {
    const runTraceId = crypto.randomUUID();
    const scheduledTime = typeof event.scheduledTime === 'number' ? event.scheduledTime : Date.now();
    try {
      const report = await detectDeadZones(env, { now: scheduledTime });
      console.log(
        JSON.stringify({
          event: 'board.dead_zone_scheduled_run',
          trace_id: runTraceId,
          window_start: report.windowStart,
          window_end: report.windowEnd,
          boards_scanned: report.results.length,
          alerts_emitted: report.alerts.length,
          cron: typeof event.cron === 'string' ? event.cron : null
        })
      );

      await snapshotBoardMetrics(env, { now: scheduledTime });
    } catch (error) {
      console.error('[worker] scheduled maintenance failure', error);
      if (typeof event.noRetry === 'function') {
        event.noRetry();
      }
    }
  }
};

const __internal = {
  resolveAccessUser,
  ensureAccessPrincipalForUser,
  deriveAccessPseudonym
};

export {
  detectDeadZones,
  __internal
};

async function handleWebsocket(request: Request, env: Env, ctx: ExecutionContext, url: URL) {
  const boardId = url.searchParams.get('boardId');
  if (!boardId) {
    return withCors(
      request,
      new Response(JSON.stringify({ error: 'Method not allowed' }), {
        status: 405,
        headers: { 'Content-Type': 'application/json' }
      }),
      env
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
