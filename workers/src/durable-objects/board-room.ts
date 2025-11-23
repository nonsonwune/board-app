import type { BoardWebSocket } from '../board-room';
import type { BoardEventPayload } from '@board-app/shared';

type WebSocketRequest = Request & { webSocket?: WebSocket };

type BoardEventRecord = BoardEventPayload & { boardId: string };

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

    private rateLimits = new Map<string, { count: number; expires: number }>();

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
            let rawPayload: unknown;
            try {
                rawPayload = await request.json();
            } catch {
                return new Response(JSON.stringify({ error: 'Invalid JSON payload', trace_id: traceId }), {
                    status: 400,
                    headers: { 'Content-Type': 'application/json' }
                });
            }

            const payload =
                typeof rawPayload === 'object' && rawPayload !== null
                    ? (rawPayload as Record<string, unknown>)
                    : {};

            const eventField = payload['event'];
            const eventName = typeof eventField === 'string' && eventField.trim() ? eventField.trim() : 'message';
            const timestamp = Date.now();
            const record: BoardEventRecord = {
                id: crypto.randomUUID(),
                boardId,
                event: eventName,
                data: payload['data'] ?? null,
                traceId,
                timestamp
            };

            await this.appendEvent(record);

            return new Response(JSON.stringify({ ok: true, event: record }), {
                status: 200,
                headers: { 'Content-Type': 'application/json' }
            });
        }

        if (request.method === 'POST' && url.pathname === '/rate-limit') {
            let payload: unknown;
            try {
                payload = await request.json();
            } catch {
                return new Response(JSON.stringify({ error: 'Invalid JSON' }), { status: 400 });
            }

            const data = payload as { key: string; limit: number; windowMs: number };
            if (!data.key || !data.limit || !data.windowMs) {
                return new Response(JSON.stringify({ error: 'Missing parameters' }), { status: 400 });
            }

            const now = Date.now();
            const entry = this.rateLimits.get(data.key);

            if (entry && entry.expires > now) {
                if (entry.count >= data.limit) {
                    return new Response(JSON.stringify({ allowed: false, remaining: 0, reset: entry.expires }), {
                        status: 429,
                        headers: { 'Content-Type': 'application/json' }
                    });
                }
                entry.count++;
                return new Response(JSON.stringify({ allowed: true, remaining: data.limit - entry.count, reset: entry.expires }), {
                    status: 200,
                    headers: { 'Content-Type': 'application/json' }
                });
            }

            // New window
            this.rateLimits.set(data.key, { count: 1, expires: now + data.windowMs });

            // Cleanup old entries occasionally
            if (this.rateLimits.size > 1000) {
                for (const [k, v] of this.rateLimits.entries()) {
                    if (v.expires <= now) {
                        this.rateLimits.delete(k);
                    }
                }
            }

            return new Response(JSON.stringify({ allowed: true, remaining: data.limit - 1, reset: now + data.windowMs }), {
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
