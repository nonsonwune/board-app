/* eslint-disable @typescript-eslint/no-explicit-any */
import { describe, expect, it } from 'vitest';
import { BoardRoom, type BoardRoomMetadata, type BoardWebSocket } from '../board-room';

type Listener<T> = (event: T) => void;

type MessageEventLike = { data: string };
type CloseEventLike = { code?: number; reason?: string };
type ErrorEventLike = { error: unknown };

class MockSocket implements BoardWebSocket {
  readyState = 1;
  accepted = false;
  sent: string[] = [];
  closedWith: { code?: number; reason?: string } | null = null;

  private readonly listeners: {
    message: Set<Listener<MessageEventLike>>;
    close: Set<Listener<CloseEventLike>>;
    error: Set<Listener<ErrorEventLike>>;
  } = {
    message: new Set(),
    close: new Set(),
    error: new Set()
  };

  accept() {
    this.accepted = true;
  }

  send(data: string) {
    this.sent.push(data);
  }

  close(code?: number, reason?: string) {
    this.closedWith = { code, reason };
    this.readyState = 3;
    for (const listener of this.listeners.close) {
      listener({ code, reason });
    }
  }

  addEventListener(type: 'message', listener: Listener<MessageEventLike>): void;
  addEventListener(type: 'close', listener: Listener<CloseEventLike>): void;
  addEventListener(type: 'error', listener: Listener<ErrorEventLike>): void;
  addEventListener(type: 'message' | 'close' | 'error', listener: Listener<any>) {
    (this.listeners[type] as Set<Listener<any>>).add(listener);
  }

  emitMessage(payload: unknown) {
    const data = typeof payload === 'string' ? payload : JSON.stringify(payload);
    for (const listener of this.listeners.message) {
      listener({ data });
    }
  }

  emitError(error: unknown) {
    for (const listener of this.listeners.error) {
      listener({ error });
    }
  }
}

describe('BoardRoom', () => {
  const metadata: BoardRoomMetadata = {
    boardId: 'demo-board',
    traceId: 'trace-123'
  };

  const createRoom = () => new BoardRoom({ boardId: 'do-demo-board', now: () => 1_701_000_000_000, keepAliveMs: 0 });

  it('sends ack on connect', async () => {
    const room = createRoom();
    const socket = new MockSocket();

    const closed = room.handleConnection(socket, metadata);

    expect(socket.accepted).toBe(true);
    expect(socket.sent).toHaveLength(1);

    const ack = JSON.parse(socket.sent[0]);
    expect(ack).toMatchObject({
      type: 'ack',
      boardId: metadata.boardId,
      trace_id: metadata.traceId
    });
    expect(typeof ack.connectionId).toBe('string');

    socket.close(1000, 'test complete');
    await closed;
  });

  it('responds to ping with pong and optional close', async () => {
    const room = createRoom();
    const socket = new MockSocket();

    const closed = room.handleConnection(socket, metadata);
    socket.sent = [];

    socket.emitMessage({ type: 'ping' });
    expect(JSON.parse(socket.sent.at(-1)!)).toMatchObject({ type: 'pong', boardId: metadata.boardId });
    expect(socket.closedWith).toBeNull();

    socket.emitMessage({ type: 'ping', closeAfterPong: true });
    const last = JSON.parse(socket.sent.at(-1)!);
    expect(last).toMatchObject({ type: 'pong' });
    expect(socket.closedWith).toMatchObject({ code: 1000, reason: 'pong complete' });

    await closed;
  });

  it('broadcasts events to other clients', async () => {
    const room = createRoom();
    const socketA = new MockSocket();
    const socketB = new MockSocket();

    const closedA = room.handleConnection(socketA, metadata);
    const closedB = room.handleConnection(socketB, metadata);

    socketA.sent = [];
    socketB.sent = [];

    socketA.emitMessage({ type: 'broadcast', event: 'note', data: { body: 'hello' } });

    await new Promise(resolve => setTimeout(resolve, 0));

    expect(socketB.sent).toHaveLength(1);
    const payload = JSON.parse(socketB.sent[0]);
    expect(payload).toMatchObject({ type: 'event', event: 'note', data: { body: 'hello' } });
    expect(payload.origin).toBeDefined();
    expect(payload.boardId).toBe(metadata.boardId);

    expect(socketA.sent).toHaveLength(0);

    socketA.close(1000, 'done');
    socketB.close(1000, 'done');

    await Promise.all([closedA, closedB]);
  });

  it('can optionally echo broadcasts back to sender and tracks connections', async () => {
    const room = createRoom();
    const socket = new MockSocket();

    const closed = room.handleConnection(socket, metadata);
    socket.sent = [];

    expect(room.getConnectionCount()).toBe(1);

    socket.emitMessage({ type: 'broadcast', event: 'self', data: { ok: true }, echoSelf: true });

    await new Promise(resolve => setTimeout(resolve, 0));

    expect(socket.sent).toHaveLength(1);
    const payload = JSON.parse(socket.sent[0]);
    expect(payload).toMatchObject({ type: 'event', event: 'self', data: { ok: true } });

    socket.close(1000, 'done');
    await closed;
    expect(room.getConnectionCount()).toBe(0);
  });
});
