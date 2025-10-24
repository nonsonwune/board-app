export interface BoardRoomOptions {
  boardId: string;
  now?: () => number;
  keepAliveMs?: number;
}

export interface BoardRoomMetadata {
  boardId: string;
  traceId: string;
}

type Listener<T> = (event: T) => void;

type MessageEventLike = { data: string | ArrayBuffer | ArrayBufferView };
type CloseEventLike = { code?: number; reason?: string };
type ErrorEventLike = { error: unknown };
type ListenerOptions = { once?: boolean };

export interface BoardWebSocket {
  readonly readyState: number;
  accept(): void;
  send(data: string): void;
  close(code?: number, reason?: string): void;
  addEventListener(type: 'message', listener: Listener<MessageEventLike>, options?: ListenerOptions): void;
  addEventListener(type: 'close', listener: Listener<CloseEventLike>, options?: ListenerOptions): void;
  addEventListener(type: 'error', listener: Listener<ErrorEventLike>, options?: ListenerOptions): void;
}

type ConnectionEntry = {
  socket: BoardWebSocket;
  metadata: BoardRoomMetadata;
  keepAliveHandle: ReturnType<typeof setInterval> | null;
};

export class BoardRoom {
  private readonly boardId: string;

  private readonly now: () => number;

  private readonly keepAliveMs: number;

  private readonly connections = new Map<string, ConnectionEntry>();

  constructor(options: BoardRoomOptions) {
    this.boardId = options.boardId;
    this.now = options.now ?? (() => Date.now());
    this.keepAliveMs = options.keepAliveMs ?? 30_000;
  }

  handleConnection(socket: BoardWebSocket, metadata: BoardRoomMetadata): Promise<void> {
    const connectionId = crypto.randomUUID();

    socket.accept();

    const keepAliveHandle = this.startKeepAlive(connectionId, socket, metadata);
    this.connections.set(connectionId, { socket, metadata, keepAliveHandle });

    socket.addEventListener('message', event => {
      this.onMessage(connectionId, event);
    });

    socket.addEventListener('error', () => {
      this.disconnect(connectionId, 1011, 'socket error');
    });

    socket.addEventListener('close', () => {
      this.disconnect(connectionId, undefined, undefined, { fromRemote: true });
    });

    this.send(socket, {
      type: 'ack',
      boardId: metadata.boardId,
      connectionId,
      trace_id: metadata.traceId,
      timestamp: this.now()
    });

    return new Promise<void>(resolve => {
      const finalise = () => resolve();
      socket.addEventListener('close', finalise);
    });
  }

  getConnectionCount() {
    return this.connections.size;
  }

  broadcast(message: Record<string, unknown>, excludeConnectionId?: string) {
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
          this.disconnect(connectionId, 1011, 'broadcast failure');
        }
      }, 0);
    }
  }

  private onMessage(connectionId: string, event: MessageEventLike) {
    const entry = this.connections.get(connectionId);
    if (!entry) {
      return;
    }

    const { socket, metadata } = entry;
    const text = this.decodeMessage(event.data);

    if (!text) {
      this.sendError(socket, metadata.boardId, 'unsupported payload');
      return;
    }

    let rawPayload: unknown;
    try {
      rawPayload = JSON.parse(text);
    } catch {
      this.sendError(socket, metadata.boardId, 'invalid JSON payload');
      return;
    }

    const payload =
      typeof rawPayload === 'object' && rawPayload !== null
        ? (rawPayload as Record<string, unknown>)
        : {};

    switch (payload['type']) {
      case 'ping': {
        this.send(socket, {
          type: 'pong',
          boardId: metadata.boardId,
          timestamp: this.now()
        });
        if (payload['closeAfterPong']) {
          this.disconnect(connectionId, 1000, 'pong complete');
        }
        return;
      }
      case 'broadcast': {
        this.broadcast(
          {
            type: 'event',
            trace_id: metadata.traceId,
            origin: connectionId,
            event: typeof payload['event'] === 'string' ? payload['event'] : 'message',
            data: payload['data'] ?? null,
            timestamp: this.now()
          },
          payload['echoSelf'] ? undefined : connectionId
        );
        return;
      }
      default: {
        this.sendError(socket, metadata.boardId, 'unknown message type');
      }
    }
  }

  private disconnect(
    connectionId: string,
    code?: number,
    reason?: string,
    options: { fromRemote?: boolean } = {}
  ) {
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

  private startKeepAlive(connectionId: string, socket: BoardWebSocket, metadata: BoardRoomMetadata) {
    if (this.keepAliveMs <= 0) {
      return null;
    }

    const handle = setInterval(() => {
      try {
        this.send(socket, {
          type: 'keepalive',
          boardId: metadata.boardId,
          timestamp: this.now()
        });
      } catch (error) {
        console.warn(`[board-room:${this.boardId}] keepalive failed`, error);
        this.disconnect(connectionId, 1011, 'keepalive failure');
      }
    }, this.keepAliveMs);

    return handle;
  }

  private send(socket: BoardWebSocket, payload: Record<string, unknown>) {
    socket.send(JSON.stringify(payload));
  }

  private sendError(socket: BoardWebSocket, boardId: string, message: string) {
    this.send(socket, {
      type: 'error',
      boardId,
      message,
      timestamp: this.now()
    });
  }

  private decodeMessage(data: string | ArrayBuffer | ArrayBufferView) {
    if (typeof data === 'string') {
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
}
