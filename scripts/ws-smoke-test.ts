// Lightweight WebSocket probe for local Cloudflare Workers. Provide endpoint and board id.
import WebSocket from 'ws';

const [, , rawUrl, rawBoardId] = process.argv;
const endpoint = rawUrl ?? 'ws://127.0.0.1:8787/boards';
const boardId = rawBoardId ?? 'demo-board';

const url = `${endpoint}?boardId=${encodeURIComponent(boardId)}`;
const timeout = setTimeout(() => {
  console.error(`[ws-smoke] Connection timeout after 10s (${url})`);
  process.exitCode = 1;
  socket?.terminate();
}, 10_000);

let socket: WebSocket | undefined;
let closedGracefully = false;
let sawAck = false;

console.info(`[ws-smoke] Connecting to ${url}`);

try {
  socket = new WebSocket(url, {
    headers: {
      'User-Agent': 'board-app-ws-smoke-test'
    }
  });
} catch (error) {
  console.error('[ws-smoke] Failed to instantiate WebSocket:', error);
  process.exit(1);
}

const finish = (reason: string) => {
  if (closedGracefully) {
    return;
  }
  closedGracefully = true;
  console.info(`[ws-smoke] Closing connection (${reason})`);
  socket?.close(1000, 'smoke complete');
};

socket.on('open', () => {
  console.info('[ws-smoke] Connected, sending probe message');
  socket?.send(
    JSON.stringify({
      type: 'ping',
      boardId,
      timestamp: Date.now(),
      closeAfterPong: true
    })
  );
});

socket.on('message', raw => {
  const payload = raw.toString();
  console.info('[ws-smoke] Received payload:', payload);

  try {
    const parsed = JSON.parse(payload);
    if (parsed.type === 'ack') {
      sawAck = true;
      return;
    }
    if (parsed.type === 'pong') {
      if (!sawAck) {
        console.warn('[ws-smoke] Received pong before ack; continuing');
      }
      finish('pong');
      return;
    }
    if (parsed.type === 'event') {
      finish('event');
      return;
    }
  } catch (error) {
    console.warn('[ws-smoke] Non-JSON payload, continuing');
  }

  finish('message');
});

socket.on('close', (code, reason) => {
  clearTimeout(timeout);
  const text = reason?.toString() ?? '';
  console.info(`[ws-smoke] Connection closed with code ${code}${text ? ` (${text})` : ''}`);
});

socket.on('error', error => {
  clearTimeout(timeout);
  console.error('[ws-smoke] Socket error:', error);
  process.exitCode = 1;
});
