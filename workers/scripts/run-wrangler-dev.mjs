#!/usr/bin/env node
import { spawn } from 'node:child_process';
import net from 'node:net';
import path from 'node:path';
import process from 'node:process';

const cwd = path.resolve(process.cwd());
const DEFAULT_PORT = Number.parseInt(process.env.BOARD_WORKER_PORT ?? '8788', 10);
const MAX_PORT = Number.parseInt(process.env.BOARD_WORKER_PORT_MAX ?? '8808', 10);

function isPortFree(port) {
  return new Promise((resolve) => {
    const server = net.createServer();

    server.once('error', () => {
      server.close();
      resolve(false);
    });

    server.once('listening', () => {
      server.close(() => resolve(true));
    });

    server.listen(port, '127.0.0.1');
  });
}

async function findOpenPort(start, max) {
  for (let port = start; port <= max; port += 1) {
    const free = await isPortFree(port);
    if (free) {
      return { port, reused: port !== start };
    }
  }

  throw new Error(`No open port found between ${start} and ${max}.`);
}

const { port, reused } = await findOpenPort(DEFAULT_PORT, MAX_PORT);

if (reused) {
  console.warn(
    `Port ${DEFAULT_PORT} is busy. Falling back to port ${port}. ` +
      'Override with BOARD_WORKER_PORT to pin a custom port.'
  );
}

const wranglerArgs = ['dev', '--config', 'wrangler.toml', '--port', String(port)];
const runner = spawn('wrangler', wranglerArgs, {
  stdio: 'inherit',
  cwd,
  env: {
    ...process.env,
    BOARD_WORKER_PORT: String(port),
  },
});

runner.on('exit', (code, signal) => {
  if (signal) {
    console.log(`wrangler dev received signal ${signal}`);
    process.exit(0);
  }

  process.exit(code ?? 0);
});
