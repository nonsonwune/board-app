#!/usr/bin/env node
import { execSync } from 'node:child_process';

const PORT = Number.parseInt(process.env.BOARD_WORKER_PORT ?? '8788', 10);

try {
  const raw = execSync(`lsof -nP -iTCP:${PORT} -sTCP:LISTEN -t`, {
    stdio: ['ignore', 'pipe', 'ignore'],
  })
    .toString()
    .trim();

  if (!raw) {
    console.log(`No process is listening on port ${PORT}.`);
    process.exit(0);
  }

  const pids = Array.from(new Set(raw.split(/\s+/).filter(Boolean)));

  for (const pid of pids) {
    try {
      execSync(`kill ${pid}`, { stdio: 'ignore' });
      console.log(`Terminated process ${pid} on port ${PORT}.`);
    } catch (killError) {
      console.error(`Failed to terminate process ${pid}:`, killError.message);
    }
  }

  console.log(`Port ${PORT} is now free.`);
} catch (error) {
  if (error.status === 1) {
    console.log(`No process is listening on port ${PORT}.`);
    process.exit(0);
  }

  console.error(`Unable to inspect port ${PORT}. Ensure lsof is installed.`);
  console.error(error.message ?? error);
  process.exit(1);
}
