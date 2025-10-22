# Workers Dev Guide

## Local Development
- Use `pnpm --filter @board-app/workers dev` to boot the worker. The wrapper selects an open port, preferring `8788`. Override with `BOARD_WORKER_PORT` or expand the window via `BOARD_WORKER_PORT_MAX`.
- Wrangler 4 defaults to anonymous telemetry; opt out locally with `WRANGLER_TELEMETRY=false` if required.
- The fallback port is surfaced through the console so QA scripts can point to the right URL.
- Before exercising the realtime endpoints locally, run `wrangler d1 migrations apply board` to create the `board_events` table. Remove the local `.wrangler/state` directory if you need a clean slate.

## API Sketch
- `GET /_health` — liveness probe.
- `GET /boards?boardId=<id>` (WebSocket upgrade) — join the realtime channel for a board.
- `GET /boards/:boardId/events?limit=20` — fetch the latest events (stored in D1) along with active connection counts.
- `POST /boards/:boardId/events` — inject a board event (`{ event: string; data?: unknown; echoSelf?: boolean }`) which is broadcast to connected clients, persisted to D1, and replayed to late joiners.
- `POST /boards/:boardId/posts` — create a post (body/author) that is stored in D1 and broadcast as a `post.created` event.
- `GET /boards/:boardId/feed?limit=20` — retrieve board metadata and recent posts, ordered by recency.

Realtime notes:
- The frontend merges incoming `post.created` websocket events into its feed to keep the list fresh between REST fetches.
- Events are persisted in `board_events` for late-join replay; D1 tables (`boards`, `posts`) are lazily created if migrations haven’t run locally.
- Remaining gap: we don’t yet stream updates for reaction counts or edits—future events will expand the event schema.

## Troubleshooting
- `pnpm --filter @board-app/workers kill-port` frees any lingering worker instance on the selected port. The script honours `BOARD_WORKER_PORT` to match your dev configuration.
- If you intentionally want the raw Wrangler behaviour, run `pnpm --filter @board-app/workers dev:raw`.
- Persistent conflicts may indicate another service using the port; inspect with `lsof -nP -iTCP:8788`.

## Follow-up Tasks
- Consider adding a CI reminder when Wrangler 3 support is dropped once v4 migration stabilises.
