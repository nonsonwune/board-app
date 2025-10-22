# Board Frontend

## Development
- `pnpm --filter @board-app/frontend dev` launches the Next.js dev server (defaults to `http://localhost:3000`).
- The realtime worker should run in parallel on `http://localhost:8788` (`pnpm --filter @board-app/workers dev`).
- Override the worker origin with `NEXT_PUBLIC_WORKER_BASE_URL` when connecting to preview/prod environments.

## Realtime Boards
- Visit `/boards/demo-board` to stream events. The page hydrates from `GET {worker}/boards/:id/events` and maintains a websocket at `ws://{worker}/boards?boardId=:id`.
- Use the inject form on `/boards/:id` or send `POST {worker}/boards/:id/events` with a JSON body (`{ "event": "note", "data": {...} }`) to simulate websocket activity.
- Create sample posts from the UI or via `POST {worker}/boards/:id/posts` (`{ "body": "...", "author": "you" }`); the feed is served by `GET {worker}/boards/:id/feed`.

## Lint & Test
- `pnpm --filter @board-app/frontend lint`
- `pnpm --filter @board-app/frontend test` (placeholder until component tests land)

Refer to `workers/README.md` for endpoint and migration details.
