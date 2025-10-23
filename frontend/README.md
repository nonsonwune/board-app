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

## Quiet Mode Sponsored Cards
- Define `NEXT_PUBLIC_SPONSORED_QUIET_CARDS` as a JSON array to surface optional sponsored prompts when a board is quiet.
  - Example:
    ```json
    [
      {
        "id": "fall-welcome",
        "title": "Campus Coffee Happy Hour",
        "body": "Show your student ID after 6pm and get a free refill tonight only.",
        "cta": "Visit Daily Grind",
        "href": "https://dailygrind.example",
        "boards": ["campus-north"],
        "impressionCap": 3
      }
    ]
    ```
- Cards may be capped per board/user and dismissed locally via the UI; dismissed state and impression counts persist in `localStorage`.

## Phase 1 Launch Controls
- Visit `/admin/phase` to view and adjust fixed-radius/text-only settings per board.
- Provide the worker base URL and the `PHASE_ADMIN_TOKEN` (set in the worker) to fetch or update settings.
- Phase 1 mode enforces a fixed radius and can disable images/text-only posts to match the MVP launch spec.

## Image Upload Guardrails
- Image uploads are disabled by default; the worker must expose `ENABLE_IMAGE_UPLOADS=true` before clients may attach images.
- Even when enabled, the worker enforces file count (≤4), size (≤3 MB each), and MIME type (`image/jpeg`, `image/png`, `image/webp`) before accepting metadata.
