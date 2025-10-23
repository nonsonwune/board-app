# Cloudflare Binding Map

Keep this table in sync with `wrangler.toml` files and deployment workflows.

## D1 Databases
- `BOARD_DB` (preview, production) — canonical relational store for users, boards, posts, moderation, notifications.

## Durable Objects
- `BoardRoomDO` — per-board realtime fan-out and live-mode state.
- `RateLimitDO` — token buckets for posts, replies, flags, reactions.
- `ModerationDO` — moderation queue workflow, audit trail, delete guardrail.

## KV Namespaces
- `BOARD_CACHE` — leaderboard shards, topic tag sets, version markers.
- `FEATURE_FLAGS` — rollout toggles consumed by frontend and Workers.

## R2 Buckets
- `board-media` — original uploads and generated thumbnails.
- `board-logs` — Logpush target for long-term retention (optional outside production).

## Queues
- `board-topic-refresh` — TF-IDF topic refresh cron.
- `board-leaderboard-refresh` — 5-minute influence recompute jobs.
- `board-notify-digest` — 6-hour notification bundling worker.

## Vectorize (Optional)
- `board-semantic` — embedding index for hybrid search and abuse similarity checks.

## Environment Hints
- Preview and production share binding names but use separate Cloudflare environments; `wrangler.toml` should declare `environments.preview` with `*_PREVIEW` account IDs if needed.
- Admin-only secrets (`ADMIN_PASSKEY_APP_ID`, `ACCESS_JWT_AUDIENCE`, `ACCESS_JWT_ISSUER`, `ACCESS_JWT_JWKS_URL`) live in `.dev.vars` locally and are provisioned via Wrangler secrets in preview/production.
- When adding a new binding, update this file, `wrangler.toml`, and note the change in the PR checklist.
- Scheduled Cron (`*/15 * * * *`) runs the dead-zone detector via the main worker to keep freshness metrics current.
