# Repository Guidelines

## Project Structure & Module Organization
Use `frontend/` for the Next.js Pages app (App Router lives under `app/`). Edge Workers live in `workers/` with Durable Objects under `workers/do/`. Shared TypeScript utilities and schema belong in `packages/shared/` (create the package if absent). D1 migrations reside in `infra/d1/migrations/`, and specs stay in `docs/` (see `docs/board_prd.md`). Co-locate tests beside code inside `__tests__/` folders.

## Build, Test, and Development Commands
- `pnpm install` — install dependencies; run `corepack enable` first on a fresh machine.
- `pnpm dev` — Pages dev server with edge runtime and live reload.
- `pnpm worker:dev` — `wrangler dev` for Workers, Durable Objects, and bindings.
- `pnpm lint` — ESLint + Prettier; must pass before commits.
- `pnpm test` — Vitest suites; add `--coverage` for reports.
- `wrangler d1 migrations apply board` — apply schema updates to the local D1 instance.

## Coding Style & Naming Conventions
TypeScript with `strict` mode and React Server Components by default. Format via Prettier (2-space indent, single quotes, trailing commas) and keep imports sorted (`pnpm lint --fix`). Name components and Durable Object classes `PascalCase`, hooks `useCamelCase`, files kebab-case except Next.js route segments. Declare bindings once in `workers/env.d.ts` and import them, never read directly from `process.env`.

## Testing Guidelines
Vitest + Miniflare cover Workers and shared logic; place `*.spec.ts` beside implementation. Playwright lives in `tests/e2e/` for login, posting, moderation, and live-board flows; name files `*.e2e.ts`. Target ≥80% statement coverage and include coverage output in PRs. Smoke-test realtime features with `pnpm smoke:ws ws://127.0.0.1:8787/boards demo-board` before requesting review.

## Commit & Pull Request Guidelines
Use Conventional Commits (`feat:`, `fix:`, `chore:`) and reference issue IDs when available. Squash local fixups; keep migration commits standalone. PRs must include a crisp summary, tests run, screenshots or curl transcripts for UI/API updates, and links to relevant spec sections. Tag the domain owner (identity, boards, moderation, realtime) and document new bindings or secrets in the PR body.

## Security & Configuration Tips
Secrets live in `.dev.vars` and are mapped in `wrangler.toml`; never commit credentials. Use separate Cloudflare environments (`preview`, `production`) and note binding names in `infra/bindings.md`. Emit JSON structured logs (with `trace_id`) for new Workers instrumentation to align with the observability plan in `docs/board_prd.md`.
