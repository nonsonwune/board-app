# Frontend & UI Files Overview

This document lists the UI-facing files for the Board Rooms application so a reviewer can focus solely on the visual/UX layer. Backend workers and shared utilities are listed elsewhere.

## Layout & Theme

- `frontend/app/globals.css`: design tokens, color palette, typography and global styles.
- `frontend/app/layout.tsx`: Next.js root layout that applies fonts, providers, and page shell.
- `frontend/components/page-shell.tsx`: shared `PageShell` and `PageHeader` primitives used by pages for consistent spacing and hero sections.
- `frontend/components/app-header.tsx`: top navigation header (brand badge, nav links, identity controls).

## Core Feature Screens

- `frontend/components/board-viewer.tsx`: main board experience (live feed, posting form, quiet-mode prompts, developer tools). Currently monolithic / in-progress for refactor.
- `frontend/app/page.tsx`: entry page routing to the board preview/landing experience (if applicable).
- `frontend/app/boards/[boardId]/page.tsx` (if present): board route that instantiates `BoardViewer`.

## Identity & Profile

- `frontend/components/identity-panel.tsx`: profile/identity management UI used on the profile page.
- `frontend/app/profile/page.tsx`: profile route shell (reuses identity components).

## Admin UI

- `frontend/components/phase-admin-panel.tsx`: Phase 1 configuration form (worker URL + token + board settings).
- `frontend/app/admin/phase/page.tsx`: admin page wrapping `phase-admin-panel` in the shared page shell.

## UI Utilities

- `frontend/components/toast-provider.tsx`: toast notifications used throughout the UI.
- `frontend/components/providers.tsx`: wraps app in context providers (identity, toasts, etc.).
- `frontend/components/quick-actions.tsx`, `frontend/components/board-preview.tsx`: landing page components for board selection/CTA cards.
- `frontend/components/board-card.tsx` (if present): card layout for board preview grid.
- `frontend/hooks/use-board-events.ts`: client hook managing websocket connection status (drives UI live indicators).

## Shared Context & State

- `frontend/context/identity-context.tsx`: client identity store (session cookie, alias cache). UI components depend on it for user status.

## Testing & QA Helpers

- `frontend/tests/**`: any Playwright or component tests (if present) covering UI flows.

---

**Notes for Reviewers:**

- The UI is mid-transition from an internal harness to a polished launch surface. `board-viewer.tsx` still contains developer tools and QA forms, which are slated for extraction.
- Styling is Tailwind-based, leaning on the new design tokens defined in `globals.css`. Some legacy styles remain in components and will be iteratively replaced with the shared primitives.
- Ensure to view both the board page and admin/profile experiences—the new page shell should present a consistent look across all routes.
