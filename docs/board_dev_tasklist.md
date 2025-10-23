# Board Dev Tasklist

Tracking TODOs stemming from the latest product decisions. Update as work progresses.

## Core Feed & Location
- [ ] Implement adaptive radius service (shrink/grow based on post freshness) with hysteresis.
- [x] Add quiet-mode content prompts when feed is sparse (`frontend/components/board-viewer.tsx`).
- [x] Layer optional sponsored quiet-mode cards / inventory controls (`frontend/components/board-viewer.tsx`).
- [x] Instrument dead-zone detector (board freshness metric feeding alerting) (`workers/src/index.ts`, `workers/src/__tests__/storage.spec.ts`).
- [ ] Phase 1 MVP variant: support fixed-radius, text-only feed configuration for targeted dorm launches.

## Ranking & Moderation
- [x] Update hot_rank to incorporate velocity boost and rapid-engagement decay window (`workers/src/index.ts`, `workers/src/__tests__/storage.spec.ts`).
- [ ] Build brigade detection heuristics (reaction entropy, cohort surges) and tie into moderation queue.
- [ ] Integrate proactive content filter/quarantine before user render.
- [ ] Implement tiered moderator roles (volunteer/staff/admin) with permissions & audit logs.
- [ ] Build consensus workflow UI (moderator voting dashboard + escalations).

## Identity & Access UX
- [x] Add toast feedback on board page for Access re-link, alias accepts, etc. (`frontend/components/board-viewer.tsx`, `frontend/components/identity-panel.tsx`).
- [x] Provide alias hints for new users (`frontend/components/identity-panel.tsx`).
- [x] Expose quick access cards on landing page (`frontend/components/board-preview.tsx`, `frontend/components/quick-actions.tsx`).

## Platform & Observability
- [x] Route `access.identity_*` logs to analytics warehouse + dashboard panels (`workers/src/index.ts`, `workers/src/__tests__/storage.spec.ts`).
- [x] Configure dead-zone alert in monitoring stack (`workers/src/index.ts`, `workers/src/__tests__/storage.spec.ts`, `workers/wrangler.toml`).
- [ ] Log moderator actions + identity lookups for audits.

## Battery & Performance
- [ ] Switch location polling to significant-change geofences with foreground-only bursts.
- [ ] Validate battery usage in field tests (target <3%/hr while active).

## Launch Strategy
- [ ] Draft soft-launch playbook for first dorm cohort (success metrics, feedback loop).
- [ ] Prepare dorm-level feature flags/toggles for controlled rollout.
- [ ] Phase 1 instrumentation: activation, engagement, D2/D7 retention, qualitative feedback capture.
