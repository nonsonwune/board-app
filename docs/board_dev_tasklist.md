# Board Dev Tasklist

Tracking TODOs stemming from the latest product decisions. Update as work progresses.

## Core Feed & Location
- [ ] Implement adaptive radius service (shrink/grow based on post freshness) with hysteresis.
- [ ] Add quiet-mode content prompts + optional sponsored cards when feed is sparse.
- [ ] Instrument dead-zone detector (board freshness metric feeding alerting).
- [ ] Phase 1 MVP variant: support fixed-radius, text-only feed configuration for targeted dorm launches.

## Ranking & Moderation
- [ ] Update hot_rank to incorporate velocity boost and rapid-engagement decay window.
- [ ] Build brigade detection heuristics (reaction entropy, cohort surges) and tie into moderation queue.
- [ ] Integrate proactive content filter/quarantine before user render.
- [ ] Implement tiered moderator roles (volunteer/staff/admin) with permissions & audit logs.
- [ ] Build consensus workflow UI (moderator voting dashboard + escalations).

## Identity & Access UX
- [ ] Add toast feedback on board page for Access re-link, alias accepts, etc. (done)
- [ ] Provide alias hints for new users (done)
- [ ] Expose quick access cards on landing page (done)

## Platform & Observability
- [ ] Route `access.identity_*` logs to analytics warehouse + dashboard panels.
- [ ] Configure dead-zone alert in monitoring stack.
- [ ] Log moderator actions + identity lookups for audits.

## Battery & Performance
- [ ] Switch location polling to significant-change geofences with foreground-only bursts.
- [ ] Validate battery usage in field tests (target <3%/hr while active).

## Launch Strategy
- [ ] Draft soft-launch playbook for first dorm cohort (success metrics, feedback loop).
- [ ] Prepare dorm-level feature flags/toggles for controlled rollout.
- [ ] Phase 1 instrumentation: activation, engagement, D2/D7 retention, qualitative feedback capture.
