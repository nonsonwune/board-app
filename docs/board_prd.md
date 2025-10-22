# Board v2.2 — Cloudflare‑Native Product & Technical Specification (Minimal‑Code Edition)

**Date:** 21 Oct 2025
**Status:** Build‑ready, comprehensive, minimal‑code

> A single source of truth for product, engineering, and operations — optimized end‑to‑end for Cloudflare (Pages, Workers, Durable Objects, D1, KV, R2, Queues, Vectorize, Images, Turnstile, Access). Minimal code, maximum clarity.

---

## 1) Vision & Principles

**Vision:** A fast, hyper‑local, pseudonymous noticeboard for campuses and neighborhoods. Win on **place‑awareness**, **immediacy**, and **safety**.

**Principles**

* **Local first:** Feeds bound to physical context (H3 cells + 1.5 km access radius).
* **Lightweight voice:** Micro‑posts (≤300 chars), quick replies, simple reactions.
* **Reputation without oligarchy:** Time‑decayed influence; small, capped author boost.
* **Safety by default:** Anonymous reactions, flag‑driven auto‑hide, transparent admin tools.
* **Mobile‑first performance:** p90 cold load <1.5s on 4G; realtime p95 <1s.
* **Edge‑native:** Compute and cache at the edge; data minimized; privacy by design.

---

## 2) Scope & Non‑Goals

**In scope (MVP):** Hyperlocal feeds, Spaces, posts with images, replies, reactions, following, per‑Board topics, search (recent), moderation & admin console, notifications, live‑event mode.

**Out of scope (MVP):** DMs, polls, paid promos, user‑generated Space creation (beyond admin), long‑form content, native app binaries (wrappers optional).

---

## 3) Success Metrics

* **Active Engaged Users (North Star):** Users opening ≥3 days/week **and** performing ≥5 actions/week.
* **Location Adoption:** #Boards with ≥20 posts in 14 days.
* **Engagement Quality:** Average Wilson score per post (confidence‑adjusted like/dislike).
* **Safety Health:** % flags resolved <24h, % auto‑hides reviewed <48h.
* **Performance:** p90 initial feed <1.5s; realtime p95 <1s.

---

## 4) Personas & Key Use Cases

* **Campus Student (primary):** What’s happening now? Events, shout‑outs, live game threads, lost & found.
* **Society/Club Rep:** Announce meets, gauge interest, quick feedback.
* **Moderator/Admin:** Keep spaces safe, resolve flags, detect brigades.

---

## 5) Feature Specification

### 5.1 Identity & Profiles

* **Global Pseudonym:** Unique, case‑insensitive (3–20 chars; emoji allowed). Used for Following & global leaderboards.
* **Per‑Board Alias (optional):** Display‑only alias within a Board. Default display = alias if set; otherwise global pseudonym. Following always attaches to the global identity.
* **Profile:** Posts across Boards (with Board flair), per‑Board Influence indicator, 30‑day global badge, follower count (no identities exposed).

### 5.2 Location & Boards

* **Detection:** On startup, map GPS to H3 res9 cell; join Board covering user’s nearby cluster.
* **Access Radius:** ~1.5 km (walkable). Feed updates when crossing boundaries.
* **Naming:** Official place name stored with stable `place_id` (provider‑agnostic); UI truncates display to 40 chars.
* **Creation:** First post in an uncovered cluster creates a Board; the first poster is marked **Creator** (immutable, timestamped).

### 5.3 Spaces

* **Seeded (MVP):** Home (default), Student Life, Events, Sports.
* **Assignment:** Optional at post time; replies inherit parent’s Space.

### 5.4 Posts & Replies

* **Post:** Text ≤300 chars; 0–4 images (≤3 MB each; JPEG/PNG/WebP; EXIF stripped). Thumbnails generated on upload.
* **Replies:** Text‑only, ≤300 chars; nested display up to 2 levels.
* **Draft Board Lock:** Draft records originating Board; if user moves, prompt to post to original (default) or switch.

### 5.5 Engagement & Influence

* **Reactions:** One Like or Dislike per user per item; can switch/remove. Identities not exposed to authors.
* **Influence (per Board):** Exponential decay (half‑life 14 days) of post scores; normalized 0–1; used in topics weighting.
* **Leaderboard (global):** 30‑day decayed roll‑up; recomputed frequently; Top‑10 receive only a **+10% tie‑breaker** in ranking.

### 5.6 Feeds & Discovery

* **Board Feed:** Sorted by `hot_rank` (see §6); 20 items/page; infinite scroll.
* **Following Feed:** Time‑ordered posts from followed users across Boards; quality gating within recency bands.
* **Trending Topics:** 3–5 tags per Board via TF‑IDF on recent posts (adaptive 15–60 min window, min 20 posts). Tapping filters Board feed for 30 min.

### 5.7 Search

* **Board‑scoped search:** Default window last 7 days, plus posts with ≥10 reactions up to 30 days. Filters: Space; sort by relevance/time. (See §7.5 for Cloudflare search backing.)

### 5.8 Notifications

* **Real‑time:** `reply`, `mention` (respect DND window).
* **Digests:** `hot`, `follow_post_nearby` — bundled **max once per 6h**.
* **Preferences:** Per‑type toggles; user DND (default 22:00–07:00); campus quiet hours (admin‑set).

### 5.9 Safety & Moderation (User‑facing)

* **Flagging:** Anonymous with reason; UI conveys effect (internal only).
* **Auto‑Hide Threshold:** ≥5 **distinct** reporters → temporary hide + moderation queue; author incurs cooldown.
* **Block/Mute:** Block hides content and prevents replies to you; mute hides content only. Reversible.

### 5.10 Admin Console

* **Access:** `is_admin = true` only; Zero‑Trust gated.
* **Dashboard:** Users, Boards, DAU/WAU/MAU, posts, flags by reason, active live Boards.
* **Queue:** Flagged items sorted by distinct reporters + recency; reasons and timestamps visible.
* **Actions:** Hide (soft), Delete (hard; two‑person confirm; auto‑restore admin‑hidden if unreviewed at 72h), Shadowban, Ban (platform/Board scope, timed), Cooldown, Thread Freeze (15 min: 5× rate‑limit + reactions off).
* **Audit:** Immutable log of admin actions (actor, target, reason, timestamp, metadata).
* **Brigade Panel:** Entropy of reporters, device/IP overlaps, burst timing.

---

## 6) Algorithms & Scoring (no code)

**Wilson Score (95% CI):** Confidence‑adjusted proportion for (likes vs total reactions). Prevents tiny‑sample outliers from dominating.

**Time Decay:** Exponential decay with 24h half‑life on post age.

**Ranking (hot_rank):**

```
hot_rank = 0.5 × time_decay + 0.45 × wilson_score + 0.05 × author_bonus
where author_bonus = 1.1 for Top‑10, else 1.0 (cap at +10%)
```

**Topics:** TF‑IDF over recent posts per Board, weighted by author trust; merge near‑duplicates (trigram similarity); compute every 15–60 min when volume ≥20 posts.

---

## 7) System Architecture — Cloudflare‑Native (descriptive)

### 7.1 Frontend

* **Pages (Next.js)** for the PWA (App Router). Edge‑rendered via Pages Functions; static assets cached on CDN; per‑route cache rules.
* **Edge Router Worker** in front of Pages to normalize headers, set cookies, inject `Cache‑Control`, and short‑circuit API calls when eligible.
* **Design:** Bottom‑nav IA; semantic HTML; WCAG 2.1 AA.

### 7.2 Core Compute & Data

* **Workers + Durable Objects (DO):**

  * **BoardRoom DO:** One DO per Board for realtime fan‑out (WebSockets), rate‑limit arbitration, and live‑mode state.
  * **RateLimit DO:** Token buckets per user/device for posts, replies, reactions, flags; escalates to Turnstile on abuse.
  * **Moderation DO:** Queue triage, two‑person delete guardrail, and audit append‑only writes.

* **D1 (SQLite) — canonical relational store:** Users, aliases, Boards, Spaces, posts, engagements, flags, moderation_actions, bans, topics, notifications, prefs, rate_limits, leaderboard_cache, drafts, board_live_mode_log.

  * **FTS5** tables for post search (board‑scoped). If FTS5 isn’t available in the target region, **fallback** to **Vectorize** (embeddings + cosine) with keyword pre‑filter in D1.
  * **H3** indices stored as text/ints; spatial filtering by equality/prefix lists.

* **KV** — low‑latency TTL caches: leaderboard top‑100, topic tag sets, feature flags, per‑Board hot shards.

* **R2** — media storage: originals + responsive thumbnails. **Image Resizing** or **Cloudflare Images** for on‑the‑fly variants; EXIF stripped on upload.

* **Queues + Cron Triggers** — background jobs: topics (15–60 min), leaderboard (5 min), live‑mode detector (2 min), emergency‑delete guardrail (6 h), metrics refresh (hourly), digest bundling (6 h max).

* **Vectorize (optional)** — semantic search boost and abuse/brigade similarity clustering; TF‑IDF remains primary topics engine.

### 7.3 Realtime

* **WebSockets** terminates in the BoardRoom DO; server debounces; client batches (~250 ms). **Fallback** to polling when WS backpressure detected or >1k users.
* **Pub/Sub (internal)** via DO interconnect; sharded by Board id.

### 7.4 Auth & Security

* **Auth:** Passkeys (WebAuthn) as primary; email magic link as fallback. JWTs minted/verified at edge (Workers). Session in HttpOnly, SameSite=Lax cookies.
* **Bot Defense:** **Turnstile** on signup and elevated flows (post bursts, repeated flags).
* **Admin Access:** **Cloudflare Access** (Zero Trust) gating Admin Console by identity group; second factor required for destructive actions.
* **Secrets:** Wrangler‑managed; rotated quarterly.

### 7.5 Search

* **Primary:** D1 **FTS5** tables, board‑scoped, with recency windows (7 days default; ≥10 reactions up to 30 days).
* **Fallback/Boost:** **Vectorize** embeddings + lexical pre‑filter; hybrid ranking (BM25 + cosine) when enabled.

### 7.6 Caching & CDN Strategy

* **Edge Cache:** Public GETs for board feeds (anonymized) cached ≤10s with `stale‑while‑revalidate=60`; personalized endpoints bypass.
* **KV‑assisted caching:** Cache keys include Board id + page + version; soft‑invalidate on write via version bump.
* **Images:** Served via CDN with automatic format negotiation; thumbnails lazy‑loaded.

### 7.7 Observability

* **Workers Analytics Engine** for edge metrics; **Logpush → R2** for request logs; optional sink to external SIEM.
* **Error Tracking:** Sentry/HyperDX via Workers logging; redaction of PII enforced in middleware.
* **Health:** Synthetic checks per core route; dashboards: latency p90/p95, downgrade rate, queue lag, auto‑hide triggers.

---

## 8) Data Model Overview (concise, D1)

**users** — id; display_name (global pseudonym, unique); is_admin; device_fingerprint_hash; created_at; last_seen_at.

**user_board_aliases** — user_id; board_id; alias (unique per Board); created_at.

**boards** — id; display_name; place_id; latitude/longitude; h3_anchor (res9); radius_m (1500 default); type (campus/neighborhood/other); creator_user_id; live_mode (auto/force_on/force_off); live_last_active_at; created_at.

**board_cells** — board_id; h3_index (covering cells).

**spaces** — id; board_id; space_name; is_system; created_at.

**posts** — id; author_id; board_id; space_id; content_text; image_urls[]; is_reply; parent_post_id; is_hidden; author_trust; hot_rank; fts (FTS5 shadow table); created_at.

**engagements** — id; user_id; post_id; type (1 like / −1 dislike); created_at; UNIQUE(user_id, post_id).

**post_reactions (view/materialized)** — post_id; likes; dislikes (aggregated, no voter IDs).

**followers** — follower_id; followed_id; created_at; PRIMARY KEY(follower_id, followed_id).

**flags** — id; post_id; reporter_user_id; reason; status (open/auto_hidden/reviewed/dismissed); distinct_reporters_count; created_at.

**moderation_actions** — id; admin_id; target_type (post/user/space/board); target_id; action (hide/delete/shadowban/ban/freeze/cooldown/restore); reason; meta; created_at.

**bans** — user_id; scope (platform/board); board_id (nullable); action_type (ban/shadowban); reason; expires_at; created_at; PK on (user_id, scope, coalesce(board_id, 'ALL')).

**topics** — id; board_id; tag; score; window_start; window_end; ttl_expires_at; created_at.

**notifications** — id; user_id; type (reply/mention/hot/follow_post_nearby); payload; read_at; created_at.

**notification_prefs** — user_id; replies; mentions; hot_digest; follows_digest; dnd_start; dnd_end.

**rate_limits** — user_id; bucket (posts/replies/reactions); count; window_start.

**leaderboard_cache** — user_id; influence_30d; rank; updated_at.

**drafts** — id; user_id; board_id; content_text; created_at; expires_at (24h).

**board_live_mode_log** — id; board_id; state (enabled/disabled); trigger (auto_threshold/admin_force_on/admin_force_off/idle_timeout); active_users; posts_per_min; changed_at.

---

## 9) Privacy, Security & Access Controls (Cloudflare)

* **Authentication:** WebAuthn passkeys + magic links; JWTs signed at edge; short‑lived, rotating refresh.
* **Authorization:** Enforced in Workers/DOs; D1 lacks native RLS — guard every read/write path. Admin endpoints require Access + `is_admin=true`.
* **Reaction Privacy:** Direct selection of voter rows is denied at API; only `post_reactions` aggregates exposed to non‑admins.
* **Shadowban:** Non‑admins cannot read shadowbanned authors’ content; authors and admins can.
* **Blocks:** Readers do not see posts by users they block; blocks are silent; enforced at query composition.
* **Bans:** Writes (post/reply/react) denied when an active ban matches scope; expiry restores rights.
* **Images:** EXIF stripped; malware scanning on upload; private R2 bucket with signed URLs; public thumbnails via CDN.
* **Location:** Persist Board anchors; **do not** persist raw user GPS beyond session.
* **Data Hygiene:** Right‑to‑deletion supported; audit logs immutable (security events only); retention policy in §17.

---

## 10) Rate Limits & Live Events (edge‑enforced)

**Baseline:**

* New accounts (<7 days): 5 posts/day; 30 reactions/day.
* Global limits: 1 post / 30 s; 1 reply / 5 s; 1 reaction / 2 s.

**Live‑Event Mode (auto):**

* **Trigger:** ≥50 active users **and** ≥3 posts/min for 5 consecutive minutes.
* **Effect:** Relax replies to 1 / 2 s; increase reaction throughput; optional feed refresh hints.
* **Revert:** After 30 minutes of idle below threshold (or if `force_off`).
* **Override:** Admin per Board: `auto`, `force_on`, `force_off`.

**Implementation:** Token buckets in RateLimit DO; WS controls in BoardRoom DO; Turnstile challenges when abuse detected.

---

## 11) Performance & UX Targets

* p90 initial load <1.5s on 4G; interaction <100 ms; realtime p95 <1s.
* Page sizes minimized; images lazy‑loaded; thumbnails + CDN; aggressive HTTP caching with SWR.
* Accessibility: WCAG 2.1 AA; semantic roles; 44×44 px tap targets.

---

## 12) API Surface (minimal contracts)

**Public (authenticated):** Boards (current/nearby/details), Posts (create/list/react/reply/flag), Profiles (get/list/follow), Topics (list), Search (board‑scoped), Notifications (list/read/update prefs).

**Admin:** Metrics; flagged queue; moderation actions (hide/delete/shadowban/ban/cooldown/freeze); live‑mode override; audit log.

**Transport:** JSON over HTTPS; WebSockets for realtime; back‑pressure aware; pagination cursor‑based.

---

## 13) Realtime & Caching Behavior

* **Per‑Board channels:** Inserts/updates for posts, replies, reaction deltas. Server debounces (≤10 msgs/s/channel); client batches (~250 ms).
* **Fallback:** Downgrade to polling when WS backpressure detected or >1k users in a Board.
* **Caches:** Leaderboard (Top‑100 cached; display Top‑10), Topics (TTL ~48h), board feed shards (≤10s TTL) with versioned keys.

---

## 14) Observability & Analytics

* **Event taxonomy:** `user_signup`, `user_login`, `board_enter`, `board_create`, `post_create`, `reply_create`, `reaction_add`, `reaction_remove`, `flag_submit`, `user_follow`, `user_block`, `space_switch`, `topic_filter`, `notification_open`, `feed_scroll_depth`, `live_mode_activated`.
* **Dashboards:** DAU/WAU/MAU; posts/day; reactions/day; average engagement/post; flags/day; load time; realtime latency; downgrade rate; queue lag.
* **Alerts:** Flag rate spike (>20% HoH); auto‑hide rate (>5% posts/hour); live‑mode false positives (>3/day); WS downgrade (>30% users); emergency‑delete second‑review backlog (>48h).

---

## 15) Rollout Plan & Acceptance Criteria

**Phase 0 (2 weeks):** Staging on Pages + D1 shadow; moderator drills; load test 1k concurrent in one Board; verify access controls.

**Phase 1 (4 weeks, single campus):** Invite 100 beta users; target ≥40% active engaged by week 4; <5% flag rate; ≥20 posts/day sustained.

**Phase 2 (8 weeks, 3–5 campuses):** Refine onboarding; add campus quiet hours; validate Following usage and Topics engagement.

**Open Beta:** Remove invite gate; waitlist for high‑demand Boards; public Top‑10 weekly spotlights.

**Acceptance Gates:** p90 feed <1.5s; realtime p95 <1s; auto‑hide at 5 distinct flags; leaderboard ≤5 min stale; search windows honored; live‑mode auto/override works; privacy controls enforced.

---

## 16) Risks & Mitigations (Cloudflare‑specific)

* **D1 FTS availability variance:** Prefer FTS5; if unavailable, enable Vectorize hybrid search; keep board‑scoped pre‑filters in D1.
* **Durable Object hot‑spotting:** Shard very active Boards by sub‑room (post id prefix) or time slice; autoshed heavy analytics off DOs.
* **KV eventual consistency:** Use KV only for non‑critical caches; invalidate via versioning; never as source of truth.
* **R2 egress costs:** Serve thumbnails via CDN; presign originals sparingly; background resize pipeline to reduce bytes.
* **Turnstile friction:** Use adaptive challenges; exempt high‑trust users; only escalate on abuse signals.
* **WebSocket limits:** Backpressure detection + automatic polling fallback; keep messages compact; compress when needed.

---

## 17) Data Retention & Compliance

* **Content:** Posts/replies retained unless deleted by author or moderation; flags/mod actions/audit logs retained for security.
* **Identifiers:** Pseudonyms and aliases stored; device fingerprints are salted/hashes (abuse heuristics only).
* **Location:** Board anchors stored; raw GPS not persisted.
* **User rights:** Account deletion removes content attribution where possible; retains security/audit where legally required.
* **Regulatory:** Align with NDPA/GDPR principles (minimization, purpose limitation, access & deletion rights). Data localization features available via Cloudflare’s regional controls if required.

---

## 18) Accessibility Checklist (AA)

* Color contrast meets AA; dynamic type support.
* Labels and roles on interactive elements; focus visible; screen‑reader hints.
* Gestures not required for core actions; alternatives provided.

---

## 19) Glossary

* **H3:** Hexagonal hierarchical geospatial index (res9 ~0.17 km² cells).
* **Wilson Score:** Lower‑bound estimator for proportion with binomial confidence.
* **Shadowban:** Author & admins see content; others do not.
* **Thread Freeze:** Temporary cool‑down (rate limits ×5; reactions disabled) ~15 minutes.
* **Influence:** Decayed sum of post scores per Board, normalized 0–1.
* **D1:** Cloudflare SQLite‑compatible database.
* **KV:** Edge key‑value store with eventual consistency.
* **R2:** Object storage.
* **Durable Object (DO):** Stateful Worker instance with single‑threaded consistency per id.
* **Vectorize:** Managed vector database for similarity search.
* **Turnstile:** Bot‑mitigation challenge.
* **Access:** Zero‑Trust identity‑aware gate for admin tools.

---

**This document stands alone.** It specifies behavior, data, safety, performance, and operations with minimal code — mapped to Cloudflare primitives for immediate execution.

---

## 20) Migration Checklist — Pure Prose (Cloudflare, No Code)

**Goal:** Move from prior mixed schemas/services to Cloudflare‑native v2.2 with zero data loss, intact access controls, and reversible changes.

### Phase A — Preflight & Risk Containment

* Name DRIs for Edge, Data, Frontend, QA, Safety.
* Take restorable backups of legacy databases and storage; document restore runbooks and timings.
* Announce change window; freeze non‑essential schema changes.
* Spin up a read‑only **shadow** stack (Pages preview + D1 dev + R2 dev) to dry‑run all steps on real snapshots.

### Phase B — Platform Provisioning

* Create **D1** (dev/stage/prod); enable FTS5 where supported.
* Create **R2** buckets: `media-originals` (private), `media-thumbs` (public via CDN).
* Create **KV** namespaces: `leaderboard`, `topics`, `feature_flags`, `feed_shards`.
* Bind **Durable Objects:** `BoardRoom`, `RateLimit`, `Moderation`.
* Enable **Queues** for background jobs; configure **Cron Triggers**.
* Generate **VAPID** keys for Web Push; configure **Turnstile**; gate Admin via **Access**.

### Phase C — Identity & Accounts

* Introduce/confirm **Global Pseudonym** uniqueness & normalization; map legacy usernames.
* Create **Per‑Board Alias** surface (display‑only, unique per Board) and precedence rules.
* Establish WebAuthn passkeys as default; set magic link fallback; migrate any existing auth to JWT sessions.

### Phase D — Boards & Location

* Standardize Board anchor fields (place name, place_id, H3 anchor, lat/long, radius).
* Backfill missing `place_id` values with a consistent provider; record source and timestamp.
* Compute and store `board_cells` coverage.

### Phase E — Content & Engagement

* Align **posts** schema to v2.2 (text limits, images array, reply linkage, `is_hidden`, `author_trust`, `hot_rank`, `fts`).
* Align **engagements** to one row per user/post; enforce uniqueness.
* Materialize/validate **post_reactions** aggregates; cross‑check counts vs legacy.
* Constrain reply nesting to 2 levels in queries and UI.

### Phase F — Social Graph & Profiles

* Consolidate **followers** on global identity; recompute counts.
* Populate profiles with per‑Board Influence and 30‑day badge.

### Phase G — Moderation & Safety

* Normalize **flags** statuses; populate distinct reporter counts.
* Enforce **auto‑hide** at 5 distinct reporters; queue hand‑off to Moderation DO; apply cooldowns.
* Standardize **moderation_actions** records; append‑only audit.
* Harmonize **bans** (scope/type) and tie into write denial.
* Enable **Thread Freeze** action; verify audit.

### Phase H — Topics, Leaderboard, Live Mode

* Create **topics** artifacts with TTL and adaptive windows (15–60 min; ≥20 posts threshold); backfill a recent window for launch.
* Ensure **leaderboard_cache** exists and refreshes frequently (cache top 100; display top 10).
* Add **board_live_mode_log** and standardize triggers.

### Phase I — Notifications & Preferences

* Normalize **notifications** (reply/mention/hot/follow_post_nearby) and **notification_prefs** (toggles + DND).
* Validate Web Push delivery paths; enable digest bundling (≤1 per 6h) job.

### Phase J — Search & Discoverability

* Create **FTS5** tables and triggers for post content; set recency filters.
* If FTS unavailable, configure **Vectorize** embeddings + hybrid ranking; keep board‑scoped D1 pre‑filter.

### Phase K — Access Controls & Privacy

* Enforce all authz in Workers/DOs (since D1 lacks RLS).
* Guarantee that non‑admins cannot read raw **engagements**; only aggregated counts exposed.
* Enforce **shadowban** invisibility and **block** suppressions; verify ban scopes and expiries.
* Ensure raw GPS never persisted.

### Phase L — Performance & Indexing

* Create indexes for hot paths (board+created desc; hot_rank desc; parent replies; followers lookups).
* Validate pagination (20 items) and query plans under load via Pages preview tests.
* Confirm CDN cache behavior for feeds and images; thumbnails present; lazy loading enabled.

### Phase M — Jobs & Scheduling

* Register recurring jobs: Topics (15–60 min), Leaderboard (5 min), Live‑mode detector (2 min), Emergency delete guardrail (6 h), Metrics refresh (hourly), Digests (6 h max).
* Ensure idempotency; record last‑run timestamps; monitor Queue depth.

### Phase N — Data Migration Order (human‑readable)

1. Provision Cloudflare resources and bindings.
2. Create additive tables/views and preferences in D1.
3. Backfill identities and aliases.
4. Align posts and engagements; reconcile reactions.
5. Normalize flags/mod actions/bans.
6. Enable topics/leaderboard/live‑mode artifacts.
7. Enforce access controls in Workers/DOs; test deny paths.
8. Switch Pages/Workers to new endpoints; monitor.
9. Deprecate legacy columns/views after stability window.

### Phase O — Validation & Sign‑off

* Metric parity checks: #posts, #replies, reactions totals, flags open/closed, bans active.
* Functional runs: posting, reacting, flagging, blocking/muting, following, topics, search.
* Adversarial checks: denial of raw engagements, shadowban behavior, blocked content suppression.
* Notifications fire; DND and bundling obeyed.
* Stakeholder sign‑off (Product, Eng, Safety, Admins).

### Phase P — Cutover

* Announce short read‑only window if needed; switch traffic to new Workers/Pages routes.
* Enable WS channels; validate fan‑out and batching.
* Watch dashboards (latency, error rate, auto‑hide triggers, WS downgrade).

### Phase Q — Post‑Cutover & Cleanup

* Remove temporary flags; keep kill‑switches for live‑mode and auto‑hide.
* Decommission deprecated schemas after cooling period; snapshot backups.
* Publish post‑mortem with timings, bugs, remediation, docs links.

### Phase R — Rollback Strategy

* Define clear rollback triggers (auth failure, unbounded errors, feed downtime, data corruption).
* Maintain last‑known‑good D1 exports and R2 snapshots; restore runbooks prepared.
* Communicate rollback steps and expected downtime; keep immutable decision log.

---

## 21) QA Test Plan — Minimal‑Code, Comprehensive (Cloudflare)

**Goal:** Prove that the v2.2 platform meets functional, safety, performance, and privacy requirements on mobile‑first web, with Cloudflare edge specifics.

### Test Roles & Personas

* **Student User (new/established)** — baseline & live‑event conditions.
* **Influencer User** — elevated volume to validate leaderboard and tie‑breaker behavior.
* **Abuser Actor** — spam, brigading, harassment attempts.
* **Admin Moderator** — queue processing, emergency deletes, thread freeze, bans.

### Environments & Data

* Pages preview + D1 dev seeded with: 3 Boards (campus, neighborhood, other); 4 Spaces each; 200 users (50 new, 150 established); 2k posts (50% images); realistic timestamps; reactions/flags to produce hot posts and auto‑hides.

### Functional Test Areas

1. **Location & Board Detection** — boundary crossing; Board creation on first post; display names and truncation.
2. **Posting & Drafts** — limits; image rules; draft Board lock; move A→B prompt; R2 upload + thumbnail generation.
3. **Replies** — 2‑level nesting; Space inheritance.
4. **Reactions** — like/dislike toggling; cross‑device consistency; anonymity preserved; aggregate counts correct.
5. **Following & Profiles** — follow/unfollow; Following feed across Boards; alias vs global precedence.
6. **Trending Topics** — tags appear only above volume threshold; tap‑to‑filter window behavior.
7. **Search** — 7‑day scope; includes ≥10‑reaction posts up to 30 days; Space filter; relevance vs time sort; FTS5 or Vectorize hybrid.
8. **Notifications** — realtime for replies/mentions; digest bundling; DND + campus quiet hours.

### Safety & Moderation Tests

1. **Flagging Pipeline** — 5 distinct reporters trigger auto‑hide; Moderation DO queue shows reasons/timestamps.
2. **Actions** — hide (soft), delete (hard with two‑person confirm & 72h auto‑restore), shadowban, ban (scoped & timed), cooldown, thread freeze (15 min). Access‑gated.
3. **Brigade Detection** — entropy/timing bursts surface; IP/device overlaps reported (no user exposure).
4. **Shadowban Visibility** — author/admins see content; others don’t; self‑reactions don’t affect rankings.
5. **Blocks & Mutes** — blocked user’s content and replies hidden from blocker; mute hides content only; reversibility verified.

### RLS/Privacy‑Equivalent Tests

* **Engagement Privacy** — non‑admin attempts to read raw engagements fail; aggregates visible.
* **Ban Enforcement** — writes denied when ban active; scope respected; expiry restores rights.
* **Location Data** — raw GPS not persisted; only Board anchors present.
* **Device Fingerprints** — salted hashes only; not used cross‑device except abuse heuristics.

### Realtime & Live‑Event Tests

* **WS Delivery** — new posts/reactions appear <1s p95; batching prevents UI thrash.
* **Backpressure Fallback** — simulate >1k concurrent; auto‑downgrade to polling; feed remains functional.
* **Live Mode Auto‑On** — thresholds relax limits; auto‑off after idle; admin overrides work.

### Performance & Reliability

* **Cold Load p90** — <1.5s on 4G profiles for Board, Following, Profile.
* **Interaction Latency** — <100 ms for react/flag/follow toggles.
* **Image Pipeline** — thumbnails served; lazy‑loaded; CDN cache hits on target.
* **Queues Lag** — digest and topics jobs stay within SLA; alert on backlog.

### Accessibility (WCAG 2.1 AA)

* **Keyboard Navigation** — focus order, skip links, visible focus, modal trapping.
* **Labels/Announcements** — ARIA for buttons, toasts, dynamic counts; alt text for images.
* **Contrast & Tap Targets** — AA pass; ≥44×44 px.

### Cross‑Device & Resilience

* **Mobile breakpoints** — iOS Safari, Chrome Android; viewport/orientation.
* **Offline/Weak Network** — readable errors; retries; degraded images; no data corruption.
* **Session Handling** — token expiry, logout/login flows, preserved drafts.

### Observability & Alerting

* **Event Logging** — all key events fire with required fields; no PII leakage.
* **Dashboards** — DAU/WAU/MAU; flags/hour; live‑mode activations; WS downgrade; Queue lag.
* **Alerts** — trigger on flag spikes, auto‑hide rates, WS downgrades, emergency‑delete backlog.

### Acceptance Criteria (Go/No‑Go)

* Functional: Core flows pass; topics/search windows honored; notifications correct and respectful of DND.
* Safety: Auto‑hide works; moderation actions recorded immutably; shadowban/ban/block behaviors correct.
* Privacy: Sensitive tables not directly readable; aggregates only; GPS never persisted.
* Performance: p90/p95 targets met under expected load; realtime behaves; fallback works.
* Accessibility: AA checks pass on representative devices.

---

## 22) Deployment & DevOps on Cloudflare (No Code)

* **Monorepo:** `apps/web` (Pages/Next.js), `apps/api` (Workers + DOs), `packages/ui`, `packages/schemas`.
* **Wrangler Environments:** `dev`, `stage`, `prod` — separate bindings for D1, KV, R2, DO, Queues, Vectorize.
* **Secrets & Config:** JWT keys, VAPID, Turnstile keys, Access policies. Rotated quarterly.
* **Pages Pipelines:** PR preview → stage promotion → prod; synthetic checks gate prod.
* **Migrations:** D1 migrations tracked and versioned; dry‑run against dev/stage before prod.
* **Feature Flags:** KV‑based; evaluated at edge.
* **SLOs:** p90 feed <1.5s, realtime p95 <1s, 99.9% API availability, Queue lag <2 min p95.

---

**End of v2.2**
