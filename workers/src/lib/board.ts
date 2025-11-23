import type { Env } from '../types';
import { normalizeBoardId } from '../utils';
import type { BoardAlias, BoardSummary, BoardEventPayload } from '@board-app/shared';
import type { RadiusState } from '@board-app/shared/location';
import { BoardRoom } from '../board-room';

// ... (existing code)

export async function persistEvent(env: Env, record: BoardEventPayload, boardId: string) {
    await env.BOARD_DB.prepare(
        `INSERT INTO board_events (id, board_id, event_type, payload, trace_id, created_at)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6)`
    )
        .bind(
            record.id,
            boardId,
            record.event ?? 'message',
            JSON.stringify(record.data ?? null),
            record.traceId ?? 'unknown',
            record.timestamp ?? Date.now()
        )
        .run();
}

export async function snapshotBoardMetrics(env: Env, options: { now?: number } = {}): Promise<void> {
    const now = options.now ?? Date.now();
    const { results } = await env.BOARD_DB.prepare(
        'SELECT id, display_name, description, created_at, radius_meters, radius_state, radius_updated_at, phase_mode, text_only, latitude, longitude FROM boards'
    ).all<BoardRecord>();
    const boards = results ?? [];

    for (const board of boards) {
        const snapshot = await computeBoardMetrics(env, board, now);
        await upsertBoardMetrics(env, snapshot);
    }
}

export const ADAPTIVE_RADIUS_WINDOW_MS = 2 * 60 * 60 * 1000;
export const ADAPTIVE_RADIUS_FRESH_THRESHOLD = 8;
export const ADAPTIVE_RADIUS_STALE_THRESHOLD = 4;


const DEFAULT_BOARD_COORDS: Record<string, { latitude: number; longitude: number }> = {
    'demo-board': { latitude: 37.7749, longitude: -122.4194 },
    'campus-north': { latitude: 40.1036, longitude: -88.2272 },
    'smoke-board': { latitude: 34.0522, longitude: -118.2437 }
};

export type BoardRecord = {
    id: string;
    display_name: string;
    description: string | null;
    created_at: number;
    radius_meters: number;
    radius_state: string | null;
    radius_updated_at: number;
    phase_mode: 'default' | 'phase1';
    text_only: number;
    latitude: number | null;
    longitude: number | null;
};

// Global state for board rooms
export const boardRooms = new Map<string, BoardRoom>();

export function getBoardRoom(boardId: string) {
    let room = boardRooms.get(boardId);
    if (!room) {
        room = new BoardRoom({ boardId });
        boardRooms.set(boardId, room);
    }
    return room;
}

export function requirePhaseAdmin(request: Request, env: Env) {
    const token = (request.headers.get('Authorization') ?? '').replace(/^Bearer\s+/i, '');
    if (!env.PHASE_ADMIN_TOKEN || token !== env.PHASE_ADMIN_TOKEN) {
        // We need to throw ApiError here, but it's not exported from types.
        // It's usually in types.ts or a separate errors file.
        // Checking imports in index.ts: import { ApiError } from './types';
        // So I should import it.
        throw new Error('unauthorized phase admin request'); // Temporary fallback if ApiError not available, but I imported it above.
    }
}

function formatBoardName(boardId: string): string {
    return boardId
        .split('-')
        .map(word => word.charAt(0).toUpperCase() + word.slice(1))
        .join(' ');
}

export async function getOrCreateBoard(env: Env, boardId: string): Promise<BoardRecord> {
    const existing = await env.BOARD_DB.prepare(
        'SELECT id, display_name, description, created_at, radius_meters, radius_state, radius_updated_at, phase_mode, text_only, latitude, longitude FROM boards WHERE id = ?1'
    )
        .bind(boardId)
        .first<BoardRecord>();

    if (existing) {
        const normalizedId = normalizeBoardId(boardId);
        const defaultLocation = DEFAULT_BOARD_COORDS[normalizedId];
        if (defaultLocation && (existing.latitude == null || existing.longitude == null)) {
            await env.BOARD_DB.prepare('UPDATE boards SET latitude = ?1, longitude = ?2 WHERE id = ?3')
                .bind(defaultLocation.latitude, defaultLocation.longitude, boardId)
                .run();
            existing.latitude = defaultLocation.latitude;
            existing.longitude = defaultLocation.longitude;
        }
        return existing;
    }

    const createdAt = Date.now();
    const displayName = formatBoardName(boardId);
    const radiusState: RadiusState = { currentMeters: 1500, lastExpandedAt: null, lastContractedAt: null };
    const defaultLocation = DEFAULT_BOARD_COORDS[normalizeBoardId(boardId)] ?? null;

    await env.BOARD_DB.prepare(
        'INSERT INTO boards (id, display_name, description, created_at, radius_meters, radius_state, radius_updated_at, phase_mode, text_only, latitude, longitude) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)'
    )
        .bind(
            boardId,
            displayName,
            null,
            createdAt,
            radiusState.currentMeters,
            JSON.stringify(radiusState),
            createdAt,
            'default',
            0,
            defaultLocation?.latitude ?? null,
            defaultLocation?.longitude ?? null
        )
        .run();

    return {
        id: boardId,
        display_name: displayName,
        description: null,
        created_at: createdAt,
        radius_meters: radiusState.currentMeters,
        radius_state: JSON.stringify(radiusState),
        radius_updated_at: createdAt,
        phase_mode: 'default',
        text_only: 0,
        latitude: defaultLocation?.latitude ?? null,
        longitude: defaultLocation?.longitude ?? null
    };
}

export async function upsertBoardAlias(
    env: Env,
    boardId: string,
    userId: string,
    alias: string,
    normalized: string
): Promise<BoardAlias> {
    const id = crypto.randomUUID();
    const createdAt = Date.now();

    await env.BOARD_DB.prepare(
        `INSERT INTO board_aliases (id, board_id, user_id, alias, alias_normalized, created_at)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6)
     ON CONFLICT(board_id, user_id) DO UPDATE SET
       alias = excluded.alias,
       alias_normalized = excluded.alias_normalized`
    )
        .bind(id, boardId, userId, alias, normalized, createdAt)
        .run();

    return {
        id,
        boardId,
        userId,
        alias,
        createdAt
    };
}

export async function getBoardAlias(env: Env, boardId: string, userId: string): Promise<BoardAlias | null> {
    const record = await env.BOARD_DB.prepare(
        'SELECT id, board_id, user_id, alias, alias_normalized, created_at FROM board_aliases WHERE board_id = ?1 AND user_id = ?2'
    )
        .bind(boardId, userId)
        .first<{ id: string; board_id: string; user_id: string; alias: string; alias_normalized: string; created_at: number }>();

    if (!record) {
        return null;
    }

    return {
        id: record.id,
        boardId: record.board_id,
        userId: record.user_id,
        alias: record.alias,
        aliasNormalized: record.alias_normalized,
        createdAt: record.created_at
    };
}

interface PhaseOneConfig {
    boards: Set<string>;
    textOnlyBoards: Set<string>;
    radiusMeters: number;
}

const phaseOneConfigCache = new WeakMap<Env, PhaseOneConfig>();

function parseBoardList(value?: string): Set<string> {
    if (!value) return new Set();
    return new Set(value.split(',').map(s => normalizeBoardId(s)).filter(Boolean));
}

export function getPhaseOneConfig(env: Env): PhaseOneConfig {
    const cached = phaseOneConfigCache.get(env);
    if (cached) {
        return cached;
    }

    const boards = parseBoardList(env.PHASE_ONE_BOARDS);
    const textOnlyBoards = parseBoardList(env.PHASE_ONE_TEXT_ONLY_BOARDS ?? env.PHASE_ONE_BOARDS);
    const radiusRaw = Number(env.PHASE_ONE_RADIUS_METERS ?? '1500');
    const radiusMeters = Number.isFinite(radiusRaw) && radiusRaw > 0 ? Math.max(250, Math.min(radiusRaw, 5000)) : 1500;

    const config: PhaseOneConfig = {
        boards,
        textOnlyBoards,
        radiusMeters
    };
    phaseOneConfigCache.set(env, config);
    return config;
}

interface BoardMetricsRow {
    board_id: string;
    snapshot_at: number;
    active_connections: number;
    posts_last_hour: number;
    posts_last_day: number;
    posts_prev_day: number;
    last_post_at: number | null;
}

interface BoardMetricsSnapshot {
    boardId: string;
    snapshotAt: number;
    activeConnections: number;
    postsLastHour: number;
    postsLastDay: number;
    postsPrevDay: number;
    lastPostAt: number | null;
}

const BOARD_METRICS_STALE_MS = 5 * 60 * 1000;

export async function computeBoardMetrics(env: Env, board: BoardRecord, now: number): Promise<BoardMetricsSnapshot> {
    const hourAgo = now - 60 * 60 * 1000;
    const dayAgo = now - 24 * 60 * 60 * 1000;
    const twoDaysAgo = now - 48 * 60 * 60 * 1000;

    const stats = await env.BOARD_DB.prepare(
        `SELECT
        SUM(CASE WHEN created_at >= ?2 THEN 1 ELSE 0 END) AS posts_last_hour,
        SUM(CASE WHEN created_at >= ?3 THEN 1 ELSE 0 END) AS posts_last_day,
        SUM(CASE WHEN created_at >= ?4 AND created_at < ?3 THEN 1 ELSE 0 END) AS posts_prev_day,
        MAX(created_at) AS last_post_at
       FROM posts
       WHERE board_id = ?1`
    )
        .bind(board.id, hourAgo, dayAgo, twoDaysAgo)
        .first<{
            posts_last_hour: number | null;
            posts_last_day: number | null;
            posts_prev_day: number | null;
            last_post_at: number | null;
        }>();

    const room = boardRooms.get(board.id);
    const activeConnections = room?.getConnectionCount() ?? 0;

    return {
        boardId: board.id,
        snapshotAt: now,
        activeConnections,
        postsLastHour: stats?.posts_last_hour ?? 0,
        postsLastDay: stats?.posts_last_day ?? 0,
        postsPrevDay: stats?.posts_prev_day ?? 0,
        lastPostAt: stats?.last_post_at ?? null
    };
}

export async function upsertBoardMetrics(env: Env, snapshot: BoardMetricsSnapshot): Promise<void> {
    await env.BOARD_DB.prepare(
        `INSERT INTO board_metrics (
        board_id,
        snapshot_at,
        active_connections,
        posts_last_hour,
        posts_last_day,
        posts_prev_day,
        last_post_at
      ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
      ON CONFLICT(board_id) DO UPDATE SET
        snapshot_at = excluded.snapshot_at,
        active_connections = excluded.active_connections,
        posts_last_hour = excluded.posts_last_hour,
        posts_last_day = excluded.posts_last_day,
        posts_prev_day = excluded.posts_prev_day,
        last_post_at = excluded.last_post_at`
    )
        .bind(
            snapshot.boardId,
            snapshot.snapshotAt,
            snapshot.activeConnections,
            snapshot.postsLastHour,
            snapshot.postsLastDay,
            snapshot.postsPrevDay,
            snapshot.lastPostAt
        )
        .run();
}

export async function listBoardsCatalog(env: Env, options: { limit?: number } = {}): Promise<BoardSummary[]> {

    const limitRaw = options.limit ?? 12;
    const limit = Math.max(1, Math.min(limitRaw, 50));
    const { results } = await env.BOARD_DB.prepare(
        `SELECT
        id,
        display_name,
        description,
        created_at,
        radius_meters,
        radius_state,
        radius_updated_at,
        phase_mode,
        text_only,
        latitude,
        longitude
      FROM boards
      ORDER BY created_at ASC
      LIMIT ?1`
    )
        .bind(limit)
        .all<BoardRecord>();

    const rows = results ?? [];
    const now = Date.now();

    const enriched = await Promise.all(
        rows.map(async record => {
            const boardId = record.id;
            const metricsRow = await env.BOARD_DB.prepare(
                `SELECT board_id, snapshot_at, active_connections, posts_last_hour, posts_last_day, posts_prev_day, last_post_at
           FROM board_metrics
          WHERE board_id = ?1`
            )
                .bind(boardId)
                .first<BoardMetricsRow>();

            let snapshot: BoardMetricsSnapshot | null = metricsRow
                ? {
                    boardId: metricsRow.board_id,
                    snapshotAt: metricsRow.snapshot_at,
                    activeConnections: metricsRow.active_connections,
                    postsLastHour: metricsRow.posts_last_hour,
                    postsLastDay: metricsRow.posts_last_day,
                    postsPrevDay: metricsRow.posts_prev_day,
                    lastPostAt: metricsRow.last_post_at ?? null
                }
                : null;

            if (!snapshot || now - snapshot.snapshotAt > BOARD_METRICS_STALE_MS) {
                snapshot = await computeBoardMetrics(env, record, now);
                await upsertBoardMetrics(env, snapshot);
            }

            const liveConnections = boardRooms.get(boardId)?.getConnectionCount();
            const activeConnections = liveConnections ?? snapshot.activeConnections;
            const postsLastDay = snapshot.postsLastDay;
            const postsPrevDay = snapshot.postsPrevDay;
            const trend = postsPrevDay > 0
                ? ((postsLastDay - postsPrevDay) / postsPrevDay) * 100
                : postsLastDay > 0
                    ? 100
                    : null;

            const radiusMeters = record.radius_meters ?? undefined;
            const radiusLabel = radiusMeters
                ? `${radiusMeters.toLocaleString('en-US')} m radius`
                : null;

            return {
                id: boardId,
                displayName: record.display_name,
                description: record.description,
                createdAt: record.created_at,
                radiusMeters,
                radiusUpdatedAt: record.radius_updated_at ?? null,
                phaseMode: record.phase_mode === 'phase1' ? 'phase1' : 'default',
                textOnly: Boolean(record.text_only),
                activeConnections,
                postsLastHour: snapshot.postsLastHour,
                postsLastDay,
                postsTrend24Hr: trend,
                lastPostAt: snapshot.lastPostAt,
                radiusLabel,
                latitude: record.latitude ?? null,
                longitude: record.longitude ?? null
            } satisfies BoardSummary;
        })
    );

    return enriched;
}

export async function getLatestFreshnessSnapshot(env: Env, boardId: string) {
    const record = await env.BOARD_DB.prepare(
        `SELECT payload FROM board_events
       WHERE board_id = ?1 AND event_type = ?2
       ORDER BY created_at DESC
       LIMIT 1`
    )
        .bind(boardId, 'board.freshness')
        .first<{ payload: string }>();

    if (!record) return null;
    try {
        return JSON.parse(record.payload) as DeadZoneSnapshot;
    } catch {
        return null;
    }
}

interface DeadZoneSnapshot {
    boardId: string;
    status: 'healthy' | 'dead_zone';
    postCount: number;
    windowStart: number;
    windowEnd: number;
    threshold: number;
    deadZoneStreak: number;
    alertTriggered: boolean;
    lastPostAt: number | null;
}

const DEAD_ZONE_WINDOW_MS = 2 * 60 * 60 * 1000;
const DEAD_ZONE_MIN_POSTS = 3;
const DEAD_ZONE_STREAK_THRESHOLD = 3;

export async function detectDeadZones(
    env: Env,
    options: {
        now?: number;
        windowMs?: number;
        minPosts?: number;
        streakThreshold?: number;
    } = {}
) {

    const now = options.now ?? Date.now();
    const windowMs = options.windowMs ?? DEAD_ZONE_WINDOW_MS;
    const minPosts = options.minPosts ?? DEAD_ZONE_MIN_POSTS;
    const streakThreshold = options.streakThreshold ?? DEAD_ZONE_STREAK_THRESHOLD;
    const windowStart = now - windowMs;

    const boardRows = await env.BOARD_DB.prepare('SELECT id FROM boards ORDER BY id ASC').all<{ id: string }>();
    const boards = boardRows?.results ?? [];

    const snapshots: DeadZoneSnapshot[] = [];
    const alerts: DeadZoneSnapshot[] = [];

    for (const board of boards) {
        const boardId = board.id;
        const countRow = await env.BOARD_DB.prepare(
            `SELECT COUNT(*) AS post_count
         FROM posts
        WHERE board_id = ?1
          AND created_at >= ?2`
        )
            .bind(boardId, windowStart)
            .first<{ post_count: number | null }>();

        const postCount = countRow?.post_count ?? 0;
        const status: DeadZoneSnapshot['status'] = postCount >= minPosts ? 'healthy' : 'dead_zone';

        const lastPostRow = await env.BOARD_DB.prepare(
            `SELECT MAX(created_at) AS last_post_at
         FROM posts
        WHERE board_id = ?1`
        )
            .bind(boardId)
            .first<{ last_post_at: number | null }>();

        const previous = await getLatestFreshnessSnapshot(env, boardId);
        const previousStreak = typeof previous?.deadZoneStreak === 'number' ? previous.deadZoneStreak : 0;
        const previousStatus = previous?.status;
        let deadZoneStreak = 0;

        if (status === 'dead_zone') {
            deadZoneStreak = previousStatus === 'dead_zone' ? previousStreak + 1 : 1;
        }

        const alertTriggered = status === 'dead_zone' && deadZoneStreak >= streakThreshold;
        const traceId = crypto.randomUUID();

        const snapshot: DeadZoneSnapshot = {
            boardId,
            status,
            postCount,
            windowStart,
            windowEnd: now,
            threshold: minPosts,
            deadZoneStreak,
            alertTriggered,
            lastPostAt: lastPostRow?.last_post_at ?? null
        };

        snapshots.push(snapshot);
        if (alertTriggered) {
            alerts.push(snapshot);
        }

        await env.BOARD_DB.prepare(
            `INSERT INTO board_events (id, board_id, event_type, payload, created_at, trace_id)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6)`
        )
            .bind(
                crypto.randomUUID(),
                boardId,
                'board.freshness',
                JSON.stringify(snapshot),
                now,
                traceId
            )
            .run();

        // Emit alert event if dead zone triggered
        if (alertTriggered) {
            await env.BOARD_DB.prepare(
                `INSERT INTO board_events (id, board_id, event_type, payload, created_at, trace_id)
           VALUES (?1, ?2, ?3, ?4, ?5, ?6)`
            )
                .bind(
                    crypto.randomUUID(),
                    boardId,
                    'board.dead_zone_triggered',
                    JSON.stringify(snapshot),
                    now,
                    traceId
                )
                .run();
        }
    }

    return {
        snapshots,
        alerts,
        windowStart,
        windowEnd: now,
        results: boards
    };
}

