import type { Env } from '../types';
import { normalizeBoardId } from '../utils';
import type { BoardAlias } from '@board-app/shared';
import type { RadiusState } from '@board-app/shared/location';

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
        'SELECT id, board_id, user_id, alias, created_at FROM board_aliases WHERE board_id = ?1 AND user_id = ?2'
    )
        .bind(boardId, userId)
        .first<{ id: string; board_id: string; user_id: string; alias: string; created_at: number }>();

    if (!record) {
        return null;
    }

    return {
        id: record.id,
        boardId: record.board_id,
        userId: record.user_id,
        alias: record.alias,
        createdAt: record.created_at
    };
}
