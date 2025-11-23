export interface Env {
    BOARD_DB: D1Database;
    BOARD_ROOM_DO: DurableObjectNamespace;
    ACCESS_JWT_AUDIENCE?: string;
    ACCESS_JWT_ISSUER?: string;
    ACCESS_JWT_JWKS_URL?: string;
    PHASE_ONE_BOARDS?: string;
    PHASE_ONE_TEXT_ONLY_BOARDS?: string;
    PHASE_ONE_RADIUS_METERS?: string;
    PHASE_ADMIN_TOKEN?: string;
    ENABLE_IMAGE_UPLOADS?: string;
    ALLOWED_ORIGINS?: string;
}

export class ApiError extends Error {
    status: number;
    body: Record<string, unknown>;

    constructor(status: number, body: Record<string, unknown>) {
        super(typeof body.error === 'string' ? body.error : 'error');
        this.status = status;
        this.body = body;
    }
}

export interface AccessPrincipal {
    subject?: string;
    email?: string;
}

export interface UserAccessLink {
    access_subject: string;
    user_id: string;
    email: string | null;
}

export interface PhaseOneConfig {
    boards: Set<string>;
    textOnlyBoards: Set<string>;
    radiusMeters: number;
}

export interface DeadZoneSnapshot {
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

export interface AccessJwtConfig {
    issuer: string;
    audience: string;
    jwksUrl?: string;
}
