import { describe, expect, it, beforeEach } from 'vitest';
import {
    issueSessionTicket,
    getSessionByToken,
    deleteSessionByToken
} from '../../lib/session';
import type { Env } from '../../types';

describe('Session Management', () => {
    let env: Env;
    let mockSessions: Map<string, unknown>;

    beforeEach(() => {
        mockSessions = new Map();

        env = {
            BOARD_DB: {
                prepare: (sql: string) => ({
                    bind: (...params: unknown[]) => ({
                        run: async () => {
                            // Mock INSERT INTO sessions
                            if (sql.includes('INSERT INTO sessions')) {
                                const [token, userId, createdAt, expiresAt] = params;
                                mockSessions.set(token, { token, user_id: userId, created_at: createdAt, expires_at: expiresAt });
                                return { success: true, meta: {} };
                            }
                            // Mock DELETE FROM sessions
                            if (sql.includes('DELETE FROM sessions')) {
                                const [token] = params;
                                mockSessions.delete(token);
                                return { success: true, meta: {} };
                            }
                            return { success: true, meta: {} };
                        },
                        first: async () => {
                            // Mock SELECT session
                            if (sql.includes('SELECT token, user_id')) {
                                const [token] = params;
                                return mockSessions.get(token) || null;
                            }
                            return null;
                        }
                    })
                })
            } as any,
            BOARD_ROOM_DO: {} as any,
        };
    });

    describe('issueSessionTicket', () => {
        it('should create a new session ticket', async () => {
            const userId = 'user-123';
            const session = await issueSessionTicket(env, userId);

            expect(session).toHaveProperty('token');
            expect(session).toHaveProperty('userId', userId);
            expect(session).toHaveProperty('expiresAt');
            expect(session.token).toBeTruthy();
            expect(session.token.length).toBeGreaterThan(0);
        });
    });

    describe('getSessionByToken', () => {
        it('should return session if valid and not expired', async () => {
            const token = 'valid-token';
            const userId = 'user-123';
            const expiresAt = Date.now() + 3600000; // 1 hour from now

            mockSessions.set(token, {
                token,
                user_id: userId,
                created_at: Date.now(),
                expires_at: expiresAt
            });

            const session = await getSessionByToken(env, token);

            expect(session).toBeTruthy();
            expect(session?.token).toBe(token);
            expect(session?.user_id).toBe(userId);
        });

        it('should return null if session does not exist', async () => {
            const session = await getSessionByToken(env, 'nonexistent-token');
            expect(session).toBeNull();
        });

        it('should return null and delete expired session', async () => {
            const token = 'expired-token';
            mockSessions.set(token, {
                token,
                user_id: 'user-123',
                created_at: Date.now() - 90000000,
                expires_at: Date.now() - 1000 // Expired 1 second ago
            });

            const session = await getSessionByToken(env, token);

            expect(session).toBeNull();
            expect(mockSessions.has(token)).toBe(false);
        });
    });

    describe('deleteSessionByToken', () => {
        it('should delete session by token', async () => {
            const token = 'session-to-delete';
            mockSessions.set(token, {
                token,
                user_id: 'user-123',
                created_at: Date.now(),
                expires_at: Date.now() + 3600000
            });

            await deleteSessionByToken(env, token);

            expect(mockSessions.has(token)).toBe(false);
        });
    });
});
