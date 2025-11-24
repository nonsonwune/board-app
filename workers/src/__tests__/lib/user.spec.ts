import { describe, expect, it, beforeEach } from 'vitest';
import { createUser, getUserById, userRecordToProfile } from '../../lib/user';
import type { Env } from '../../types';

describe('User Management', () => {
    let env: Env;
    let mockUsers: Map<string, unknown>;

    beforeEach(() => {
        mockUsers = new Map();

        env = {
            BOARD_DB: {
                prepare: (sql: string) => ({
                    bind: (...params: unknown[]) => ({
                        run: async () => {
                            // Mock INSERT INTO users
                            if (sql.includes('INSERT INTO users')) {
                                const [id, pseudonym, normalized, recoveryKeyHash, createdAt, status] = params;
                                mockUsers.set(id as string, {
                                    id,
                                    pseudonym,
                                    pseudonym_normalized: normalized,
                                    recovery_key_hash: recoveryKeyHash,
                                    created_at: createdAt,
                                    status
                                });
                                return { success: true, meta: {} };
                            }
                            return { success: true, meta: {} };
                        },
                        first: async () => {
                            // Mock SELECT user by ID
                            if (sql.includes('SELECT id, pseudonym')) {
                                const [userId] = params;
                                return mockUsers.get(userId as string) || null;
                            }
                            return null;
                        }
                    })
                })
            } as unknown as Env['BOARD_DB'],
            BOARD_ROOM_DO: {} as unknown as Env['BOARD_ROOM_DO'],
        };
    });

    describe('createUser', () => {
        it('should create a new user', async () => {
            const pseudonym = 'TestUser';
            const normalized = 'testuser';

            const user = await createUser(env, pseudonym, normalized);

            expect(user).toHaveProperty('id');
            expect(user).toHaveProperty('pseudonym', pseudonym);
            expect(user).toHaveProperty('createdAt');
            expect(user.id).toBeTruthy();
        });

        it('should set status to active by default', async () => {
            const user = await createUser(env, 'User', 'user');

            // Verify the user was stored with active status
            const stored = mockUsers.get(user.id) as { status: string } | undefined;
            expect(stored?.status).toBe('active');
        });

        it('should accept custom status', async () => {
            const user = await createUser(env, 'AutoUser', 'autouser', 'access_auto');

            const stored = mockUsers.get(user.id) as { status: string } | undefined;
            expect(stored?.status).toBe('access_auto');
        });
    });

    describe('getUserById', () => {
        it('should return user if exists', async () => {
            const userId = 'user-123';
            mockUsers.set(userId, {
                id: userId,
                pseudonym: 'TestUser',
                pseudonym_normalized: 'testuser',
                created_at: Date.now(),
                status: 'active'
            });

            const user = await getUserById(env, userId);

            expect(user).toBeTruthy();
            expect(user?.id).toBe(userId);
            expect(user?.pseudonym).toBe('TestUser');
        });

        it('should return null if user does not exist', async () => {
            const user = await getUserById(env, 'nonexistent-user');
            expect(user).toBeNull();
        });
    });

    describe('userRecordToProfile', () => {
        it('should convert user record to profile', () => {
            const userRecord = {
                id: 'user-456',
                pseudonym: 'ProfileUser',
                pseudonym_normalized: 'profileuser',
                created_at: 1234567890,
                status: 'active' as const
            };

            const profile = userRecordToProfile(userRecord);

            expect(profile).toEqual({
                id: 'user-456',
                pseudonym: 'ProfileUser',
                createdAt: 1234567890
            });
        });

        it('should only include profile fields', () => {
            const userRecord = {
                id: 'user-789',
                pseudonym: 'Test',
                pseudonym_normalized: 'test',
                created_at: 9876543210,
                status: 'access_auto' as const
            };

            const profile = userRecordToProfile(userRecord);

            expect(profile).not.toHaveProperty('pseudonym_normalized');
            expect(profile).not.toHaveProperty('status');
        });
    });
});
