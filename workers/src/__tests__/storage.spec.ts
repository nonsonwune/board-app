/* eslint-disable @typescript-eslint/no-explicit-any, @typescript-eslint/no-unused-vars */
import { describe, expect, it, beforeEach, vi } from 'vitest';
import WorkerEntrypoint, {
  detectDeadZones,
  __internal
} from '../index';
import { getOrCreateBoard, snapshotBoardMetrics, listBoardsCatalog, upsertBoardAlias, getBoardAlias } from '../lib/board';
import { createPost, listPosts, searchBoardPosts, listUserPosts, listFollowingPosts, createReply, applyReaction } from '../lib/post';
import { createUser, setFollowState, getFollowCounts, isFollowing, listFollowingIds } from '../lib/user';
import type { BoardCatalogResponse, BoardFeedResponse } from '@board-app/shared';
import type { Env } from '../index';

// applyReaction was in index.ts but was removed - need to check if it exists elsewhere
// For now, let's create a stub or import from the correct location

type ExecCall = { sql: string };

type PreparedCall = {
  sql: string;
  params: any[];
};

class MockPrepared {
  constructor(private readonly db: MockD1, public readonly sql: string) { }

  bind(...params: any[]) {
    return new BoundPrepared(this.db, this.sql, params);
  }

  async run() {
    return new BoundPrepared(this.db, this.sql, []).run();
  }

  async all<T>() {
    return new BoundPrepared(this.db, this.sql, []).all<T>();
  }

  async first<T>() {
    return new BoundPrepared(this.db, this.sql, []).first<T>();
  }

  async raw<T extends unknown[] = unknown[]>(): Promise<T> {
    return [] as unknown as T;
  }

}


class BoundPrepared {
  constructor(private readonly db: MockD1, public readonly sql: string, private readonly params: any[]) { }

  bind(...params: any[]) {
    return new BoundPrepared(this.db, this.sql, [...this.params, ...params]);
  }

  async raw<T extends unknown[] = unknown[]>(): Promise<T> {
    return [] as T;
  }

  async run() {
    this.db.prepareCalls.push({ sql: this.sql, params: this.params });
    if (this.sql.startsWith('INSERT INTO boards')) {
      const [
        id,
        name,
        description,
        createdAt,
        radiusMeters = 1500,
        radiusState = null,
        radiusUpdatedAt = createdAt,
        phaseMode = 'default',
        textOnly = 0
      ] = this.params;
      this.db.boards.set(id, {
        id,
        display_name: name,
        description,
        created_at: createdAt,
        radius_meters: radiusMeters ?? 1500,
        radius_state: typeof radiusState === 'string' ? radiusState : radiusState ? JSON.stringify(radiusState) : null,
        radius_updated_at: radiusUpdatedAt ?? createdAt,
        phase_mode: phaseMode,
        text_only: textOnly
      });
    }
    if (this.sql.startsWith('INSERT INTO posts')) {
      const [id, boardId, userId, author, body, createdAt] = this.params;
      this.db.posts.push({
        id,
        board_id: boardId,
        user_id: userId,
        author,
        body,
        created_at: createdAt,
        reaction_count: 0,
        like_count: 0,
        dislike_count: 0
      });
    }
    if (this.sql.startsWith('INSERT INTO replies')) {
      const [id, postId, boardId, userId, author, body, createdAt] = this.params;
      this.db.replies.push({
        id,
        post_id: postId,
        board_id: boardId,
        user_id: userId,
        author,
        body,
        created_at: createdAt
      });
    }
    if (this.sql.startsWith('INSERT INTO board_events')) {
      const [id, boardId, eventType, payload, traceId, createdAt] = this.params;
      this.db.events.push({
        id,
        board_id: boardId,
        event_type: eventType,
        payload,
        trace_id: traceId,
        created_at: createdAt
      });
    }
    if (this.sql.startsWith('INSERT INTO board_metrics')) {
      const [boardId, snapshotAt, activeConnections, postsLastHour, postsLastDay, postsPrevDay, lastPostAt] = this.params;
      this.db.boardMetrics.set(boardId, {
        board_id: boardId,
        snapshot_at: snapshotAt,
        active_connections: activeConnections,
        posts_last_hour: postsLastHour,
        posts_last_day: postsLastDay,
        posts_prev_day: postsPrevDay,
        last_post_at: lastPostAt ?? null
      });
    }
    if (this.sql.startsWith('INSERT INTO dead_zone_alerts')) {
      const [id, boardId, streak, postCount, threshold, windowStart, windowEnd, windowMs, triggeredAt, alertLevel, traceId, createdAt] = this.params;
      this.db.deadZoneAlerts.push({
        id,
        board_id: boardId,
        streak,
        post_count: postCount,
        threshold,
        window_start: windowStart,
        window_end: windowEnd,
        window_ms: windowMs,
        triggered_at: triggeredAt,
        alert_level: alertLevel,
        trace_id: traceId,
        created_at: createdAt
      });
    }
    if (this.sql.startsWith('UPDATE boards SET phase_mode')) {
      const [phaseMode, textOnly, radiusMeters, radiusState, radiusUpdatedAt, boardId] = this.params;
      const board = this.db.boards.get(boardId);
      if (board) {
        board.phase_mode = phaseMode;
        board.text_only = textOnly;
        board.radius_meters = radiusMeters;
        board.radius_state = radiusState;
        board.radius_updated_at = radiusUpdatedAt;
      }
    }
    if (this.sql.startsWith('UPDATE boards SET radius_meters')) {
      const [radiusMeters, radiusState, radiusUpdatedAt, boardId] = this.params;
      const board = this.db.boards.get(boardId);
      if (board) {
        board.radius_meters = radiusMeters;
        board.radius_state = radiusState;
        board.radius_updated_at = radiusUpdatedAt;
      }
    }

    if (this.sql.startsWith('INSERT INTO access_identity_events')) {
      const [id, eventType, subject, userId, email, traceId, metadata, createdAt] = this.params;
      this.db.accessIdentityEvents.push({
        id,
        event_type: eventType,
        subject,
        user_id: userId,
        email,
        trace_id: traceId,
        metadata,
        created_at: createdAt
      });
    }
    if (this.sql.startsWith('INSERT INTO sessions')) {
      const [token, userId, createdAt, expiresAt] = this.params;
      this.db.sessions.set(token, { token, user_id: userId, created_at: createdAt, expires_at: expiresAt });
    }
    if (this.sql.startsWith('DELETE FROM sessions')) {
      const [token] = this.params;
      this.db.sessions.delete(token);
    }
    if (this.sql.startsWith('INSERT INTO users')) {
      const [id, pseudonym, normalized, createdAt, status] = this.params;
      if (Array.from(this.db.users.values()).some(user => user.pseudonym_normalized === normalized)) {
        throw new Error('UNIQUE constraint failed: users.pseudonym_normalized');
      }
      this.db.users.set(id, {
        id,
        pseudonym,
        pseudonym_normalized: normalized,
        created_at: createdAt,
        status: status ?? 'active'
      });
    }
    if (this.sql.startsWith('INSERT INTO board_aliases')) {
      const [id, boardId, userId, alias, aliasNormalized, createdAt] = this.params;
      const aliasKey = `${boardId}:${aliasNormalized}`;
      const userKey = `${boardId}:${userId}`;
      if (!this.sql.includes('ON CONFLICT')) {
        this.db.aliases.set(userKey, {
          id,
          board_id: boardId,
          user_id: userId,
          alias,
          alias_normalized: aliasNormalized,
          created_at: createdAt
        });
      } else {
        if (Array.from(this.db.aliases.values()).some(entry => entry.board_id === boardId && entry.alias_normalized === aliasNormalized && entry.user_id !== userId)) {
          throw new Error('UNIQUE constraint failed: board_aliases.board_id, board_aliases.alias_normalized');
        }
        const existing = this.db.aliases.get(userKey);
        if (existing) {
          existing.alias = alias;
          existing.alias_normalized = aliasNormalized;
        } else {
          this.db.aliases.set(userKey, {
            id,
            board_id: boardId,
            user_id: userId,
            alias,
            alias_normalized: aliasNormalized,
            created_at: createdAt
          });
        }
      }
      this.db.aliasLookup.set(aliasKey, userId);
    }
    if (this.sql.startsWith('INSERT INTO user_access_links')) {
      const [subject, userId, email] = this.params;
      const existing = this.db.accessLinks.get(subject);
      if (!existing) {
        for (const link of this.db.accessLinks.values()) {
          if (link.user_id === userId) {
            throw new Error('UNIQUE constraint failed: user_access_links.user_id');
          }
        }
        this.db.accessLinks.set(subject, {
          access_subject: subject,
          user_id: userId,
          email: email ?? null
        });
      } else {
        existing.user_id = userId;
        existing.email = email ?? null;
      }
    }
    if (this.sql.startsWith('INSERT INTO reactions')) {
      const [id, postId, boardId, userId, reaction, createdAt] = this.params;
      const key = `${postId}:${userId}`;
      const existing = this.db.reactions.get(key);
      if (existing) {
        existing.id = id;
        existing.reaction = reaction;
        existing.created_at = createdAt;
      } else {
        this.db.reactions.set(key, {
          id,
          post_id: postId,
          board_id: boardId,
          user_id: userId,
          reaction,
          created_at: createdAt
        });
      }
    }
    if (this.sql.startsWith('UPDATE posts SET like_count')) {
      const [likeCount, dislikeCount, total, postId] = this.params;
      const post = this.db.posts.find(p => p.id === postId);
      if (post) {
        post.like_count = likeCount;
        post.dislike_count = dislikeCount;
        post.reaction_count = total;
      }
    }
    if (this.sql.startsWith('UPDATE users SET status')) {
      const [status, userId] = this.params;
      const user = this.db.users.get(userId);
      if (user) {
        user.status = status;
      }
    }
    if (this.sql.startsWith('DELETE FROM reactions')) {
      const [postId, userId] = this.params;
      const key = `${postId}:${userId}`;
      this.db.reactions.delete(key);
    }
    if (this.sql.startsWith('INSERT INTO follows')) {
      const [followerId, followingId, createdAt] = this.params;
      const exists = this.db.follows.some(
        entry => entry.follower_id === followerId && entry.following_id === followingId
      );
      if (!exists) {
        this.db.follows.push({ follower_id: followerId, following_id: followingId, created_at: createdAt });
      }
    }
    if (this.sql.startsWith('DELETE FROM follows')) {
      const [followerId, followingId] = this.params;
      this.db.follows = this.db.follows.filter(
        entry => !(entry.follower_id === followerId && entry.following_id === followingId)
      );
    }
    return {
      results: [],
      success: true as const,
      meta: {
        duration: 0,
        size: 0,
        rows_read: 0,
        rows_written: 0,
        last_row_id: 0,
        size_after: 0,
        changed_db: false,
        changes: 0,
        served_by: 'mock'
      }
    };
  }

  async all<T>() {
    this.db.prepareCalls.push({ sql: this.sql, params: this.params });
    if (this.sql.startsWith('SELECT id FROM boards')) {
      const results = Array.from(this.db.boards.values()).map(board => ({ id: board.id }));
      return { results: results as T[], success: true as const, meta: { duration: 0, size: 0, rows_read: 0, rows_written: 0, last_row_id: 0, size_after: 0, changed_db: false, changes: 0, served_by: 'mock' } };
    }
    if (
      this.sql.includes('FROM boards') &&
      this.sql.includes('display_name') &&
      this.sql.includes('radius_meters')
    ) {
      const limit = Number(this.params[0]) || this.db.boards.size;
      const rows = Array.from(this.db.boards.values())
        .sort((a, b) => (a.created_at ?? 0) - (b.created_at ?? 0))
        .slice(0, limit);
      return { results: rows as T[], success: true as const, meta: { duration: 0, size: 0, rows_read: 0, rows_written: 0, last_row_id: 0, size_after: 0, changed_db: false, changes: 0, served_by: 'mock' } };
    }
    if (this.sql.includes('FROM board_metrics')) {
      const rows = Array.from(this.db.boardMetrics.values());
      return { results: rows as T[], success: true as const, meta: { duration: 0, size: 0, rows_read: 0, rows_written: 0, last_row_id: 0, size_after: 0, changed_db: false, changes: 0, served_by: 'mock' } };
    }
    if (this.sql.startsWith('SELECT id, display_name')) {
      const board = this.db.boards.get(this.params[0]);
      return { results: board ? [board as T] : [], success: true as const, meta: { duration: 0, size: 0, rows_read: 0, rows_written: 0, last_row_id: 0, size_after: 0, changed_db: false, changes: 0, served_by: 'mock' } };
    }
    if (this.sql.includes('FROM posts p')) {
      const rawLimit = Number(this.params[this.params.length - 1]) || this.db.posts.length;
      let posts = [...this.db.posts];

      if (this.sql.includes('WHERE p.created_at >= ?1')) {
        const earliest = this.params[0];
        const boardFilter = this.params[1];
        const likeFilter = this.params[2];
        const cursorCreatedAt = this.params[3];
        const cursorId = this.params[4];
        posts = posts.filter(post => post.created_at >= earliest);
        if (boardFilter) {
          posts = posts.filter(post => post.board_id === boardFilter);
        }
        if (typeof likeFilter === 'string' && likeFilter) {
          const needle = likeFilter
            .replace(/%/g, '')
            .replace(/_/g, '')
            .replace(/\\/g, '')
            .toLowerCase();
          posts = posts.filter(post => post.body.toLowerCase().includes(needle));
        }
        posts = posts.filter(
          post => post.created_at < cursorCreatedAt || (post.created_at === cursorCreatedAt && post.id < cursorId)
        );
      } else if (this.sql.includes('IN (SELECT following_id FROM follows')) {
        const followerId = this.params[0];
        const cursorCreatedAt = this.params[1];
        const cursorId = this.params[2];
        posts = posts.filter(post =>
          post.user_id && this.db.follows.some(entry => entry.follower_id === followerId && entry.following_id === post.user_id)
        );
        posts = posts.filter(
          post => post.created_at < cursorCreatedAt || (post.created_at === cursorCreatedAt && post.id < cursorId)
        );
      } else if (this.sql.includes('WHERE p.user_id = ?')) {
        const userId = this.params[0];
        posts = posts.filter(post => post.user_id === userId);
      } else if (this.sql.includes('WHERE p.board_id = ?1')) {
        const boardId = this.params[0];
        posts = posts.filter(post => post.board_id === boardId);
      }

      posts.sort((a, b) => {
        if (b.created_at !== a.created_at) {
          return b.created_at - a.created_at;
        }
        return b.id.localeCompare(a.id);
      });

      const limited = posts.slice(0, rawLimit).map(post => {
        const alias = post.user_id ? this.db.aliases.get(`${post.board_id}:${post.user_id}`) : undefined;
        const user = post.user_id ? this.db.users.get(post.user_id) : undefined;
        const board = this.db.boards.get(post.board_id);
        const replyCount = this.db.replies.filter(reply => reply.post_id === post.id).length;
        return {
          ...post,
          board_alias: alias?.alias ?? null,
          pseudonym: user?.pseudonym ?? null,
          board_name: board?.display_name ?? null,
          reply_count: replyCount
        };
      });

      return { results: limited as T[], success: true as const, meta: { duration: 0, size: 0, rows_read: 0, rows_written: 0, last_row_id: 0, size_after: 0, changed_db: false, changes: 0, served_by: 'mock' } };
    }
    if (this.sql.includes('FROM replies r')) {
      const boardId = this.params[0];
      const postId = this.params[1];
      const cursorCreatedAt = this.params[2];
      const cursorId = this.params[3];
      const limit = this.params[4];
      const replies = this.db.replies
        .filter(reply => reply.board_id === boardId && reply.post_id === postId)
        .filter(reply => reply.created_at > cursorCreatedAt || (reply.created_at === cursorCreatedAt && reply.id > cursorId))
        .sort((a, b) => (a.created_at - b.created_at) || a.id.localeCompare(b.id))
        .slice(0, limit)
        .map(reply => {
          const alias = this.db.aliases.get(`${boardId}:${reply.user_id}`);
          const user = reply.user_id ? this.db.users.get(reply.user_id) : undefined;
          return {
            ...reply,
            board_alias: alias?.alias ?? null,
            pseudonym: user?.pseudonym ?? null
          };
        });
      return { results: replies as T[], success: true as const, meta: { duration: 0, size: 0, rows_read: 0, rows_written: 0, last_row_id: 0, size_after: 0, changed_db: false, changes: 0, served_by: 'mock' } };
    }
    if (this.sql.startsWith('SELECT following_id FROM follows')) {
      const followerId = this.params[0];
      const limit = this.params[1];
      const rows = this.db.follows
        .filter(entry => entry.follower_id === followerId)
        .sort((a, b) => b.created_at - a.created_at)
        .slice(0, limit)
        .map(entry => ({ following_id: entry.following_id }));
      return { results: rows as T[], success: true as const, meta: { duration: 0, size: 0, rows_read: 0, rows_written: 0, last_row_id: 0, size_after: 0, changed_db: false, changes: 0, served_by: 'mock' } };
    }
    return { results: [] as T[], success: true as const, meta: { duration: 0, size: 0, rows_read: 0, rows_written: 0, last_row_id: 0, size_after: 0, changed_db: false, changes: 0, served_by: 'mock' } };
  }

  async first<T>() {
    this.db.prepareCalls.push({ sql: this.sql, params: this.params });
    if (this.sql.startsWith('SELECT COUNT(*) AS post_count')) {
      const [boardId, windowStart] = this.params;
      const postCount = this.db.posts.filter(
        post => post.board_id === boardId && post.created_at >= windowStart
      ).length;
      return { post_count: postCount } as T;
    }
    if (this.sql.startsWith('SELECT MAX(created_at) AS last_post_at')) {
      const [boardId] = this.params;
      const last = this.db.posts
        .filter(post => post.board_id === boardId)
        .map(post => post.created_at)
        .sort((a, b) => b - a)[0];
      return { last_post_at: last ?? null } as T;
    }
    if (this.sql.startsWith('SELECT payload FROM board_events')) {
      const [boardId, eventType] = this.params;
      const events = this.db.events
        .filter(event => event.board_id === boardId && event.event_type === eventType)
        .sort((a, b) => b.created_at - a.created_at);
      const latest = events[0];
      return latest ? ({ payload: latest.payload } as T) : undefined;
    }
    if (this.sql.startsWith('SELECT token, user_id, created_at, expires_at FROM sessions')) {
      const token = this.params[0];
      const session = this.db.sessions.get(token);
      return session ? (session as T) : undefined;
    }
    if (this.sql.includes('FROM board_metrics')) {
      const boardId = this.params[0];
      const record = this.db.boardMetrics.get(boardId);
      return record ? (record as T) : undefined;
    }
    if (this.sql.startsWith('SELECT id, display_name')) {
      const board = this.db.boards.get(this.params[0]);
      return board ? (board as T) : undefined;
    }
    if (this.sql.startsWith('SELECT id, pseudonym')) {
      const user = this.db.users.get(this.params[0]);
      return user ? (user as T) : undefined;
    }
    if (this.sql.includes('FROM board_aliases')) {
      const boardId = this.params[0];
      const userId = this.params[1];
      const record = this.db.aliases.get(`${boardId}:${userId}`);
      return record ? (record as T) : undefined;
    }
    if (this.sql.startsWith('SELECT id, board_id FROM posts')) {
      const post = this.db.posts.find(entry => entry.id === this.params[0]);
      return post ? ({ id: post.id, board_id: post.board_id } as T) : undefined;
    }
    if (this.sql.startsWith('SELECT 1 FROM posts WHERE id')) {
      const [postId, boardId] = this.params;
      const exists = this.db.posts.some(entry => entry.id === postId && entry.board_id === boardId);
      return exists ? (1 as unknown as T) : undefined;
    }
    if (this.sql.includes("SUM(CASE WHEN reaction =")) {
      const postId = this.params[0];
      let likeCount = 0;
      let dislikeCount = 0;
      for (const entry of this.db.reactions.values()) {
        if (entry.post_id === postId) {
          if (entry.reaction === 1) likeCount += 1;
          if (entry.reaction === -1) dislikeCount += 1;
        }
      }
      return { like_count: likeCount, dislike_count: dislikeCount } as T;
    }
    if (this.sql.startsWith('SELECT access_subject, user_id, email FROM user_access_links WHERE access_subject')) {
      const subject = this.params[0];
      const link = this.db.accessLinks.get(subject);
      return link ? (link as T) : undefined;
    }
    if (this.sql.startsWith('SELECT access_subject, user_id, email FROM user_access_links WHERE user_id')) {
      const userId = this.params[0];
      const link = Array.from(this.db.accessLinks.values()).find(entry => entry.user_id === userId);
      return link ? (link as T) : undefined;
    }
    if (this.sql.startsWith('SELECT COUNT(*) AS follower_count FROM follows')) {
      const targetId = this.params[0];
      const count = this.db.follows.filter(entry => entry.following_id === targetId).length;
      return { follower_count: count } as T;
    }
    if (this.sql.startsWith('SELECT COUNT(*) AS following_count FROM follows')) {
      const sourceId = this.params[0];
      const count = this.db.follows.filter(entry => entry.follower_id === sourceId).length;
      return { following_count: count } as T;
    }
    if (this.sql.startsWith('SELECT 1 FROM follows WHERE follower_id')) {
      const followerId = this.params[0];
      const followingId = this.params[1];
      const exists = this.db.follows.some(
        entry => entry.follower_id === followerId && entry.following_id === followingId
      );
      return exists ? (1 as unknown as T) : undefined;
    }
    return undefined;
  }
}

class MockD1 {
  execCalls: ExecCall[] = [];
  prepareCalls: PreparedCall[] = [];
  boards = new Map<string, any>();
  posts: any[] = [];
  replies: any[] = [];
  events: any[] = [];
  users = new Map<string, any>();
  aliases = new Map<string, any>();
  aliasLookup = new Map<string, string>();
  reactions = new Map<string, any>();
  follows: Array<{ follower_id: string; following_id: string; created_at: number }> = [];
  accessLinks = new Map<string, { access_subject: string; user_id: string; email: string | null }>();
  deadZoneAlerts: any[] = [];
  accessIdentityEvents: any[] = [];
  sessions = new Map<string, { token: string; user_id: string; created_at: number; expires_at: number }>();
  boardMetrics = new Map<string, any>();

  async exec(sql: string) {
    this.execCalls.push({ sql });
    return { success: true, count: 0, duration: 0 };
  }

  prepare(sql: string) {
    return new MockPrepared(this, sql);
  }

  async batch<T>(statements: D1PreparedStatement[]): Promise<D1Result<T>[]> {
    return [];
  }

  async dump(): Promise<ArrayBuffer> {
    return new ArrayBuffer(0);
  }

  withSession(constraintOrBookmark?: string): D1DatabaseSession {
    // Return a session object that delegates to this MockD1
    return {
      exec: (sql: string) => this.exec(sql),
      prepare: (sql: string) => this.prepare(sql),
      batch: <T>(statements: D1PreparedStatement[]) => this.batch<T>(statements),
      dump: () => this.dump()
    } as D1DatabaseSession;
  }
}

describe('storage helpers', () => {
  let env: Env & { BOARD_DB: MockD1 };

  beforeEach(() => {
    env = {
      BOARD_DB: new MockD1(),
      BOARD_ROOM_DO: {
        idFromName: (name: string) => ({ name, toString: () => name }),
        get: (id: any) => ({
          fetch: async () => new Response(JSON.stringify({ allowed: true }))
        })
      } as any,
      PHASE_ONE_BOARDS: undefined,
      PHASE_ONE_TEXT_ONLY_BOARDS: undefined,
      PHASE_ONE_RADIUS_METERS: undefined,
      PHASE_ADMIN_TOKEN: undefined,
      ENABLE_IMAGE_UPLOADS: undefined
    };
  });




  it('creates board on first request', async () => {
    const board = await getOrCreateBoard(env, 'demo-board');
    expect(board.display_name).toBe('Demo Board');
    const boardAgain = await getOrCreateBoard(env, 'demo-board');
    expect(boardAgain.id).toBe(board.id);
  });

  it('lists boards catalog with limit and ordering', async () => {
    vi.useFakeTimers();
    try {
      vi.setSystemTime(new Date('2024-05-01T10:00:00Z'));
      await getOrCreateBoard(env, 'alpha-hall');
      vi.advanceTimersByTime(60_000);
      await getOrCreateBoard(env, 'beta-labs');
      vi.advanceTimersByTime(60_000);
      await getOrCreateBoard(env, 'gamma-garden');
    } finally {
      vi.useRealTimers();
    }

    await snapshotBoardMetrics(env, { now: Date.now() });
    expect(env.BOARD_DB.boardMetrics.size).toBeGreaterThan(0);

    const boards = await listBoardsCatalog(env, { limit: 2 });
    expect(boards).toHaveLength(2);
    expect(boards.map(board => board.id)).toEqual(['alpha-hall', 'beta-labs']);
    expect(boards[0].displayName).toBe('Alpha Hall');
    expect(boards[0].activeConnections).toBe(0);
    expect(boards[0].postsLastHour).toBe(0);
    expect(boards[0].postsLastDay).toBe(0);
    expect(boards[0].lastPostAt).toBeNull();
    expect(boards[0].postsTrend24Hr).toBeNull();
    expect(boards[0].radiusLabel).toBe('1,500 m radius');
    expect(boards[0].latitude).toBeNull();
    expect(boards[0].longitude).toBeNull();
  });

  it('serves board catalog via HTTP route', async () => {
    await getOrCreateBoard(env, 'catalog-board');

    await snapshotBoardMetrics(env, { now: Date.now() });

    const request = new Request('https://example.com/boards/catalog?limit=5', {
      headers: { Origin: 'http://localhost:3000' }
    });
    const ctx = {
      waitUntil: vi.fn(),
      passThroughOnException: vi.fn()
    } as unknown as ExecutionContext;

    const response = await WorkerEntrypoint.fetch(request, env, ctx);
    expect(response.status).toBe(200);
    const payload = (await response.json()) as BoardCatalogResponse;
    expect(payload.ok).toBe(true);
    expect(payload.boards.length).toBeGreaterThanOrEqual(1);
    expect(payload.boards[0].id).toBe('catalog-board');
    expect(payload.boards[0].activeConnections).toBe(0);
    expect(payload.boards[0].radiusLabel).toBe('1,500 m radius');
    expect(payload.boards[0].latitude).toBeNull();
    expect(payload.boards[0].longitude).toBeNull();
  });

  it('creates and lists posts', async () => {
    const board = await getOrCreateBoard(env, 'demo-board');
    const user = await createUser(env, 'Alice', 'alice');
    const alias = await upsertBoardAlias(env, board.id, user.id, 'Watcher', 'watcher');
    const post = await createPost(env, board.id, 'Hello world', alias.alias, user.id, alias.alias, user.pseudonym);
    expect(post.body).toBe('Hello world');
    expect(post.alias).toBe('Watcher');
    expect(post.pseudonym).toBe('Alice');
    const posts = await listPosts(env, board.id, 10);
    expect(posts).toHaveLength(1);
    expect(posts[0].alias).toBe('Watcher');
    expect(posts[0].pseudonym).toBe('Alice');
    expect(posts[0].author).toBe('Watcher');
    expect(posts[0].userId).toBe(user.id);
    expect(posts[0].likeCount).toBe(0);
    expect(posts[0].dislikeCount).toBe(0);
    expect(posts[0].hotRank).toBeGreaterThan(0);
  });

  it('registers users and rejects duplicate pseudonyms', async () => {
    const user = await createUser(env, 'Pseudonym', 'pseudonym');
    expect(user.pseudonym).toBe('Pseudonym');

    await expect(createUser(env, 'Pseudonym', 'pseudonym')).rejects.toThrow(/UNIQUE/i);
  });

  it('logs out by deleting session and expiring cookie', async () => {
    const token = 'token123';
    const now = Date.now();
    env.BOARD_DB.sessions.set(token, {
      token,
      user_id: 'user-1',
      created_at: now - 1000,
      expires_at: now + 60_000
    });

    const request = new Request('https://example.com/identity/logout', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`
      }
    });
    const ctx = {
      waitUntil: vi.fn(),
      passThroughOnException: vi.fn()
    } as unknown as ExecutionContext;

    const response = await WorkerEntrypoint.fetch(request, env, ctx);
    expect(response.status).toBe(200);
    expect(env.BOARD_DB.sessions.has(token)).toBe(false);
    expect(response.headers.get('Set-Cookie')).toContain('Max-Age=0');
  });

  it('upserts board aliases and enforces board-level uniqueness', async () => {
    const board = await getOrCreateBoard(env, 'demo-board');
    const user = await createUser(env, 'AliasUser', 'aliasuser');

    const alias = await upsertBoardAlias(env, board.id, user.id, 'Watcher', 'watcher');
    expect(alias.alias).toBe('Watcher');

    const updated = await upsertBoardAlias(env, board.id, user.id, 'Sentinel', 'sentinel');
    expect(updated.alias).toBe('Sentinel');
    const fetched = await getBoardAlias(env, board.id, user.id);
    expect(fetched?.aliasNormalized).toBe('sentinel');

    const other = await createUser(env, 'Other', 'other');
    await expect(upsertBoardAlias(env, board.id, other.id, 'Sentinel', 'sentinel')).rejects.toThrow(/UNIQUE/i);
  });

  it('applies reactions and updates aggregate counts', async () => {
    const board = await getOrCreateBoard(env, 'demo-board');
    const post = await createPost(env, board.id, 'Hello world', 'Alice', null);
    const user = await createUser(env, 'Reactor', 'reactor');

    const like = await applyReaction(env, board.id, post.id, user.id, 'like');
    expect(like.likeCount).toBe(1);
    expect(like.total).toBe(1);

    const dislike = await applyReaction(env, board.id, post.id, user.id, 'dislike');
    expect(dislike.likeCount).toBe(0);
    expect(dislike.dislikeCount).toBe(1);

    const cleared = await applyReaction(env, board.id, post.id, user.id, 'remove');
    expect(cleared.total).toBe(0);
  });

  it('lists user posts with reply counts and board metadata', async () => {
    const board = await getOrCreateBoard(env, 'story-board');
    const author = await createUser(env, 'Storyteller', 'storyteller');
    const alias = await upsertBoardAlias(env, board.id, author.id, 'Narrator', 'narrator');

    const post = await createPost(
      env,
      board.id,
      'Meetup tonight #events',
      alias.alias,
      author.id,
      alias.alias,
      author.pseudonym,
      undefined,
      board.display_name
    );

    const authorRecord = env.BOARD_DB.users.get(author.id);
    expect(authorRecord).toBeDefined();
    await createReply(
      env,
      post.id,
      board.id,
      'Count me in!',
      alias.alias,
      author.id,
      alias.alias,
      author.pseudonym
    );

    const posts = await listUserPosts(env, author.id, 5);
    expect(posts).toHaveLength(1);
    expect(posts[0].boardName).toBe(board.display_name);
    expect(posts[0].replyCount).toBe(1);
    expect(posts[0].alias).toBe('Narrator');
  });

  it('provides following feed with pagination and follow counts', async () => {
    const board = await getOrCreateBoard(env, 'follow-board');
    const alice = await createUser(env, 'Alice', 'alice');
    const bob = await createUser(env, 'Bob', 'bob');
    const carol = await createUser(env, 'Carol', 'carol');

    await upsertBoardAlias(env, board.id, bob.id, 'ChefBob', 'chefbob');
    await upsertBoardAlias(env, board.id, carol.id, 'CoachCarol', 'coachcarol');

    vi.useFakeTimers();
    try {
      vi.setSystemTime(new Date('2024-03-01T10:00:00Z'));
      await createPost(env, board.id, 'Lunch specials', 'ChefBob', bob.id, 'ChefBob', 'Bob', undefined, board.display_name);
      vi.advanceTimersByTime(1000);
      await createPost(env, board.id, 'Morning workout', 'CoachCarol', carol.id, 'CoachCarol', 'Carol', undefined, board.display_name);
      vi.advanceTimersByTime(1000);
      await createPost(env, board.id, 'Dinner ideas', 'ChefBob', bob.id, 'ChefBob', 'Bob', undefined, board.display_name);
    } finally {
      vi.useRealTimers();
    }

    await setFollowState(env, alice.id, bob.id, true);
    expect(await isFollowing(env, alice.id, bob.id)).toBe(true);
    expect(await isFollowing(env, alice.id, carol.id)).toBe(false);

    const counts = await getFollowCounts(env, bob.id);
    expect(counts.followerCount).toBe(1);

    const ids = await listFollowingIds(env, alice.id, 10);
    expect(ids).toEqual([bob.id]);

    const page1 = await listFollowingPosts(env, alice.id, { limit: 1 });
    expect(page1.posts).toHaveLength(1);
    expect(page1.hasMore).toBe(true);
    expect(page1.posts[0].userId).toBe(bob.id);
    expect(page1.posts[0].boardName).toBe(board.display_name);

    const page2 = await listFollowingPosts(env, alice.id, { limit: 1, cursor: page1.cursor });
    expect(page2.posts).toHaveLength(1);
    expect(page2.hasMore).toBe(false);

    await setFollowState(env, alice.id, bob.id, false);
    expect(await isFollowing(env, alice.id, bob.id)).toBe(false);
    const clearedIds = await listFollowingIds(env, alice.id, 10);
    expect(clearedIds).toEqual([]);
  });

  it('searches board posts by query and recency', async () => {
    const board = await getOrCreateBoard(env, 'search-board');
    const author = await createUser(env, 'Searcher', 'searcher');
    await upsertBoardAlias(env, board.id, author.id, 'Scout', 'scout');

    vi.useFakeTimers();
    vi.setSystemTime(new Date('2024-04-01T09:00:00Z'));
    await createPost(
      env,
      board.id,
      'Morning bulletin #coffee',
      'Scout',
      author.id,
      'Scout',
      author.pseudonym,
      undefined,
      board.display_name
    );
    vi.advanceTimersByTime(5 * 60 * 1000);
    await createPost(
      env,
      board.id,
      'Campus update without tag',
      'Scout',
      author.id,
      'Scout',
      author.pseudonym,
      undefined,
      board.display_name
    );
    const results = await searchBoardPosts(env, {
      boardId: board.id,
      query: '#coffee',
      limit: 5,
      windowMs: 24 * 60 * 60 * 1000
    });

    expect(results.posts).toHaveLength(1);
    expect(results.posts[0].body).toContain('#coffee');
    expect(results.hasMore).toBe(false);
    vi.useRealTimers();
  });

  it('auto provisions access users and allows explicit relinking', async () => {
    const principal = { subject: 'https://access.example.com/user/12345', email: 'jane@example.com' };
    const autoUser = await __internal.resolveAccessUser(env, principal);
    expect(autoUser.pseudonym.length).toBeGreaterThan(0);
    const autoLink = env.BOARD_DB.accessLinks.get(principal.subject);
    expect(autoLink?.user_id).toBe(autoUser.id);
    expect(env.BOARD_DB.users.get(autoUser.id)?.status).toBe('access_auto');

    const legacyUser = await createUser(env, 'LegacyUser', 'legacyuser');
    await expect(__internal.ensureAccessPrincipalForUser(env, principal, legacyUser.id)).rejects.toThrow(
      'access identity mismatch'
    );

    await __internal.ensureAccessPrincipalForUser(env, principal, legacyUser.id, { allowReassign: true });
    const updatedLink = env.BOARD_DB.accessLinks.get(principal.subject);
    expect(updatedLink?.user_id).toBe(legacyUser.id);
    expect(env.BOARD_DB.users.get(legacyUser.id)?.status).toBe('active');
    expect(env.BOARD_DB.users.get(autoUser.id)?.status).toBe('access_orphan');

    const accessEvents = env.BOARD_DB.accessIdentityEvents;
    expect(accessEvents).toHaveLength(3);
    expect(accessEvents.map(event => event.event_type)).toEqual([
      'access.identity_auto_provisioned',
      'access.identity_orphaned',
      'access.identity_relinked'
    ]);
    const autoProvisioned = accessEvents.find(event => event.event_type === 'access.identity_auto_provisioned');
    expect(autoProvisioned?.subject).toBe(principal.subject);
    expect(autoProvisioned?.user_id).toBe(autoUser.id);
    const metadata = autoProvisioned?.metadata ? JSON.parse(autoProvisioned.metadata as string) : {};
    expect(metadata.pseudonym).toBe('Jane');
  });

  it('detects board dead zones and tracks streaks', async () => {
    vi.useFakeTimers();
    try {
      const detectionTime = new Date('2024-01-01T12:00:00Z');
      const staleTime = new Date(detectionTime.getTime() - 6 * 60 * 60 * 1000);
      const recentTime = new Date(detectionTime.getTime() - 30 * 60 * 1000);

      vi.setSystemTime(detectionTime);
      const healthyBoard = await getOrCreateBoard(env, 'active-board');
      const quietBoard = await getOrCreateBoard(env, 'quiet-board');

      vi.setSystemTime(staleTime);
      await createPost(env, quietBoard.id, 'Old news', 'system', null);

      vi.setSystemTime(recentTime);
      await createPost(env, healthyBoard.id, 'Update 1', 'system', null);
      vi.advanceTimersByTime(1000);
      await createPost(env, healthyBoard.id, 'Update 2', 'system', null);
      vi.advanceTimersByTime(1000);
      await createPost(env, healthyBoard.id, 'Update 3', 'system', null);

      const report1 = await detectDeadZones(env, {
        now: detectionTime.getTime(),
        windowMs: 2 * 60 * 60 * 1000,
        streakThreshold: 2
      });

      expect(report1.snapshots).toHaveLength(2);
      const quietSnapshot1 = report1.snapshots.find(snapshot => snapshot.boardId === quietBoard.id);
      expect(quietSnapshot1?.status).toBe('dead_zone');
      expect(quietSnapshot1?.deadZoneStreak).toBe(1);
      expect(quietSnapshot1?.alertTriggered).toBe(false);
      expect(report1.alerts).toHaveLength(0);

      const laterTime = new Date(detectionTime.getTime() + 30 * 60 * 1000);
      const report2 = await detectDeadZones(env, {
        now: laterTime.getTime(),
        windowMs: 2 * 60 * 60 * 1000,
        streakThreshold: 2
      });

      const quietSnapshot2 = report2.snapshots.find(snapshot => snapshot.boardId === quietBoard.id);
      expect(quietSnapshot2?.status).toBe('dead_zone');
      expect(quietSnapshot2?.deadZoneStreak).toBe(2);
      expect(quietSnapshot2?.alertTriggered).toBe(true);
      expect(report2.alerts).toHaveLength(1);
      expect(report2.alerts[0].boardId).toBe(quietBoard.id);

      const healthySnapshot = report2.snapshots.find(snapshot => snapshot.boardId === healthyBoard.id);
      expect(healthySnapshot?.status).toBe('healthy');
      expect(healthySnapshot?.deadZoneStreak).toBe(0);

      const freshnessEvents = env.BOARD_DB.events.filter(event => event.event_type === 'board.freshness');
      expect(freshnessEvents).toHaveLength(4);
      const alertEvents = env.BOARD_DB.events.filter(event => event.event_type === 'board.dead_zone_triggered');
      expect(alertEvents).toHaveLength(1);
      expect(alertEvents[0].board_id).toBe(quietBoard.id);

      expect(env.BOARD_DB.deadZoneAlerts).toHaveLength(1);
      expect(env.BOARD_DB.deadZoneAlerts[0].board_id).toBe(quietBoard.id);
      expect(env.BOARD_DB.deadZoneAlerts[0].streak).toBe(2);
    } finally {
      vi.useRealTimers();
    }
  });

  it('runs the dead-zone detector during scheduled events', async () => {
    const module = await import('../index');
    const worker = module.default;
    const scheduledEvent = {
      scheduledTime: Date.now(),
      cron: '*/15 * * * *',
      noRetry() {
        /* noop */
      }
    } as ScheduledController;
    const ctx = {
      waitUntil: (_promise: Promise<unknown>) => { }
    } as ExecutionContext;

    await worker.scheduled(scheduledEvent, env);

    const selectBoardsCall = env.BOARD_DB.prepareCalls.find(call => call.sql.includes('SELECT id FROM boards'));
    expect(selectBoardsCall).toBeDefined();
  });

  it('ranks posts with velocity-aware hot scores', async () => {
    vi.useFakeTimers();
    try {
      const baseTime = new Date('2024-02-01T08:00:00Z').getTime();
      vi.setSystemTime(baseTime);
      const board = await getOrCreateBoard(env, 'ranking-board');
      const author = await createUser(env, 'Poster', 'poster');
      const reactorOne = await createUser(env, 'ReactorOne', 'reactorone');
      const reactorTwo = await createUser(env, 'ReactorTwo', 'reactortwo');
      const reactorThree = await createUser(env, 'ReactorThree', 'reactorthree');

      const earlyPost = await createPost(env, board.id, 'Earlier insights', null, author.id, null, author.pseudonym);

      vi.setSystemTime(baseTime + 10 * 60 * 1000);
      await applyReaction(env, board.id, earlyPost.id, reactorOne.id, 'like');
      await applyReaction(env, board.id, earlyPost.id, reactorTwo.id, 'like');
      await applyReaction(env, board.id, earlyPost.id, reactorThree.id, 'like');

      vi.setSystemTime(baseTime + 3 * 60 * 60 * 1000);
      const freshPost = await createPost(env, board.id, 'Breaking update', null, author.id, null, author.pseudonym);

      vi.setSystemTime(baseTime + 3 * 60 * 60 * 1000 + 30 * 1000);
      await applyReaction(env, board.id, freshPost.id, reactorOne.id, 'like');
      await applyReaction(env, board.id, freshPost.id, reactorTwo.id, 'like');

      const evaluationTime = baseTime + 3 * 60 * 60 * 1000 + 5 * 60 * 1000;
      const posts = await listPosts(env, board.id, 10, { now: evaluationTime });

      expect(posts).toHaveLength(2);
      expect(posts[0].id).toBe(freshPost.id);
      expect((posts[0].hotRank ?? 0) > (posts[1].hotRank ?? 0)).toBe(true);
      expect(posts[1].id).toBe(earlyPost.id);
    } finally {
      vi.useRealTimers();
    }
  });

  it('adapts board radius based on recent activity', async () => {
    const board = await getOrCreateBoard(env, 'adaptive-board');
    const entry = env.BOARD_DB.boards.get(board.id);
    if (entry) {
      entry.radius_meters = 800;
      entry.radius_state = JSON.stringify({ currentMeters: 800, lastExpandedAt: null, lastContractedAt: null });
      entry.radius_updated_at = 0;
    }

    const request = new Request('https://unit.test/boards/adaptive-board/feed');
    const ctx = {
      waitUntil: (_promise: Promise<unknown>) => { }
    } as ExecutionContext;
    const response = await WorkerEntrypoint.fetch(request, env, ctx);
    expect(response.status).toBe(200);
    const body = (await response.json()) as BoardFeedResponse;
    expect(body.board.radiusMeters).toBeGreaterThan(800);
    const updated = env.BOARD_DB.boards.get(board.id);
    expect(updated?.radius_meters).toBe(body.board.radiusMeters);
  });

  it('locks radius and text-only settings for phase one boards', async () => {
    env.PHASE_ONE_BOARDS = 'phase-one-board';
    env.PHASE_ONE_TEXT_ONLY_BOARDS = 'phase-one-board';
    env.PHASE_ONE_RADIUS_METERS = '900';

    const board = await getOrCreateBoard(env, 'phase-one-board');
    const entry = env.BOARD_DB.boards.get(board.id);
    if (entry) {
      entry.radius_meters = 500;
      entry.radius_state = JSON.stringify({ currentMeters: 500, lastExpandedAt: null, lastContractedAt: null });
      entry.radius_updated_at = 0;
    }

    const request = new Request('https://unit.test/boards/phase-one-board/feed');
    const ctx = {
      waitUntil: (_promise: Promise<unknown>) => { }
    } as ExecutionContext;
    const response = await WorkerEntrypoint.fetch(request, env, ctx);
    expect(response.status).toBe(200);
    const body = (await response.json()) as BoardFeedResponse;
    expect(body.board.phaseMode).toBe('phase1');
    expect(body.board.textOnly).toBe(true);
    expect(body.board.radiusMeters).toBe(900);
    const updated = env.BOARD_DB.boards.get(board.id);
    expect(updated?.radius_meters).toBe(900);
  });


  it('rejects image uploads when not enabled', async () => {
    const request = new Request('https://unit.test/boards/image-guard/posts', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        body: 'Image attempt',
        images: [{ name: 'test.jpg', type: 'image/jpeg', size: 1024 }]
      })
    });
    const ctx = {
      waitUntil: (_: Promise<unknown>) => { }
    } as ExecutionContext;
    const response = await WorkerEntrypoint.fetch(request, env, ctx);
    expect(response.status).toBe(403);
    const payload = await response.json() as { error?: string };
    expect(payload.error).toMatch(/image uploads are currently disabled/i);
  });

  it('rejects image uploads for text-only boards', async () => {
    env.PHASE_ONE_TEXT_ONLY_BOARDS = 'text-only-board';
    env.ENABLE_IMAGE_UPLOADS = 'true';

    const request = new Request('https://unit.test/boards/text-only-board/posts', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        body: 'Hello',
        images: [{ name: 'test.jpg', type: 'image/jpeg', size: 2048 }]
      })
    });
    const ctx = {
      waitUntil: (_: Promise<unknown>) => { }
    } as ExecutionContext;
    const response = await WorkerEntrypoint.fetch(request, env, ctx);
    expect(response.status).toBe(403);
    const payload = await response.json() as { error?: string };
    expect(payload.error).toMatch(/disabled for this board/i);
  });

  it('accepts valid image metadata when enabled', async () => {
    env.ENABLE_IMAGE_UPLOADS = 'true';

    const request = new Request('https://unit.test/boards/media/posts', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        body: 'Post with image',
        images: [{ id: 'hero', name: 'hero.jpg', type: 'image/jpeg', size: 409_600 }]
      })
    });
    const ctx = {
      waitUntil: (_: Promise<unknown>) => { }
    } as ExecutionContext;
    const response = await WorkerEntrypoint.fetch(request, env, ctx);
    expect(response.status).toBe(201);
    const payload = await response.json() as { post: { images?: string[] } };
    expect(payload.post.images).toEqual(['hero']);
  });

});
