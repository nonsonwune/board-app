import { describe, expect, it, beforeEach, vi } from 'vitest';
import {
  __resetSchemaForTests,
  ensureSchema,
  getOrCreateBoard,
  createPost,
  listPosts,
  createUser,
  upsertBoardAlias,
  applyReaction,
  getBoardAlias,
  detectDeadZones,
  __internal
} from '../index';
import type { Env } from '../index';

type ExecCall = { sql: string };

type PreparedCall = {
  sql: string;
  params: any[];
};

class MockPrepared {
  constructor(private readonly db: MockD1, public readonly sql: string) {}

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
}

class BoundPrepared {
  constructor(private readonly db: MockD1, public readonly sql: string, private readonly params: any[]) {}

  async run() {
    this.db.prepareCalls.push({ sql: this.sql, params: this.params });
    if (this.sql.startsWith('INSERT INTO boards')) {
      const [id, name, description, createdAt] = this.params;
      this.db.boards.set(id, {
        id,
        display_name: name,
        description,
        created_at: createdAt
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
    return { success: true };
  }

  async all<T>() {
    this.db.prepareCalls.push({ sql: this.sql, params: this.params });
    if (this.sql.startsWith('SELECT id FROM boards')) {
      const results = Array.from(this.db.boards.values()).map(board => ({ id: board.id }));
      return { results: results as T[] };
    }
    if (this.sql.startsWith('SELECT id, display_name')) {
      const board = this.db.boards.get(this.params[0]);
      return { results: board ? [board as T] : [] };
    }
    if (this.sql.includes('FROM posts p')) {
      const boardId = this.params[0];
      const limit = this.params[1];
      const posts = this.db.posts
        .filter(post => post.board_id === boardId)
        .sort((a, b) => b.created_at - a.created_at)
        .slice(0, limit)
        .map(post => {
          const alias = this.db.aliases.get(`${boardId}:${post.user_id}`);
          const user = post.user_id ? this.db.users.get(post.user_id) : undefined;
          return {
            ...post,
            board_alias: alias?.alias ?? null,
            pseudonym: user?.pseudonym ?? null
          };
        });
      return { results: posts as T[] };
    }
    return { results: [] as T[] };
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
    return undefined;
  }
}

class MockD1 {
  execCalls: ExecCall[] = [];
  prepareCalls: PreparedCall[] = [];
  boards = new Map<string, any>();
  posts: any[] = [];
  events: any[] = [];
  users = new Map<string, any>();
  aliases = new Map<string, any>();
  aliasLookup = new Map<string, string>();
  reactions = new Map<string, any>();
  accessLinks = new Map<string, { access_subject: string; user_id: string; email: string | null }>();
  deadZoneAlerts: any[] = [];
  accessIdentityEvents: any[] = [];

  async exec(sql: string) {
    this.execCalls.push({ sql });
    return { success: true };
  }

  prepare(sql: string) {
    return new MockPrepared(this, sql);
  }
}

describe('storage helpers', () => {
  let env: Env & { BOARD_DB: MockD1 };

  beforeEach(() => {
    env = {
      BOARD_DB: new MockD1(),
      BOARD_ROOM_DO: {} as any
    };
    __resetSchemaForTests();
  });

  it('initializes schema once', async () => {
    await ensureSchema(env);
    await ensureSchema(env);
    const schemaCalls = env.BOARD_DB.prepareCalls.filter(call =>
      call.sql.startsWith('CREATE TABLE') || call.sql.startsWith('CREATE INDEX')
    );
    expect(schemaCalls.length).toBeGreaterThanOrEqual(13);
    expect(schemaCalls[0].sql).toContain('CREATE TABLE IF NOT EXISTS boards');
    expect(schemaCalls.some(call => call.sql.includes('dead_zone_alerts'))).toBe(true);
  });

  it('creates board on first request', async () => {
    const board = await getOrCreateBoard(env, 'demo-board');
    expect(board.display_name).toBe('Demo Board');
    const boardAgain = await getOrCreateBoard(env, 'demo-board');
    expect(boardAgain.id).toBe(board.id);
    const schemaCalls = env.BOARD_DB.prepareCalls.filter(call =>
      call.sql.startsWith('CREATE TABLE') || call.sql.startsWith('CREATE INDEX')
    );
    expect(schemaCalls.length).toBeGreaterThanOrEqual(13); // schema called once, includes dead-zone artifacts
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

      expect(report1.results).toHaveLength(2);
      const quietSnapshot1 = report1.results.find(snapshot => snapshot.boardId === quietBoard.id);
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

      const quietSnapshot2 = report2.results.find(snapshot => snapshot.boardId === quietBoard.id);
      expect(quietSnapshot2?.status).toBe('dead_zone');
      expect(quietSnapshot2?.deadZoneStreak).toBe(2);
      expect(quietSnapshot2?.alertTriggered).toBe(true);
      expect(report2.alerts).toHaveLength(1);
      expect(report2.alerts[0].boardId).toBe(quietBoard.id);

      const healthySnapshot = report2.results.find(snapshot => snapshot.boardId === healthyBoard.id);
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
      waitUntil: (_promise: Promise<unknown>) => {}
    } as ExecutionContext;

    await worker.scheduled!(scheduledEvent, env, ctx);

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
});
