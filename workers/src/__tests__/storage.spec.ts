import { describe, expect, it, beforeEach } from 'vitest';
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
      this.db.events.push({ params: this.params });
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
    expect(schemaCalls).toHaveLength(11);
    expect(schemaCalls[0].sql).toContain('CREATE TABLE IF NOT EXISTS boards');
  });

  it('creates board on first request', async () => {
    const board = await getOrCreateBoard(env, 'demo-board');
    expect(board.display_name).toBe('Demo Board');
    const boardAgain = await getOrCreateBoard(env, 'demo-board');
    expect(boardAgain.id).toBe(board.id);
    const schemaCalls = env.BOARD_DB.prepareCalls.filter(call =>
      call.sql.startsWith('CREATE TABLE') || call.sql.startsWith('CREATE INDEX')
    );
    expect(schemaCalls).toHaveLength(11); // schema called once
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
  });
});
