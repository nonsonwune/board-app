import { describe, expect, it, beforeEach } from 'vitest';
import {
  __resetSchemaForTests,
  ensureSchema,
  getOrCreateBoard,
  createPost,
  listPosts
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
      const [id, boardId, author, body, createdAt] = this.params;
      this.db.posts.push({
        id,
        board_id: boardId,
        author,
        body,
        created_at: createdAt,
        reaction_count: 0
      });
    }
    if (this.sql.startsWith('INSERT INTO board_events')) {
      this.db.events.push({ params: this.params });
    }
    return { success: true };
  }

  async all<T>() {
    this.db.prepareCalls.push({ sql: this.sql, params: this.params });
    if (this.sql.startsWith('SELECT id, display_name')) {
      const board = this.db.boards.get(this.params[0]);
      return { results: board ? [board as T] : [] };
    }
    if (this.sql.startsWith('SELECT id, board_id, author')) {
      const boardId = this.params[0];
      const limit = this.params[1];
      const posts = this.db.posts
        .filter(post => post.board_id === boardId)
        .sort((a, b) => b.created_at - a.created_at)
        .slice(0, limit);
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
    return undefined;
  }
}

class MockD1 {
  execCalls: ExecCall[] = [];
  prepareCalls: PreparedCall[] = [];
  boards = new Map<string, any>();
  posts: any[] = [];
  events: any[] = [];

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
    expect(env.BOARD_DB.execCalls.map(call => call.sql)).toHaveLength(5);
  });

  it('creates board on first request', async () => {
    const board = await getOrCreateBoard(env, 'demo-board');
    expect(board.display_name).toBe('Demo Board');
    const boardAgain = await getOrCreateBoard(env, 'demo-board');
    expect(boardAgain.id).toBe(board.id);
    expect(env.BOARD_DB.execCalls).toHaveLength(5); // schema called once
  });

  it('creates and lists posts', async () => {
    await getOrCreateBoard(env, 'demo-board');
    const post = await createPost(env, 'demo-board', 'Hello world', 'Alice');
    expect(post.body).toBe('Hello world');
    const posts = await listPosts(env, 'demo-board', 10);
    expect(posts).toHaveLength(1);
    expect(posts[0].author).toBe('Alice');
  });
});
