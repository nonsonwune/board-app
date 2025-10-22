-- Identity and reaction support
ALTER TABLE posts ADD COLUMN like_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE posts ADD COLUMN dislike_count INTEGER NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  pseudonym TEXT NOT NULL UNIQUE,
  pseudonym_normalized TEXT NOT NULL UNIQUE,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS board_aliases (
  id TEXT PRIMARY KEY,
  board_id TEXT NOT NULL,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  alias TEXT NOT NULL,
  alias_normalized TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  UNIQUE(board_id, alias_normalized),
  UNIQUE(board_id, user_id)
);

CREATE TABLE IF NOT EXISTS reactions (
  id TEXT PRIMARY KEY,
  post_id TEXT NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
  board_id TEXT NOT NULL,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  reaction INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  UNIQUE(post_id, user_id)
);
