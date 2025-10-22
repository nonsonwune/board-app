-- Boards metadata
CREATE TABLE IF NOT EXISTS boards (
  id TEXT PRIMARY KEY,
  display_name TEXT NOT NULL,
  description TEXT,
  created_at INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
);

-- Posts per board
CREATE TABLE IF NOT EXISTS posts (
  id TEXT PRIMARY KEY,
  board_id TEXT NOT NULL REFERENCES boards(id) ON DELETE CASCADE,
  author TEXT,
  body TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  reaction_count INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS posts_board_created_at_idx
  ON posts (board_id, created_at DESC);
