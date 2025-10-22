CREATE TABLE IF NOT EXISTS boards (
  id TEXT PRIMARY KEY,
  display_name TEXT NOT NULL,
  description TEXT,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS posts (
  id TEXT PRIMARY KEY,
  board_id TEXT NOT NULL REFERENCES boards(id) ON DELETE CASCADE,
  author TEXT,
  body TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  reaction_count INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS posts_board_created_at_idx ON posts (board_id, created_at DESC);
CREATE TABLE IF NOT EXISTS board_events (
  id TEXT PRIMARY KEY,
  board_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  payload TEXT NOT NULL,
  trace_id TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS board_events_board_created_at_idx ON board_events (board_id, created_at DESC);
