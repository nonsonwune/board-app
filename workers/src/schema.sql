CREATE TABLE IF NOT EXISTS boards (
  id TEXT PRIMARY KEY,
  display_name TEXT NOT NULL,
  description TEXT,
  created_at INTEGER NOT NULL,
  radius_meters INTEGER NOT NULL DEFAULT 1500,
  radius_state TEXT,
  radius_updated_at INTEGER,
  phase_mode TEXT NOT NULL DEFAULT 'default',
  text_only INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS posts (
  id TEXT PRIMARY KEY,
  board_id TEXT NOT NULL REFERENCES boards(id) ON DELETE CASCADE,
  user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
  author TEXT,
  body TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  reaction_count INTEGER NOT NULL DEFAULT 0,
  like_count INTEGER NOT NULL DEFAULT 0,
  dislike_count INTEGER NOT NULL DEFAULT 0
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
CREATE TABLE IF NOT EXISTS dead_zone_alerts (
  id TEXT PRIMARY KEY,
  board_id TEXT NOT NULL REFERENCES boards(id) ON DELETE CASCADE,
  streak INTEGER NOT NULL,
  post_count INTEGER NOT NULL,
  threshold INTEGER NOT NULL,
  window_start INTEGER NOT NULL,
  window_end INTEGER NOT NULL,
  window_ms INTEGER NOT NULL,
  triggered_at INTEGER NOT NULL,
  alert_level TEXT NOT NULL DEFAULT 'dead_zone',
  trace_id TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS dead_zone_alerts_board_triggered_at_idx ON dead_zone_alerts (board_id, triggered_at DESC);
CREATE TABLE IF NOT EXISTS access_identity_events (
  id TEXT PRIMARY KEY,
  event_type TEXT NOT NULL,
  subject TEXT NOT NULL,
  user_id TEXT,
  email TEXT,
  trace_id TEXT,
  metadata TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS access_identity_events_event_created_idx ON access_identity_events (event_type, created_at DESC);
CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_user_expires_idx ON sessions (user_id, expires_at DESC);
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  pseudonym TEXT NOT NULL UNIQUE,
  pseudonym_normalized TEXT NOT NULL UNIQUE,
  created_at INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'active'
);
CREATE TABLE IF NOT EXISTS user_access_links (
  access_subject TEXT PRIMARY KEY,
  user_id TEXT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
  email TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
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

CREATE TABLE IF NOT EXISTS replies (
  id TEXT PRIMARY KEY,
  post_id TEXT NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
  board_id TEXT NOT NULL,
  user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
  author TEXT,
  body TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS replies_post_created_at_idx ON replies (post_id, created_at ASC);
CREATE TABLE IF NOT EXISTS reactions (
  id TEXT PRIMARY KEY,
  post_id TEXT NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
  board_id TEXT NOT NULL,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  reaction INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  UNIQUE(post_id, user_id)
);

CREATE TABLE IF NOT EXISTS follows (
  follower_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  following_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (follower_id, following_id)
);

CREATE INDEX IF NOT EXISTS follows_following_idx ON follows (following_id);
