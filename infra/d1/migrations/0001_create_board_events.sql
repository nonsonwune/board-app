-- board_events history for realtime broadcast replay
CREATE TABLE IF NOT EXISTS board_events (
  id TEXT PRIMARY KEY,
  board_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  payload TEXT NOT NULL,
  trace_id TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS board_events_board_created_at_idx
  ON board_events (board_id, created_at DESC);
