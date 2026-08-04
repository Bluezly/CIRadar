-- CI Radar 1.0 compatibility state store.
-- The row is locked transactionally so multiple API/worker processes do not
-- overwrite one another. A future normalized schema can implement db.Backend
-- without changing analyzers, connectors, notifications, or MCP.
CREATE TABLE IF NOT EXISTS ciradar_state (
  id text PRIMARY KEY,
  version bigint NOT NULL DEFAULT 1,
  payload jsonb NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ciradar_state_updated_at_idx ON ciradar_state(updated_at);
