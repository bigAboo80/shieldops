CREATE TABLE IF NOT EXISTS assets (
    id SERIAL PRIMARY KEY,
    kind TEXT NOT NULL,
    name TEXT NOT NULL,
    namespace TEXT,
    labels JSONB,
    images TEXT[] NOT NULL DEFAULT '{}',
    uid TEXT UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

ALTER TABLE assets ADD COLUMN IF NOT EXISTS images TEXT[] NOT NULL DEFAULT '{}';

CREATE TABLE IF NOT EXISTS edges (
    id SERIAL PRIMARY KEY,
    source_uid TEXT REFERENCES assets(uid) ON DELETE CASCADE,
    target_uid TEXT REFERENCES assets(uid) ON DELETE CASCADE,
    edge_type TEXT NOT NULL,
    properties JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMP DEFAULT NOW(),
    UNIQUE (source_uid, target_uid, edge_type, properties)
);

CREATE INDEX IF NOT EXISTS idx_edges_source_uid ON edges(source_uid);
CREATE INDEX IF NOT EXISTS idx_edges_target_uid ON edges(target_uid);
CREATE INDEX IF NOT EXISTS idx_edges_edge_type ON edges(edge_type);
