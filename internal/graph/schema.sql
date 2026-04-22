CREATE TABLE assets (
    id SERIAL PRIMARY KEY,
    kind TEXT NOT NULL,
    name TEXT NOT NULL,
    namespace TEXT,
    labels JSONB,
    uid TEXT UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE edges (
    id SERIAL PRIMARY KEY,
    source_uid TEXT REFERENCES assets(uid),
    target_uid TEXT REFERENCES assets(uid),
    edge_type TEXT NOT NULL,
    properties JSONB,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_edges_source_uid ON edges(source_uid);
CREATE INDEX idx_edges_target_uid ON edges(target_uid);
CREATE INDEX idx_edges_edge_type ON edges(edge_type);
