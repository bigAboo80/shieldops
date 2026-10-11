-- Every scan keeps its own snapshot of the graph, so scans can be compared.
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL DEFAULT 'running', -- running | done | failed
    -- detectors whose results are complete, e.g. exposed-cve is not when trivy was skipped
    complete_detectors TEXT NOT NULL DEFAULT '[]' -- JSON array
);

CREATE TABLE IF NOT EXISTS assets (
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    uid TEXT NOT NULL,
    kind TEXT NOT NULL,
    name TEXT NOT NULL,
    namespace TEXT NOT NULL DEFAULT '',
    workload TEXT NOT NULL DEFAULT '',
    labels TEXT NOT NULL DEFAULT '{}', -- JSON object
    images TEXT NOT NULL DEFAULT '[]', -- JSON array
    PRIMARY KEY (scan_id, uid)
);

CREATE TABLE IF NOT EXISTS edges (
    scan_id INTEGER NOT NULL,
    source_uid TEXT NOT NULL,
    target_uid TEXT NOT NULL,
    edge_type TEXT NOT NULL,
    properties TEXT NOT NULL DEFAULT '{}', -- JSON object with sorted keys
    PRIMARY KEY (scan_id, source_uid, target_uid, edge_type, properties),
    FOREIGN KEY (scan_id, source_uid) REFERENCES assets(scan_id, uid) ON DELETE CASCADE,
    FOREIGN KEY (scan_id, target_uid) REFERENCES assets(scan_id, uid) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_edges_type ON edges(scan_id, edge_type);
CREATE INDEX IF NOT EXISTS idx_edges_target ON edges(scan_id, target_uid);

CREATE TABLE IF NOT EXISTS findings (
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL,
    detector TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    PRIMARY KEY (scan_id, fingerprint)
);
