CREATE INDEX sessions_creation_order
    ON sessions(created_at_ms, id);
CREATE INDEX devices_creation_order
    ON devices(created_at_ms, id);
