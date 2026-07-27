CREATE TABLE sessions (
    id TEXT PRIMARY KEY NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'archived')),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= created_at_ms),
    version INTEGER NOT NULL DEFAULT 1 CHECK (version >= 1)
) STRICT;

CREATE TABLE devices (
    id TEXT PRIMARY KEY NOT NULL,
    display_name TEXT NOT NULL CHECK (length(trim(display_name)) > 0),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= created_at_ms),
    version INTEGER NOT NULL DEFAULT 1 CHECK (version >= 1)
) STRICT;

CREATE TABLE authentication_records (
    id TEXT PRIMARY KEY NOT NULL,
    device_id TEXT NOT NULL,
    provider TEXT NOT NULL CHECK (length(trim(provider)) > 0),
    subject TEXT,
    status TEXT NOT NULL CHECK (status IN ('pending', 'authorized', 'revoked')),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= created_at_ms),
    version INTEGER NOT NULL DEFAULT 1 CHECK (version >= 1),
    FOREIGN KEY (device_id) REFERENCES devices(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CHECK (
        (status = 'authorized' AND subject IS NOT NULL AND length(trim(subject)) > 0)
        OR (status <> 'authorized' AND subject IS NULL)
    )
) STRICT;

CREATE TABLE tasks (
    id TEXT PRIMARY KEY NOT NULL,
    session_id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (length(trim(kind)) > 0),
    payload TEXT NOT NULL,
    status TEXT NOT NULL CHECK (
        status IN ('pending', 'running', 'succeeded', 'failed', 'cancelled')
    ),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= created_at_ms),
    version INTEGER NOT NULL DEFAULT 1 CHECK (version >= 1),
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON UPDATE RESTRICT ON DELETE RESTRICT
) STRICT;

CREATE TABLE claw_writer_lock (
    singleton INTEGER PRIMARY KEY NOT NULL CHECK (singleton = 1),
    owner TEXT NOT NULL CHECK (length(owner) > 0),
    acquired_at_ms INTEGER NOT NULL CHECK (acquired_at_ms >= 0)
) STRICT;

CREATE INDEX authentication_records_device_order
    ON authentication_records(device_id, created_at_ms, id);
CREATE INDEX tasks_session_order
    ON tasks(session_id, created_at_ms, id);
