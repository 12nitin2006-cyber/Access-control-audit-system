DROP TABLE IF EXISTS findings;
DROP TABLE IF EXISTS audit_runs;
DROP TABLE IF EXISTS access_logs;
DROP TABLE IF EXISTS sod_rules;
DROP TABLE IF EXISTS role_permissions;
DROP TABLE IF EXISTS user_roles;
DROP TABLE IF EXISTS resources;
DROP TABLE IF EXISTS roles;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,
    full_name     TEXT NOT NULL,
    department    TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    app_role      TEXT NOT NULL DEFAULT 'staff' CHECK (app_role IN ('admin','auditor','staff')),
    status        TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled','terminated')),
    last_login    TEXT,
    created_at    TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE roles (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    description TEXT
);

CREATE TABLE user_roles (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

CREATE TABLE resources (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    type        TEXT NOT NULL,
    sensitivity TEXT NOT NULL CHECK (sensitivity IN ('low','medium','high'))
);

CREATE TABLE role_permissions (
    role_id     INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    resource_id INTEGER NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
    permission  TEXT NOT NULL CHECK (permission IN ('read','write','delete','admin')),
    PRIMARY KEY (role_id, resource_id, permission)
);

CREATE TABLE sod_rules (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    role_a      INTEGER NOT NULL REFERENCES roles(id),
    role_b      INTEGER NOT NULL REFERENCES roles(id),
    description TEXT
);

CREATE TABLE access_logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id),
    resource_id INTEGER NOT NULL REFERENCES resources(id),
    action      TEXT NOT NULL,
    result      TEXT NOT NULL CHECK (result IN ('granted','denied')),
    logged_at   TEXT NOT NULL
);
CREATE INDEX idx_logs_user ON access_logs(user_id);

CREATE TABLE audit_runs (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    run_at         TEXT NOT NULL,
    run_by         TEXT NOT NULL,
    total_findings INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE findings (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id   INTEGER NOT NULL REFERENCES audit_runs(id) ON DELETE CASCADE,
    rule     TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('low','medium','high')),
    user_id  INTEGER NOT NULL REFERENCES users(id),
    detail   TEXT NOT NULL,
    status   TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','resolved'))
);
