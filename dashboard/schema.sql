-- schema.sql — SOC Dashboard incident management persistence
-- SQLite 3. Applied automatically on first run by app_v9.py (init_db()).
-- Safe to re-run: all statements use IF NOT EXISTS.
--
-- Three tables:
--   cases       — one row per incident case
--   case_alerts — alerts (by source IP / context) attached to a case (many-to-one)
--   audit_log   — append-only trail of every state change for accountability
--
-- Author: Tyce Erickson · CMU MSISPM Portfolio · Project 4

PRAGMA journal_mode = WAL;      -- better concurrency for the polling dashboard
PRAGMA foreign_keys = ON;

-- ── cases ────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS cases (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    title        TEXT    NOT NULL,
    severity     TEXT    NOT NULL DEFAULT 'medium'   -- low | medium | high | critical
                         CHECK (severity IN ('low','medium','high','critical')),
    status       TEXT    NOT NULL DEFAULT 'open'      -- open | investigating | closed
                         CHECK (status IN ('open','investigating','closed')),
    assignee     TEXT    NOT NULL DEFAULT 'unassigned',
    src_ip       TEXT,                                -- primary IP this case is about (nullable)
    playbook     TEXT,                                -- key of the attached playbook, if any
    playbook_done TEXT   NOT NULL DEFAULT '[]',       -- JSON array of completed checklist step indices
    notes        TEXT    NOT NULL DEFAULT '',
    created_at   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE INDEX IF NOT EXISTS idx_cases_status   ON cases(status);
CREATE INDEX IF NOT EXISTS idx_cases_severity ON cases(severity);
CREATE INDEX IF NOT EXISTS idx_cases_src_ip   ON cases(src_ip);

-- ── case_alerts ──────────────────────────────────────────────────────────
-- A snapshot of the alert/IP context at the time it was attached, so the case
-- timeline is stable even if the live index rolls over.
CREATE TABLE IF NOT EXISTS case_alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id     INTEGER NOT NULL,
    src_ip      TEXT,
    summary     TEXT,                                 -- short human label
    detail_json TEXT,                                 -- full JSON snapshot
    added_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_case_alerts_case ON case_alerts(case_id);

-- ── audit_log ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS audit_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id   INTEGER,
    action    TEXT NOT NULL,                          -- created | updated | status_change | note | alert_added | playbook_step
    detail    TEXT,                                   -- free-form / JSON detail of what changed
    actor     TEXT NOT NULL DEFAULT 'analyst',
    ts        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_case ON audit_log(case_id);
CREATE INDEX IF NOT EXISTS idx_audit_ts   ON audit_log(ts);
