package session

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// daemon_sessions table schema.
//
// The primary key is the natural composite of (user_id, device_id, agent_type, agent_session_id).
// This means each unique agent session gets exactly one row, and any repeated hook events
// for the same session will UPDATE the existing row via ON CONFLICT DO UPDATE.
//
// Column design:
//
//   - Identity columns (user_id, device_id, agent_type, agent_session_id):
//     Together form the primary key. Never change once a session is created.
//
//   - session_key: hex(SHA256(identity))[:16], used as the in-memory map key
//     and for API lookups. Included for reverse lookup by key if needed.
//
//   - Process columns (pid, terminal, cwd, memory_mb, cpu_percent):
//     Updated by PID Scanner via UpdateProcessFields(). These change frequently
//     and are separated in a lighter UPDATE to avoid write contention.
//
//   - Status columns (status, start_time_ms, last_event_time_ms, ...):
//     Updated by hook events via Upsert(). Status transitions follow the
//     session lifecycle state machine.
//
//   - Content columns (user_input, agent_output, session_title, payload,
//     last_hook_event, last_file, last_command, turn_count, git_branch):
//     Extracted from hook event payloads, providing the dashboard with
//     contextual information about what the agent is doing.
//
//   - Timestamp bookkeeping (created_at, updated_at, ended_at):
//     created_at/updated_at are always set. ended_at is set when the session
//     reaches a terminal state (stopped, disappeared).
const createTableSQL = `
CREATE TABLE IF NOT EXISTS daemon_sessions (
    user_id          TEXT NOT NULL,
    device_id        TEXT NOT NULL,
    agent_type       TEXT NOT NULL,
    agent_session_id TEXT NOT NULL,
    session_key      TEXT NOT NULL,
    pid              INTEGER DEFAULT 0,
    terminal         TEXT DEFAULT '',
    cwd              TEXT DEFAULT '',
    status           TEXT DEFAULT 'active',
    start_time_ms    INTEGER NOT NULL,
    last_event_time_ms INTEGER DEFAULT 0,
    last_event_type  TEXT DEFAULT '',
    last_file        TEXT DEFAULT '',
    last_command     TEXT DEFAULT '',
    user_input       TEXT DEFAULT '',
    agent_output     TEXT DEFAULT '',
    session_title    TEXT DEFAULT '',
    payload          TEXT DEFAULT '',
    last_hook_event  TEXT DEFAULT '',
    memory_mb        REAL DEFAULT 0,
    cpu_percent      REAL DEFAULT 0,
	turn_count       INTEGER DEFAULT 0,
	turns            TEXT DEFAULT '[]',
	git_branch       TEXT DEFAULT '',
	source           TEXT DEFAULT 'hook',
    created_at       INTEGER NOT NULL,
    updated_at       INTEGER NOT NULL,
    ended_at         INTEGER,
    PRIMARY KEY (user_id, device_id, agent_type, agent_session_id)
);
`

// Light migration: adds content columns that may not exist in older databases.
//
// These were added after the initial table creation. ALTER TABLE ADD COLUMN
// is safe in SQLite (no table locking issues for column additions).
// The migration is designed to be idempotent – errors from duplicate columns
// are silently ignored (db.Exec doesn't check the error).
//
// Columns added:
//   - user_input:   the last user prompt text
//   - agent_output: accumulated agent output log
//   - session_title: first user input used as title
//   - payload:      raw JSON of the most recent hook event
//   - last_hook_event: raw event name from the hook
var migrationSQLs = []string{
	`ALTER TABLE daemon_sessions ADD COLUMN user_input TEXT DEFAULT ''`,
	`ALTER TABLE daemon_sessions ADD COLUMN agent_output TEXT DEFAULT ''`,
	`ALTER TABLE daemon_sessions ADD COLUMN session_title TEXT DEFAULT ''`,
	`ALTER TABLE daemon_sessions ADD COLUMN payload TEXT DEFAULT ''`,
	`ALTER TABLE daemon_sessions ADD COLUMN last_hook_event TEXT DEFAULT ''`,
	`ALTER TABLE daemon_sessions ADD COLUMN turns TEXT DEFAULT '[]'`,
	`ALTER TABLE daemon_sessions ADD COLUMN story_id INTEGER`,
	`ALTER TABLE daemon_sessions ADD COLUMN source TEXT DEFAULT 'hook'`,
}

// Store wraps a SQLite database connection for session persistence.
//
// Uses modernc.org/sqlite – a pure Go SQLite implementation with no CGO dependency.
// This means the binary is fully static and cross-compilable without a C toolchain.
//
// Connection configuration:
//   - _journal_mode=WAL: Write-Ahead Logging for better concurrent read performance.
//     Writers don't block readers, readers don't block writers.
//   - _busy_timeout=5000: Wait up to 5 seconds when encountering SQLITE_BUSY
//     (another write is in progress), instead of failing immediately.
//   - SetMaxOpenConns(1): Single writer. Multiple goroutines can read concurrently
//     in WAL mode, but only one can write. This avoids SQLITE_BUSY entirely
//     for our single-writer pattern.
type Store struct {
	db *sql.DB
}

// NewStore opens (or creates) the SQLite database and initializes the schema.
//
// Parameters:
//   - dbPath: filesystem path to the SQLite database file (e.g. ~/.agent-monitor/daemon.db)
//
// Returns an error if:
//   - The database cannot be opened
//   - The CREATE TABLE fails (permissions, disk full, etc.)
//
// Migration errors (ALTER TABLE for columns that already exist) are silently ignored
// because SQLite doesn't support IF NOT EXISTS for ALTER TABLE.
func NewStore(dbPath string) (*Store, error) {
	db, err := sql.Open("sqlite", dbPath+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	db.SetMaxOpenConns(1)

	if _, err := db.Exec(`PRAGMA foreign_keys=ON`); err != nil {
		db.Close()
		return nil, fmt.Errorf("enable foreign keys: %w", err)
	}

	if _, err := db.Exec(createTableSQL); err != nil {
		db.Close()
		return nil, fmt.Errorf("create table: %w", err)
	}

	// Run each migration independently so one failure doesn't block the rest.
	for _, m := range migrationSQLs {
		db.Exec(m)
	}

	return &Store{db: db}, nil
}

// DB returns the underlying *sql.DB for sharing with other packages.
func (s *Store) DB() (*sql.DB, error) {
	return s.db, nil
}

// Close closes the database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

// Upsert inserts a new session or updates an existing one.
//
// Uses SQLite's INSERT ... ON CONFLICT DO UPDATE syntax for atomic upsert.
// The conflict target is the composite primary key (user_id, device_id,
// agent_type, agent_session_id).
//
// Behavior:
//   - New row: INSERTs all columns including created_at, updated_at.
//   - Existing row: UPDATEs all mutable columns, only sets updated_at.
//   - ended_at: Set to current time if session status is stopped or disappeared
//     (terminal states). nil otherwise (keeps previous value).
//
// This is used for full session state writes (hook events, status changes).
// For process-metric-only updates, prefer UpdateProcessFields() which is lighter.
func (s *Store) Upsert(sess *Session) error {
	now := time.Now().UnixMilli()

	// Only set ended_at for terminal states
	endedAt := interface{}(nil)
	if sess.Status == StatusStopped || sess.Status == StatusDisappeared {
		endedAt = now
	}

	// "null" is a special JSON value that should be treated as empty
	payload := string(sess.Payload)
	if payload == "null" {
		payload = ""
	}

	turnsJSON := "[]"
	if len(sess.Turns) > 0 {
		if b, err := json.Marshal(sess.Turns); err == nil {
			turnsJSON = string(b)
		}
	}

	_, err := s.db.Exec(`
		INSERT INTO daemon_sessions (
			user_id, device_id, agent_type, agent_session_id, session_key,
			pid, terminal, cwd, status, start_time_ms,
			last_event_time_ms, last_event_type, last_file, last_command,
			user_input, agent_output, session_title, payload, last_hook_event,
			memory_mb, cpu_percent, turn_count, turns, git_branch, story_id, source,
			created_at, updated_at, ended_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(user_id, device_id, agent_type, agent_session_id) DO UPDATE SET
			session_key = excluded.session_key,
			pid = excluded.pid,
			terminal = excluded.terminal,
			cwd = excluded.cwd,
			status = excluded.status,
			start_time_ms = excluded.start_time_ms,
			last_event_time_ms = excluded.last_event_time_ms,
			last_event_type = excluded.last_event_type,
			last_file = excluded.last_file,
			last_command = excluded.last_command,
			user_input = excluded.user_input,
			agent_output = excluded.agent_output,
			session_title = excluded.session_title,
			payload = excluded.payload,
			last_hook_event = excluded.last_hook_event,
			memory_mb = excluded.memory_mb,
			cpu_percent = excluded.cpu_percent,
			turn_count = excluded.turn_count,
			turns = excluded.turns,
			git_branch = excluded.git_branch,
			story_id = excluded.story_id,
			source = excluded.source,
			updated_at = excluded.updated_at,
			ended_at = excluded.ended_at
	`,
		sess.UserID, sess.DeviceID, sess.AgentType, sess.AgentSessionID, sess.SessionKey,
		sess.PID, sess.Terminal, sess.CWD, string(sess.Status), sess.StartTimeMs,
		sess.LastEventTimeMs, sess.LastEventType, sess.LastFile, sess.LastCommand,
		sess.UserInput, sess.AgentOutput, sess.SessionTitle, payload, sess.LastHookEvent,
		sess.MemoryMB, sess.CPUPercent, sess.TurnCount, turnsJSON, sess.GitBranch,
		sess.StoryID, sessionSource(sess),
		now, now, endedAt,
	)
	return err
}

// UpdateProcessFields updates only process-level metrics in the database.
//
// This is a lighter UPDATE compared to Upsert() – it only changes:
//
//	pid, terminal, cwd, memory_mb, cpu_percent, updated_at
//
// It does NOT touch: status, hook event data, content fields, ended_at.
//
// This reduces write contention because:
//  1. Fewer columns updated → smaller WAL entries.
//  2. Hook events (Upsert) and process scans (UpdateProcessFields) touch
//     different columns, reducing SQLite page-level conflicts.
//  3. updated_at timestamp is still refreshed to show liveness.
//
// Called by HandlePidUpdate() on every PID scan cycle where process
// metrics changed meaningfully.
func (s *Store) UpdateProcessFields(sess *Session) error {
	now := time.Now().UnixMilli()
	_, err := s.db.Exec(`
		UPDATE daemon_sessions SET
			pid = ?, terminal = ?, cwd = ?, memory_mb = ?, cpu_percent = ?,
			updated_at = ?
		WHERE user_id = ? AND device_id = ? AND agent_type = ? AND agent_session_id = ?
	`,
		sess.PID, sess.Terminal, sess.CWD, sess.MemoryMB, sess.CPUPercent,
		now,
		sess.UserID, sess.DeviceID, sess.AgentType, sess.AgentSessionID,
	)
	return err
}

// LoadAll loads all sessions from the database into memory.
//
// Called once at daemon startup to restore state from the previous run.
// Sessions are ordered by start_time_ms DESC (most recent first).
//
// Field mapping note:
//   - Separate variables are used for TEXT columns that could be NULL (user_input,
//     agent_output, session_title, payload, last_hook_event) to handle the
//     transition from empty string to non-NULL.
//   - created_at and updated_at are scanned but discarded (not needed in memory).
//
// The session's lastHookTime is initialized from LastEventTimeMs. This is
// acceptable because the PID Scanner will run immediately after recovery
// and detect any idle/dead sessions.
func (s *Store) LoadAll() ([]*Session, error) {
	rows, err := s.db.Query(`
		SELECT user_id, device_id, agent_type, agent_session_id, session_key,
			pid, terminal, cwd, status, start_time_ms,
			last_event_time_ms, last_event_type, last_file, last_command,
			user_input, agent_output, session_title, payload, last_hook_event,
			memory_mb, cpu_percent, turn_count, turns, git_branch,
			story_id, source, created_at, updated_at
		FROM daemon_sessions
		ORDER BY start_time_ms DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []*Session
	for rows.Next() {
		var s Session
		var userInput, agentOutput, sessionTitle, payload, lastHookEvent, turnsJSON string
		var storyID sql.NullInt64
		if err := rows.Scan(
			&s.UserID, &s.DeviceID, &s.AgentType, &s.AgentSessionID, &s.SessionKey,
			&s.PID, &s.Terminal, &s.CWD, &s.Status, &s.StartTimeMs,
			&s.LastEventTimeMs, &s.LastEventType, &s.LastFile, &s.LastCommand,
			&userInput, &agentOutput, &sessionTitle, &payload, &lastHookEvent,
			&s.MemoryMB, &s.CPUPercent, &s.TurnCount, &turnsJSON, &s.GitBranch,
			&storyID, &s.Source, new(int64), new(int64),
		); err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}
		if storyID.Valid {
			s.StoryID = &storyID.Int64
		}
		s.UserInput = userInput
		s.AgentOutput = agentOutput
		s.SessionTitle = sessionTitle
		s.LastHookEvent = lastHookEvent
		if payload != "" {
			s.Payload = []byte(payload)
		}
		if turnsJSON != "" && turnsJSON != "[]" {
			json.Unmarshal([]byte(turnsJSON), &s.Turns)
		}
		s.lastHookTime = s.LastEventTimeMs
		if s.Source == "" {
			s.Source = "hook"
		}
		sessions = append(sessions, &s)
	}

	return sessions, rows.Err()
}

func sessionSource(sess *Session) string {
	if sess.Source == "" {
		return "hook"
	}
	return sess.Source
}
