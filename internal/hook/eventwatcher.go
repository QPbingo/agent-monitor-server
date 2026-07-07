// Package hook implements the file-based event ingestion pipeline.
//
// EventWatcher monitors events.jsonl using fsnotify (OS-level file change
// notifications). It parses each JSON line line, validates the daemon auth
// token, and forwards valid events to SessionManager.
//
// Consumption offset is persisted in events.offset for crash recovery,
// ensuring no events are lost or duplicated across daemon restarts.
//
// Data flow:
//
//	agent-monitor-hook binary
//	    │  (called by agent's hook system on every event)
//	    │  writes one JSON line to events.jsonl
//	    ▼
//	events.jsonl (on disk, ~/.agent-monitor/)
//	    │  fsnotify detects IN_MODIFY
//	    ▼
//	EventWatcher.handleNewLines()
//	    │  1. Seek to lastPos (from events.offset)
//	    │  2. bufio.Scanner by line
//	    │  3. json.Unmarshal → HookEvent
//	    │  4. token.ConstantTimeCompare (auth validation)
//	    │  5. handler.HandleEvent() → SessionManager
//	    │  6. saveOffset() → events.offset
//	    ▼
//	SessionManager (in-memory + SQLite)
//
// Security: Invalid tokens cause the event to be dropped silently.
// The offset is still advanced past invalid lines so they don't block
// processing of subsequent events.
package hook

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/heybox/agent-monitor-server/internal/session"
	"github.com/heybox/agent-monitor-server/internal/token"
)

// EventHandler is the interface that SessionManager implements to receive
// parsed and validated hook events.
//
// This decouples the EventWatcher (I/O layer) from SessionManager
// (business logic layer).
type EventHandler interface {
	HandleEvent(event *session.HookEvent)
}

// EventWatcher monitors the events.jsonl file and processes new hook events.
//
// Lifecycle:
//  1. NewEventWatcher() – creates the watcher, opens/creates events.jsonl.
//  2. Start() – reads the offset, processes any pending lines, starts the
//     background event loop goroutine.
//  3. loop() – background goroutine watching fsnotify events.
//  4. Stop() – closes the done channel and fsnotify watcher.
//
// Offsets are persisted atomically (write whole file) after each processed
// line. This means:
//   - If the daemon crashes mid-line, the incomplete line is re-read on restart
//     (since offset points to before that line).
//   - No events are lost because the offset is only advanced after successful
//     processing.
//   - No events are duplicated because position tracking is byte-accurate.
type EventWatcher struct {
	dir        string            // ~/.agent-monitor/ directory
	filePath   string            // ~/.agent-monitor/events.jsonl
	offsetPath string            // ~/.agent-monitor/events.offset
	tokenValue string            // Daemon auth token for event validation
	handler    EventHandler      // SessionManager (receives parsed events)
	watcher    *fsnotify.Watcher // OS-level file change monitor
	lastPos    int64             // Byte offset of last processed position
	done       chan struct{}     // Close to signal the event loop to exit
	mu         sync.Mutex        // Protects concurrent handleNewLines() calls
}

// NewEventWatcher creates a new event watcher for the given directory.
//
// The events.jsonl file is created if it doesn't exist (os.Create|O_RDONLY).
// The fsnotify watcher is initialized but not yet watching (Start() does that).
//
// Parameters:
//   - dir:        The ~/.agent-monitor/ directory path.
//   - tokenValue: Daemon auth token for validating hook events.
//   - handler:    EventHandler implementation (SessionManager).
func NewEventWatcher(dir string, tokenValue string, handler EventHandler) (*EventWatcher, error) {
	filePath := filepath.Join(dir, "events.jsonl")

	// Ensure the directory exists
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create monitor dir: %w", err)
	}

	// Create events.jsonl if it doesn't exist (O_CREATE)
	f, err := os.OpenFile(filePath, os.O_CREATE|os.O_RDONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("open events.jsonl: %w", err)
	}
	f.Close()

	// Create the fsnotify watcher (OS-level file event monitoring)
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("create fsnotify watcher: %w", err)
	}

	return &EventWatcher{
		dir:        dir,
		filePath:   filePath,
		offsetPath: filepath.Join(dir, "events.offset"),
		tokenValue: tokenValue,
		handler:    handler,
		watcher:    w,
		done:       make(chan struct{}),
	}, nil
}

// Start begins watching for events and launches the background event loop.
//
// Startup sequence:
//  1. Add events.jsonl to the fsnotify watcher.
//  2. Read the last consumed offset from events.offset.
//     If the offset file doesn't exist or is invalid, default to the current
//     end of events.jsonl (skip existing content from a fresh start).
//  3. Process any lines between lastPos and the current end of file
//     (catches events written between daemon restarts).
//  4. Launch the background event loop in a new goroutine.
func (ew *EventWatcher) Start() error {
	// Start watching the events.jsonl file for changes
	if err := ew.watcher.Add(ew.filePath); err != nil {
		return fmt.Errorf("watch events.jsonl: %w", err)
	}

	// Read the persisted consumption offset
	// readOffset returns -1 if the file doesn't exist or is invalid
	ew.lastPos = ew.readOffset()
	if ew.lastPos < 0 {
		// No valid offset file – start from the end of the current file
		// (anything written before this daemon started is part of a previous run)
		fi, err := os.Stat(ew.filePath)
		if err != nil {
			return fmt.Errorf("stat events.jsonl: %w", err)
		}
		ew.lastPos = fi.Size()
	}

	// Process any events that were written between the last run and now.
	// Run in a goroutine so the HTTP server can start immediately even when
	// there is a large backlog (e.g. 60+ MB events.jsonl with 60K+ lines).
	go ew.handleNewLines()

	// Launch the background event loop
	go ew.loop()
	return nil
}

// Stop signals the event loop to exit and closes the fsnotify watcher.
//
// Blocks until the loop goroutine exits (via done channel close).
// The fsnotify watcher is closed asynchronously.
//
// Called via defer in main() during shutdown:
//
//	defer ew.Stop()
func (ew *EventWatcher) Stop() {
	close(ew.done)
	ew.watcher.Close()
}

// loop is the background event loop that processes fsnotify events.
//
// Listens for two types of file events:
//
//	fnotify.Write:
//	  The hook binary appended new data to events.jsonl.
//	  Call handleNewLines() to read and process the new lines.
//	  The offset tracking ensures only new data is read.
//
//	fsnotify.Create:
//	  The events.jsonl file was recreated (e.g., deleted and recreated,
//	  or log rotation). Re-register the watcher on the new file and
//	  reset the offset to 0 to re-read all content.
//	  The old file descriptor is stale, so we Remove + re-Add.
//
// Exits when ew.done is closed (via Stop()).
func (ew *EventWatcher) loop() {
	for {
		select {
		case <-ew.done:
			return
		case event, ok := <-ew.watcher.Events:
			if !ok {
				return
			}
			switch {
			case event.Has(fsnotify.Write):
				// New data appended to the file
				ew.handleNewLines()
			case event.Has(fsnotify.Create):
				// File was recreated – reset tracking and re-read from scratch
				ew.watcher.Remove(ew.filePath)
				ew.watcher.Add(ew.filePath)
				ew.lastPos = 0
				log.Printf("[eventwatcher] events.jsonl recreated, reset offset to 0")
			}
		case err, ok := <-ew.watcher.Errors:
			if !ok {
				return
			}
			log.Printf("[eventwatcher] fsnotify error: %v", err)
		}
	}
}

// handleNewLines reads and processes new lines in events.jsonl from lastPos.
//
// Processing steps per-line:
//  1. Seek to lastPos in events.jsonl.
//  2. Scan line by line using bufio.Scanner (2MB max buffer for large payloads).
//  3. Skip empty lines.
//  4. Parse JSON → HookEvent struct.
//  5. Validate daemon_token with constant-time comparison.
//     Invalid tokens → log and skip (but advance offset).
//  6. Forward to handler.HandleEvent() (SessionManager).
//  7. Save the byte offset after the \n of the processed line.
//
// Offset tracking detail:
//
//	byteOffset tracks the position after each processed line (including \n).
//	It is updated incrementally: byteOffset += len(line) + 1 (for \n).
//	After all lines are processed, lastPos is set to byteOffset and persisted.
//
//	This ensures:
//	  - Crash mid-processing: lastPos points to the last fully-processed line+1.
//	    The incomplete line will be re-read on restart because it doesn't end with \n
//	    (scanner.Scan() only returns complete lines).
//	  - Invalid lines: offset is advanced past them so they don't block the pipeline.
//	  - File recreated: offset is reset to 0 and all content is re-read.
func (ew *EventWatcher) handleNewLines() {
	ew.mu.Lock()
	defer ew.mu.Unlock()

	f, err := os.Open(ew.filePath)
	if err != nil {
		log.Printf("[eventwatcher] open events.jsonl: %v", err)
		return
	}
	defer f.Close()

	// Seek to the last consumed position
	if _, err := f.Seek(ew.lastPos, io.SeekStart); err != nil {
		log.Printf("[eventwatcher] seek to %d: %v", ew.lastPos, err)
		return
	}

	reader := bufio.NewReader(f)

	// Track byte position incrementally for accurate offset persistence
	byteOffset := ew.lastPos
	for {
		lineBytes, readErr := reader.ReadBytes('\n')
		if len(lineBytes) == 0 {
			if readErr != nil && readErr != io.EOF {
				log.Printf("[eventwatcher] read line: %v", readErr)
			}
			break
		}
		byteOffset += int64(len(lineBytes))
		line := strings.TrimRight(string(lineBytes), "\r\n")

		if line == "" {
			continue
		}

		// ── Parse the JSON line ──────────────────────────────────────────
		var hookEvent session.HookEvent
		if err := json.Unmarshal([]byte(line), &hookEvent); err != nil {
			log.Printf("[eventwatcher] parse JSON: %v", err)
			ew.saveOffset(byteOffset) // skip malformed lines
			continue
		}

		// ── Authenticate the event ───────────────────────────────────────
		// The daemon token must be present and match the local daemon token.
		// Constant-time comparison prevents timing side-channel attacks.
		if hookEvent.DaemonToken == "" || !token.ConstantTimeCompare(hookEvent.DaemonToken, ew.tokenValue) {
			log.Printf("[eventwatcher] invalid token for event %s, dropped", hookEvent.Event)
			ew.saveOffset(byteOffset) // skip unauthorized events
			continue
		}

		// ── Forward to session manager ───────────────────────────────────
		// SessionManager handles session creation, state updates, persistence,
		// and real-time notification to WebSocket clients.
		ew.handler.HandleEvent(&hookEvent)

		// ── Persist offset after successful processing ───────────────────
		// If we crash here, the offset has already been saved for this line,
		// so it won't be re-read. If the crash happens before this, the line
		// will be re-read (no data loss).
		ew.saveOffset(byteOffset)

		if readErr == io.EOF {
			break
		}
	}

	// Update the last known position after all lines are processed
	ew.lastPos = byteOffset
	ew.saveOffset(ew.lastPos)
}

// readOffset reads the last consumed byte offset from events.offset.
//
// The offset file contains a single int64 value as ASCII text.
// Returns -1 if the file doesn't exist, is empty, or contains invalid data.
func (ew *EventWatcher) readOffset() int64 {
	data, err := os.ReadFile(ew.offsetPath)
	if err != nil {
		return -1
	}
	offset, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return -1
	}
	return offset
}

// saveOffset atomically writes the current byte offset to events.offset.
//
// Called after processing each line and after completing all available lines.
// The atomic write (whole file replacement) ensures that a partial write
// during a crash doesn't leave a corrupted offset file.
//
// The file is created with 0600 permissions (owner read/write only) to
// prevent other users from reading process position information.
func (ew *EventWatcher) saveOffset(offset int64) {
	ew.lastPos = offset
	data := []byte(strconv.FormatInt(offset, 10))
	if err := os.WriteFile(ew.offsetPath, data, 0600); err != nil {
		log.Printf("[eventwatcher] write offset: %v", err)
	}
}
