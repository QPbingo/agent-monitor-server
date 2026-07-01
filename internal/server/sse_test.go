package server

import (
	"bytes"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestSSEClient_WriteMutex covers SSE-02 (constraint A): concurrent writes to
// the same SSEClient never interleave bytes. If the per-client mutex were
// absent, concurrent fmt.Fprintf calls would interleave "data: ..." frames on
// the shared ResponseWriter, corrupting the SSE stream. We verify every emitted
// frame is a complete, well-formed "data: {json}\n\n" block.
func TestSSEClient_WriteMutex(t *testing.T) {
	rec := httptest.NewRecorder()
	client := &SSEClient{
		w:       rec,
		flusher: rec,
		send:    make(chan []byte, sseSendBufSize),
	}

	const goroutines = 16
	const perGoroutine = 50
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < perGoroutine; j++ {
				payload := []byte(fmt.Sprintf(`{"id":%d,"seq":%d}`, n, j))
				if !client.write(payload) {
					t.Errorf("write failed for goroutine %d seq %d", n, j)
				}
			}
		}(i)
	}
	wg.Wait()

	body := rec.Body.String()
	// Every frame must be exactly "data: {\"id\":N,\"seq\":M}\n\n".
	// Split on "\n\n" and verify each non-empty segment starts with "data: "
	// and is a complete JSON object (no interleaving).
	frames := strings.Split(body, "\n\n")
	total := 0
	for _, f := range frames {
		if f == "" {
			continue
		}
		if !strings.HasPrefix(f, "data: ") {
			t.Fatalf("frame does not start with 'data: ': %q", f)
		}
		// The payload portion must be a single JSON object. If bytes interleaved,
		// we'd see something like data: {"id":1{"id":2,...
		payload := f[len("data: "):]
		if !strings.HasPrefix(payload, `{"id":`) || !strings.HasSuffix(payload, `}`) {
			t.Fatalf("malformed frame payload (interleaving?): %q", payload)
		}
		// Must contain exactly one "id" and one "seq".
		if strings.Count(payload, `"id":`) != 1 || strings.Count(payload, `"seq":`) != 1 {
			t.Fatalf("frame payload has duplicated/mixed fields (interleaving?): %q", payload)
		}
		total++
	}
	if total != goroutines*perGoroutine {
		t.Fatalf("frame count = %d, want %d", total, goroutines*perGoroutine)
	}
}

// TestSSEClient_WriteJSON verifies writeJSON emits a valid SSE data frame.
func TestSSEClient_WriteJSON(t *testing.T) {
	rec := httptest.NewRecorder()
	c := &SSEClient{w: rec, flusher: rec, send: make(chan []byte, 1)}
	c.writeJSON(map[string]string{"type": "snapshot"})

	body := rec.Body.String()
	if !strings.HasPrefix(body, "data: ") || !strings.HasSuffix(body, "\n\n") {
		t.Fatalf("writeJSON output = %q, want 'data: ...\\n\\n'", body)
	}
	if !strings.Contains(body, `"type":"snapshot"`) {
		t.Fatalf("writeJSON payload missing type: %q", body)
	}
}

// TestSSEClient_WriteComment verifies the heartbeat comment line format.
func TestSSEClient_WriteComment(t *testing.T) {
	rec := httptest.NewRecorder()
	c := &SSEClient{w: rec, flusher: rec, send: make(chan []byte, 1)}
	if !c.writeComment(": ping") {
		t.Fatal("writeComment returned false")
	}
	if body := rec.Body.String(); body != ": ping\n\n" {
		t.Fatalf("comment output = %q, want ': ping\\n\\n'", body)
	}
}

// TestSSEHub_BroadcastDelivers covers the broadcast path: Notify enqueues a
// delta and the hub Run() loop delivers it to a registered client's send chan.
func TestSSEHub_BroadcastDelivers(t *testing.T) {
	h := NewSSEHub(nil, nil, nil, nil)
	go h.Run()

	c := &SSEClient{
		w:       httptest.NewRecorder(),
		flusher: nil, // not used here; we only read from send
		send:    make(chan []byte, 4),
	}
	h.register <- c
	// Give the hub's Run loop time to process the registration so the client
	// is in the set before we broadcast. (register is unbuffered; the send
	// only completes once Run receives it, but the map insertion happens
	// after that receive in the same goroutine.)
	// A tiny sleep is acceptable here because we are synchronizing with a
	// separate goroutine that we do not control directly.
	// Wait until the client is registered by polling the hub's client set.
	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		h.mu.Lock()
		n := len(h.clients)
		h.mu.Unlock()
		if n == 1 {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}

	// BroadcastAgent takes a map and broadcasts to all clients.
	h.BroadcastAgent(map[string]interface{}{"type": "agent_message", "content": "hi"})

	select {
	case msg := <-c.send:
		if !bytes.Contains(msg, []byte(`"type":"agent_message"`)) {
			t.Fatalf("broadcast msg = %q, want agent_message", msg)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("no message delivered to client")
	}
}
