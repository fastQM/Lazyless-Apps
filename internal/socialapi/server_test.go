package socialapi

import (
	"bytes"
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ClawdCity-Apps/internal/social"
)

func TestSSEStreamWritesStateEvent(t *testing.T) {
	t.Parallel()

	m, err := social.NewManager(social.Config{DataDir: t.TempDir(), RPCSocketPath: "/tmp/does-not-exist.sock"})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	s := NewServer(m)

	req := httptest.NewRequest("GET", "/api/social/v1/stream", nil)
	ctx, cancel := context.WithCancel(req.Context())
	defer cancel()
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		s.handleStream(rec, req)
		close(done)
	}()

	time.Sleep(100 * time.Millisecond)
	_, err = m.Init("alice", "hi", "", "pw", social.Settings{Discoverable: true, AllowStrangerRequests: true, AllowGlobalFeed: true})
	if err != nil {
		t.Fatalf("init social: %v", err)
	}

	time.Sleep(200 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("stream handler did not exit")
	}

	body := rec.Body.String()
	if !strings.Contains(body, "event: ready") {
		t.Fatalf("expected ready event, got: %s", body)
	}
	if !strings.Contains(body, "event: state") {
		t.Fatalf("expected state event, got: %s", body)
	}
}

func TestHandleInitAndState(t *testing.T) {
	t.Parallel()
	m, err := social.NewManager(social.Config{DataDir: t.TempDir(), RPCSocketPath: "/tmp/does-not-exist.sock"})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	s := NewServer(m)
	mux := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/social/v1/state", nil)
	s.handleState(mux, req)
	if mux.Code != 200 {
		t.Fatalf("state code: %d", mux.Code)
	}

	initReq := httptest.NewRequest("POST", "/api/social/v1/init", bytes.NewBufferString(`{"username":"bob","passphrase":"pw","settings":{"discoverable":true,"allow_stranger_requests":true,"allow_global_feed":true}}`))
	initReq.Header.Set("Content-Type", "application/json")
	initRec := httptest.NewRecorder()
	s.handleInit(initRec, initReq)
	if initRec.Code != 200 {
		t.Fatalf("init code: %d body=%s", initRec.Code, initRec.Body.String())
	}
}
