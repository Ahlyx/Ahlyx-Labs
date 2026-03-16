package pcap

import (
	"crypto/rand"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const sessionTTL = time.Hour

// RelaySession holds the two WebSocket ends of a relay pair plus a message
// buffer for frames that arrive before the browser has connected.
type RelaySession struct {
	mu       sync.Mutex
	sendMu   sync.Mutex // serialises writes to the browser conn
	agent    *websocket.Conn
	browser  *websocket.Conn
	buffer   [][]byte // buffered agent frames, capped at 50
	created  time.Time
	lastUsed time.Time
}

// SetAgent stores the agent connection and updates the idle timestamp.
func (s *RelaySession) SetAgent(ws *websocket.Conn) {
	s.mu.Lock()
	s.agent = ws
	s.lastUsed = time.Now()
	s.mu.Unlock()
}

// SetBrowserAndFlush stores the browser connection and delivers any buffered
// frames. sendMu is held for the entire operation so no concurrent Forward
// call can interleave with the flush.
func (s *RelaySession) SetBrowserAndFlush(ws *websocket.Conn) {
	s.sendMu.Lock()
	s.mu.Lock()
	s.browser = ws
	s.lastUsed = time.Now()
	buf := s.buffer
	s.buffer = nil
	s.mu.Unlock()

	for _, msg := range buf {
		_ = ws.WriteMessage(websocket.TextMessage, msg)
	}
	s.sendMu.Unlock()
}

// Forward relays msg to the browser. If the browser is not yet connected the
// frame is buffered up to a maximum of 50 messages; excess frames are dropped.
func (s *RelaySession) Forward(msg []byte) {
	s.mu.Lock()
	s.lastUsed = time.Now()
	browser := s.browser
	if browser == nil {
		if len(s.buffer) < 50 {
			s.buffer = append(s.buffer, msg)
		}
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()

	s.sendMu.Lock()
	_ = browser.WriteMessage(websocket.TextMessage, msg)
	s.sendMu.Unlock()
}

// CloseBoth closes both connections if they are still open.
func (s *RelaySession) CloseBoth() {
	s.mu.Lock()
	agent := s.agent
	browser := s.browser
	s.agent = nil
	s.browser = nil
	s.mu.Unlock()

	if agent != nil {
		_ = agent.Close()
	}
	if browser != nil {
		_ = browser.Close()
	}
}

// SessionStore is a sync.RWMutex-protected map of session IDs to sessions.
type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*RelaySession
}

// Store is the package-level session store, initialised on startup.
var Store = newSessionStore()

func newSessionStore() *SessionStore {
	s := &SessionStore{
		sessions: make(map[string]*RelaySession),
	}
	s.startCleanup()
	return s
}

func (s *SessionStore) startCleanup() {
	go func() {
		t := time.NewTicker(10 * time.Minute)
		defer t.Stop()
		for range t.C {
			s.cleanup()
		}
	}()
}

func (s *SessionStore) cleanup() {
	cutoff := time.Now().Add(-sessionTTL)
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, sess := range s.sessions {
		sess.mu.Lock()
		stale := sess.lastUsed.Before(cutoff)
		sess.mu.Unlock()
		if stale {
			delete(s.sessions, id)
		}
	}
}

// Create allocates a new session and returns its ID.
func (s *SessionStore) Create() string {
	id := newSessionID()
	s.mu.Lock()
	s.sessions[id] = &RelaySession{
		created:  time.Now(),
		lastUsed: time.Now(),
	}
	s.mu.Unlock()
	return id
}

// GetOrCreate returns an existing session or creates a new one.
func (s *SessionStore) GetOrCreate(id string) *RelaySession {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess, ok := s.sessions[id]; ok {
		return sess
	}
	sess := &RelaySession{
		created:  time.Now(),
		lastUsed: time.Now(),
	}
	s.sessions[id] = sess
	return sess
}

// Get returns an existing session, or (nil, false) if not found.
func (s *SessionStore) Get(id string) (*RelaySession, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.sessions[id]
	return sess, ok
}

// Delete removes a session from the store. Safe to call more than once.
func (s *SessionStore) Delete(id string) {
	s.mu.Lock()
	delete(s.sessions, id)
	s.mu.Unlock()
}

// newSessionID returns a random 8-character lowercase alphanumeric string.
func newSessionID() string {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = chars[int(b[i])%len(chars)]
	}
	return string(b)
}
