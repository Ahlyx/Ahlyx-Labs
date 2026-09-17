package pcap

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const (
	sessionTTL     = time.Hour
	maxBufferBytes = 1 << 20
	maxBufferItems = 50
)

type RelayRole string

const (
	AgentRole  RelayRole = "agent"
	ViewerRole RelayRole = "viewer"
)

// SessionCredentials are issued only to the process creating a session. The
// session ID is a lookup reference; the role tokens are bearer secrets.
type SessionCredentials struct {
	SessionID   string
	AgentToken  string
	ViewerToken string
}

// RelaySession holds the two WebSocket ends of a relay pair plus a bounded
// buffer for frames that arrive before the browser has connected.
type RelaySession struct {
	mu       sync.Mutex
	sendMu   sync.Mutex
	agent    *websocket.Conn
	browser  *websocket.Conn
	buffer   [][]byte
	bufBytes int

	agentToken  string
	viewerToken string
	agentBound  bool
	viewerBound bool

	created  time.Time
	lastUsed time.Time
}

// Reserve validates the credential for role and consumes its one permitted
// binding. It prevents a second agent or viewer from racing the first one.
func (s *RelaySession) Reserve(role RelayRole, token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if time.Since(s.created) > sessionTTL {
		return false
	}
	switch role {
	case AgentRole:
		if s.agentBound || !equalSecret(token, s.agentToken) {
			return false
		}
		s.agentBound = true
	case ViewerRole:
		if s.viewerBound || !equalSecret(token, s.viewerToken) {
			return false
		}
		s.viewerBound = true
	default:
		return false
	}
	s.lastUsed = time.Now()
	return true
}

// Release clears a reservation only when a WebSocket upgrade fails.
func (s *RelaySession) Release(role RelayRole) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if role == AgentRole && s.agent == nil {
		s.agentBound = false
	}
	if role == ViewerRole && s.browser == nil {
		s.viewerBound = false
	}
}

func (s *RelaySession) SetAgent(ws *websocket.Conn) {
	s.mu.Lock()
	s.agent = ws
	s.lastUsed = time.Now()
	s.mu.Unlock()
}

func (s *RelaySession) SetBrowserAndFlush(ws *websocket.Conn) {
	s.sendMu.Lock()
	s.mu.Lock()
	s.browser = ws
	s.lastUsed = time.Now()
	buf := s.buffer
	s.buffer = nil
	s.bufBytes = 0
	s.mu.Unlock()
	for _, msg := range buf {
		_ = ws.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if err := ws.WriteMessage(websocket.TextMessage, msg); err != nil {
			break
		}
	}
	s.sendMu.Unlock()
}

// Forward relays msg to the browser, buffering bounded bytes and frames until
// it connects. Buffer pressure drops live data rather than consuming memory.
func (s *RelaySession) Forward(msg []byte) {
	s.mu.Lock()
	s.lastUsed = time.Now()
	browser := s.browser
	if browser == nil {
		if len(s.buffer) < maxBufferItems && s.bufBytes+len(msg) <= maxBufferBytes {
			copyMsg := append([]byte(nil), msg...)
			s.buffer = append(s.buffer, copyMsg)
			s.bufBytes += len(copyMsg)
		}
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()
	s.sendMu.Lock()
	_ = browser.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_ = browser.WriteMessage(websocket.TextMessage, msg)
	s.sendMu.Unlock()
}

func (s *RelaySession) Touch() {
	s.mu.Lock()
	s.lastUsed = time.Now()
	s.mu.Unlock()
}

func (s *RelaySession) IsExpired(now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return now.Sub(s.created) > sessionTTL || now.Sub(s.lastUsed) > sessionTTL
}

// CloseBoth closes connections and clears all credentials and buffered state.
func (s *RelaySession) CloseBoth() {
	s.mu.Lock()
	agent := s.agent
	browser := s.browser
	s.agent = nil
	s.browser = nil
	s.buffer = nil
	s.bufBytes = 0
	s.agentToken = ""
	s.viewerToken = ""
	s.mu.Unlock()
	if agent != nil {
		_ = agent.Close()
	}
	if browser != nil {
		_ = browser.Close()
	}
}

type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*RelaySession
}

var Store = newSessionStore()

func newSessionStore() *SessionStore {
	s := &SessionStore{sessions: make(map[string]*RelaySession)}
	s.startCleanup()
	return s
}

func (s *SessionStore) startCleanup() {
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for range t.C {
			s.cleanup()
		}
	}()
}

func (s *SessionStore) cleanup() {
	now := time.Now()
	var stale []*RelaySession
	s.mu.Lock()
	for id, sess := range s.sessions {
		if sess.IsExpired(now) {
			delete(s.sessions, id)
			stale = append(stale, sess)
		}
	}
	s.mu.Unlock()
	for _, sess := range stale {
		sess.CloseBoth()
	}
}

// Create allocates a session with separate 256-bit agent and viewer tokens.
func (s *SessionStore) Create() (SessionCredentials, error) {
	id, err := randomHex(16)
	if err != nil {
		return SessionCredentials{}, err
	}
	agentToken, err := randomToken()
	if err != nil {
		return SessionCredentials{}, err
	}
	viewerToken, err := randomToken()
	if err != nil {
		return SessionCredentials{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[id] = &RelaySession{agentToken: agentToken, viewerToken: viewerToken, created: time.Now(), lastUsed: time.Now()}
	return SessionCredentials{SessionID: id, AgentToken: agentToken, ViewerToken: viewerToken}, nil
}

func (s *SessionStore) Reserve(id string, role RelayRole, token string) (*RelaySession, bool) {
	if !validSessionID(id) || token == "" {
		return nil, false
	}
	s.mu.RLock()
	sess, ok := s.sessions[id]
	s.mu.RUnlock()
	if !ok || !sess.Reserve(role, token) {
		return nil, false
	}
	return sess, true
}

func (s *SessionStore) Get(id string) (*RelaySession, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.sessions[id]
	return sess, ok
}

func (s *SessionStore) Delete(id string) {
	s.mu.Lock()
	sess := s.sessions[id]
	delete(s.sessions, id)
	s.mu.Unlock()
	if sess != nil {
		sess.CloseBoth()
	}
}

func randomHex(size int) (string, error) {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		return "", errors.New("secure random generation failed")
	}
	return hex.EncodeToString(b), nil
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", errors.New("secure random generation failed")
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func validSessionID(id string) bool {
	if len(id) != 32 {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}

func equalSecret(provided, expected string) bool {
	if len(provided) != len(expected) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) == 1
}
