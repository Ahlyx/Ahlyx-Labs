package pcap

import (
	"testing"
	"time"
)

func TestSessionCredentialsAreSeparateAndRoleBound(t *testing.T) {
	store := &SessionStore{sessions: make(map[string]*RelaySession)}
	credentials, err := store.Create()
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if !validSessionID(credentials.SessionID) {
		t.Fatalf("invalid session ID %q", credentials.SessionID)
	}
	if len(credentials.AgentToken) < 43 || len(credentials.ViewerToken) < 43 || credentials.AgentToken == credentials.ViewerToken {
		t.Fatal("tokens are not independent 256-bit URL-safe values")
	}
	if _, ok := store.Reserve(credentials.SessionID, AgentRole, credentials.ViewerToken); ok {
		t.Fatal("viewer credential authenticated as agent")
	}
	if _, ok := store.Reserve(credentials.SessionID, ViewerRole, credentials.AgentToken); ok {
		t.Fatal("agent credential authenticated as viewer")
	}
	if _, ok := store.Reserve(credentials.SessionID, AgentRole, credentials.AgentToken); !ok {
		t.Fatal("agent credential was rejected")
	}
	if _, ok := store.Reserve(credentials.SessionID, AgentRole, credentials.AgentToken); ok {
		t.Fatal("agent credential rebound a reserved agent session")
	}
}

func TestExpiredSessionCannotBeReservedAndIsRemoved(t *testing.T) {
	store := &SessionStore{sessions: make(map[string]*RelaySession)}
	credentials, err := store.Create()
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	session, _ := store.Get(credentials.SessionID)
	session.created = time.Now().Add(-sessionTTL - time.Second)
	if _, ok := store.Reserve(credentials.SessionID, AgentRole, credentials.AgentToken); ok {
		t.Fatal("expired session was reserved")
	}
	store.cleanup()
	if _, ok := store.Get(credentials.SessionID); ok {
		t.Fatal("expired session remains in store")
	}
}
