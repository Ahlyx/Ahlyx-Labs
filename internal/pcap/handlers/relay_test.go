package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Ahlyx/Ahlyx-Labs/internal/pcap"
)

func TestRelayCredentialsBindRoleToTransport(t *testing.T) {
	agent := httptest.NewRequest(http.MethodGet, "/ws/relay/id", nil)
	agent.Header.Set("Authorization", "Bearer agent-token")
	role, token, ok := relayCredentials(agent)
	if !ok || role != pcap.AgentRole || token != "agent-token" {
		t.Fatalf("agent credential = (%q, %q, %v)", role, token, ok)
	}

	viewer := httptest.NewRequest(http.MethodGet, "/ws/relay/id", nil)
	viewer.Header.Set("Sec-WebSocket-Protocol", "ahlyx-relay-v1, viewer-token")
	role, token, ok = relayCredentials(viewer)
	if !ok || role != pcap.ViewerRole || token != "viewer-token" {
		t.Fatalf("viewer credential = (%q, %q, %v)", role, token, ok)
	}
}

func TestViewerOriginPolicy(t *testing.T) {
	if !isViewerOrigin("https://ahlyxlabs.com") || !isViewerOrigin("https://www.ahlyxlabs.com") {
		t.Fatal("official viewer origin was rejected")
	}
	for _, origin := range []string{"", "https://example.com", "http://ahlyxlabs.com"} {
		if isViewerOrigin(origin) {
			t.Errorf("untrusted viewer origin %q was accepted", origin)
		}
	}
}
