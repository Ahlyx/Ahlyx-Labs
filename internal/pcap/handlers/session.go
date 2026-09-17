package handlers

import (
	"net/http"

	"github.com/Ahlyx/Ahlyx-Labs/internal/pcap"
	"github.com/Ahlyx/Ahlyx-Labs/internal/shared"
)

// NewSession creates a relay session and returns role-specific credentials.
//
//	GET /api/v1/pcap/session
func NewSession(w http.ResponseWriter, r *http.Request) {
	credentials, err := pcap.Store.Create()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "relay session is temporarily unavailable")
		return
	}
	shared.LogQuery("pcap", "session", "", false, 0, 0, 0, 0)
	writeJSON(w, http.StatusOK, map[string]string{
		"session_id":   credentials.SessionID,
		"relay_url":    "wss://api.ahlyxlabs.com/ws/relay/" + credentials.SessionID,
		"agent_token":  credentials.AgentToken,
		"viewer_token": credentials.ViewerToken,
	})
}
