package handlers

import (
	"net/http"

	"github.com/Ahlyx/Ahlyx-Labs/internal/pcap"
	"github.com/Ahlyx/Ahlyx-Labs/internal/shared"
)

// NewSession creates a relay session and returns its ID and WebSocket URL.
//
//	GET /api/v1/pcap/session
func NewSession(w http.ResponseWriter, r *http.Request) {
	id := pcap.Store.Create()
	shared.LogQuery("pcap", "session", "", false, 0, 0, 0, 0)
	writeJSON(w, http.StatusOK, map[string]string{
		"session_id": id,
		"relay_url":  "wss://api.ahlyxlabs.com/ws/relay/" + id,
	})
}
