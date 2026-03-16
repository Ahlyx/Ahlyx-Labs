package handlers

import (
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/websocket"

	"github.com/Ahlyx/Ahlyx-Labs/internal/pcap"
)

var upgrader = websocket.Upgrader{
	HandshakeTimeout: 10 * time.Second,
	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		return origin == "https://ahlyxlabs.com" ||
			origin == "https://www.ahlyxlabs.com" ||
			origin == ""
	},
}

// HandleRelay upgrades the request to a WebSocket connection and wires it
// into the relay session identified by {session_id}.
//
//	GET /ws/relay/{session_id}?role=agent
//	GET /ws/relay/{session_id}?role=browser
//
// The agent side reads frames and forwards them to the browser. The browser
// side holds the connection open so disconnects are detected promptly. Either
// side disconnecting closes both connections and removes the session.
func HandleRelay(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "session_id")
	role := r.URL.Query().Get("role")

	if role != "agent" && role != "browser" {
		writeError(w, http.StatusBadRequest, "role must be agent or browser")
		return
	}

	sess, ok := pcap.Store.Get(sessionID)
	if !ok {
		writeError(w, http.StatusNotFound, "session not found")
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("pcap relay: upgrade error session=%s role=%s: %v", sessionID, role, err)
		return
	}

	switch role {
	case "agent":
		relayAgent(conn, sessionID, sess)
	case "browser":
		relayBrowser(conn, sessionID, sess)
	}
}

func relayAgent(conn *websocket.Conn, sessionID string, sess *pcap.RelaySession) {
	sess.SetAgent(conn)
	defer func() {
		sess.CloseBoth()
		pcap.Store.Delete(sessionID)
		log.Printf("pcap relay: agent disconnected  session=%s", sessionID)
	}()

	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			break
		}
		sess.Forward(msg)
	}
}

func relayBrowser(conn *websocket.Conn, sessionID string, sess *pcap.RelaySession) {
	sess.SetBrowserAndFlush(conn)
	defer func() {
		sess.CloseBoth()
		pcap.Store.Delete(sessionID)
		log.Printf("pcap relay: browser disconnected session=%s", sessionID)
	}()

	// Browser sends nothing meaningful; loop just to detect disconnects.
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			break
		}
	}
}
