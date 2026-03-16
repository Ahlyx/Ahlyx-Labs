package handlers

import (
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	"golang.org/x/net/websocket"

	"github.com/Ahlyx/Ahlyx-Labs/internal/pcap"
)

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

	srv := websocket.Server{
		// Accept all origins; the chi CORS middleware handles origin
		// enforcement at the HTTP layer before we reach this handler.
		Handshake: func(_ *websocket.Config, _ *http.Request) error {
			return nil
		},
		Handler: websocket.Handler(func(ws *websocket.Conn) {
			switch role {
			case "agent":
				relayAgent(ws, sessionID, sess)
			case "browser":
				relayBrowser(ws, sessionID, sess)
			}
		}),
	}
	srv.ServeHTTP(w, r)
}

func relayAgent(ws *websocket.Conn, sessionID string, sess *pcap.RelaySession) {
	sess.SetAgent(ws)
	defer func() {
		sess.CloseBoth()
		pcap.Store.Delete(sessionID)
		log.Printf("pcap relay: agent disconnected  session=%s", sessionID)
	}()

	for {
		var msg []byte
		if err := websocket.Message.Receive(ws, &msg); err != nil {
			break
		}
		sess.Forward(msg)
	}
}

func relayBrowser(ws *websocket.Conn, sessionID string, sess *pcap.RelaySession) {
	sess.SetBrowserAndFlush(ws)
	defer func() {
		sess.CloseBoth()
		pcap.Store.Delete(sessionID)
		log.Printf("pcap relay: browser disconnected session=%s", sessionID)
	}()

	// Browser sends nothing meaningful; loop just to detect disconnects.
	for {
		var msg []byte
		if err := websocket.Message.Receive(ws, &msg); err != nil {
			break
		}
	}
}
