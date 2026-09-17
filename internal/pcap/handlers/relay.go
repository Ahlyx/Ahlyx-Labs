package handlers

import (
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/websocket"

	"github.com/Ahlyx/Ahlyx-Labs/internal/pcap"
)

const (
	maxRelayMessage = 64 << 10
	readWait        = 70 * time.Second
	pingEvery       = 50 * time.Second
	writeWait       = 10 * time.Second
	browserProtocol = "ahlyx-relay-v1"
)

var upgrader = websocket.Upgrader{
	HandshakeTimeout: 10 * time.Second,
	Subprotocols:     []string{browserProtocol},
	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		return origin == "" || isViewerOrigin(origin)
	},
}

// HandleRelay authenticates a role before upgrading. The route contains only
// the non-secret session reference: agents use Authorization and browsers use
// a WebSocket subprotocol credential after consuming a URL fragment locally.
func HandleRelay(w http.ResponseWriter, r *http.Request) {
	role, token, ok := relayCredentials(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "relay authentication failed")
		return
	}
	if role == pcap.ViewerRole && !isViewerOrigin(r.Header.Get("Origin")) {
		writeError(w, http.StatusForbidden, "relay origin is not allowed")
		return
	}

	sessionID := chi.URLParam(r, "session_id")
	sess, ok := pcap.Store.Reserve(sessionID, role, token)
	if !ok {
		writeError(w, http.StatusUnauthorized, "relay authentication failed")
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		sess.Release(role)
		return
	}
	if role == pcap.AgentRole {
		relayAgent(conn, sessionID, sess)
		return
	}
	relayBrowser(conn, sessionID, sess)
}

func relayCredentials(r *http.Request) (pcap.RelayRole, string, bool) {
	if authorization := r.Header.Get("Authorization"); strings.HasPrefix(authorization, "Bearer ") {
		token := strings.TrimPrefix(authorization, "Bearer ")
		return pcap.AgentRole, token, token != ""
	}

	protocols := websocket.Subprotocols(r)
	if len(protocols) == 2 && protocols[0] == browserProtocol && protocols[1] != "" {
		return pcap.ViewerRole, protocols[1], true
	}
	return "", "", false
}

func isViewerOrigin(origin string) bool {
	return origin == "https://ahlyxlabs.com" || origin == "https://www.ahlyxlabs.com"
}

func relayAgent(conn *websocket.Conn, sessionID string, sess *pcap.RelaySession) {
	sess.SetAgent(conn)
	defer func() {
		pcap.Store.Delete(sessionID)
	}()
	serveRelayConnection(conn, sess, func(messageType int, msg []byte) bool {
		if messageType != websocket.TextMessage {
			return false
		}
		sess.Forward(msg)
		return true
	})
}

func relayBrowser(conn *websocket.Conn, sessionID string, sess *pcap.RelaySession) {
	sess.SetBrowserAndFlush(conn)
	defer func() {
		pcap.Store.Delete(sessionID)
	}()
	// The viewer is receive-only. Reading is retained for lifecycle handling and
	// automatic pong processing, but application data from it is rejected.
	serveRelayConnection(conn, sess, func(messageType int, _ []byte) bool {
		return messageType == websocket.CloseMessage
	})
}

func serveRelayConnection(conn *websocket.Conn, sess *pcap.RelaySession, handle func(int, []byte) bool) {
	conn.SetReadLimit(maxRelayMessage)
	_ = conn.SetReadDeadline(time.Now().Add(readWait))
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(readWait))
	})

	done := make(chan struct{})
	stop := make(chan struct{})
	go func() {
		ticker := time.NewTicker(pingEvery)
		defer ticker.Stop()
		defer close(done)
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				if err := conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(writeWait)); err != nil {
					return
				}
			}
		}
	}()
	defer func() {
		close(stop)
		_ = conn.Close()
		<-done
	}()

	for {
		messageType, msg, err := conn.ReadMessage()
		if err != nil || !handle(messageType, msg) {
			return
		}
		sess.Touch()
	}
}
