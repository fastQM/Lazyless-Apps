package socialapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"ClawdCity-Apps/internal/social"
)

type Server struct {
	m *social.Manager
}

func NewServer(m *social.Manager) *Server {
	return &Server{m: m}
}

func (s *Server) Register(mux *http.ServeMux) {
	mux.HandleFunc("/api/social/v1/state", s.handleState)
	mux.HandleFunc("/api/social/v1/stream", s.handleStream)
	mux.HandleFunc("/api/social/v1/init", s.handleInit)
	mux.HandleFunc("/api/social/v1/unlock", s.handleUnlock)
	mux.HandleFunc("/api/social/v1/profile", s.handleProfile)
	mux.HandleFunc("/api/social/v1/broadcast", s.handleBroadcast)
	mux.HandleFunc("/api/social/v1/friends/request", s.handleRequest)
	mux.HandleFunc("/api/social/v1/friends/respond", s.handleRespond)
	mux.HandleFunc("/api/social/v1/friends/invite", s.handleInvite)
	mux.HandleFunc("/api/social/v1/friends/request-by-invite", s.handleRequestByInvite)
	mux.HandleFunc("/api/social/v1/messages/send", s.handleSendMessage)
	mux.HandleFunc("/api/social/v1/messages/", s.handleConversation)
}

func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming not supported")
		return
	}
	ch, cancel := s.m.SubscribeEvents()
	defer cancel()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("event: ready\ndata: {}\n\n"))
	flusher.Flush()

	for {
		select {
		case <-r.Context().Done():
			return
		case event, ok := <-ch:
			if !ok {
				return
			}
			if _, err := w.Write([]byte(fmt.Sprintf("event: %s\ndata: {}\n\n", event))); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, s.m.Snapshot())
}

func (s *Server) handleInit(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		writeNoContent(w)
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		Username   string          `json:"username"`
		Bio        string          `json:"bio"`
		AvatarData string          `json:"avatar_data"`
		Passphrase string          `json:"passphrase"`
		Settings   social.Settings `json:"settings"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	p, err := s.m.Init(req.Username, req.Bio, req.AvatarData, req.Passphrase, req.Settings)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"me": p})
}

func (s *Server) handleUnlock(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		writeNoContent(w)
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		Passphrase string `json:"passphrase"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if err := s.m.Unlock(req.Passphrase); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleProfile(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		writeNoContent(w)
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		Username   string          `json:"username"`
		Bio        string          `json:"bio"`
		AvatarData string          `json:"avatar_data"`
		Settings   social.Settings `json:"settings"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	p, err := s.m.UpdateProfile(req.Username, req.Bio, req.AvatarData, req.Settings)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"me": p})
}

func (s *Server) handleBroadcast(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		Text string `json:"text"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if err := s.m.Broadcast(req.Text); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		TargetUserID string `json:"target_user_id"`
		Message      string `json:"message"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if err := s.m.SendFriendRequest(req.TargetUserID, req.Message, "discover"); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleRespond(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		RequestID string `json:"request_id"`
		Accept    bool   `json:"accept"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if err := s.m.RespondFriendRequest(req.RequestID, req.Accept); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleInvite(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	token, err := s.m.CreateInviteLink()
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"token": token})
}

func (s *Server) handleRequestByInvite(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		Token   string `json:"token"`
		Message string `json:"message"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if err := s.m.SendFriendRequestByInvite(req.Token, req.Message); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleSendMessage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		ToUserID string `json:"to_user_id"`
		Body     string `json:"body"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if err := s.m.SendDirectMessage(req.ToUserID, req.Body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleConversation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	userID := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/social/v1/messages/"), "/")
	if userID == "" {
		writeError(w, http.StatusBadRequest, "user id required")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"messages": s.m.Conversation(userID)})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": msg})
}

func writeNoContent(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
	w.WriteHeader(http.StatusNoContent)
}
