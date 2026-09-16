package server

import (
	"log"
	"net/http"
	"strconv"
	"time"

	"mikrodash/internal/routeros"
)

func (s *Server) startWireGuardHistory() {
	if s.auditDB == nil {
		return
	}
	s.sessions.SetVPNSample(func(routerID string, at time.Time, rows []routeros.Reply) {
		if err := s.auditDB.RecordWireGuard(routerID, at.UnixMilli(), rows); err != nil {
			log.Printf("[wireguard] recording %s: %v", routerID, err)
		}
	})
	sweep := func() {
		if err := s.auditDB.SweepWireGuard(time.Now().UnixMilli()); err != nil {
			log.Printf("[wireguard] retention/expired observations: %v", err)
		}
	}
	sweep()
	s.wgStop, s.wgDone = make(chan struct{}), make(chan struct{})
	go func() {
		defer close(s.wgDone)
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-s.wgStop:
				return
			case <-ticker.C:
				sweep()
			}
		}
	}()
}

func (s *Server) registerWireGuardHistory(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/vpn/wireguard/sessions", s.wireGuardHistory)
}

func (s *Server) wireGuardHistory(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	sess, err := s.auth.Validate(r.Header.Get("Cookie"))
	if err != nil {
		writeJSONErr(w, http.StatusUnauthorized, "not signed in")
		return
	}
	q := r.URL.Query()
	routerID := q.Get("routerId")
	if routerID == "" {
		writeJSONErr(w, http.StatusBadRequest, "routerId required")
		return
	}
	if sess.AuthMode != "none" {
		if !sess.CanPage("vpn", "read", routerID) {
			writeJSONErr(w, http.StatusForbidden, "Not permitted")
			return
		}
		if s.rbac.Available() && !permitted(s.rbac.CanPage(s.userIDFor(sess.Username), "vpn", "read", routerID)) {
			writeJSONErr(w, http.StatusForbidden, "Not permitted")
			return
		}
	}
	if s.auditDB == nil {
		writeJSONErr(w, http.StatusServiceUnavailable, "history unavailable")
		return
	}
	limit, offset := 50, 0
	for key, dst := range map[string]*int{"limit": &limit, "offset": &offset} {
		if raw := q.Get(key); raw != "" {
			n, err := strconv.Atoi(raw)
			if err != nil || n < 0 || (key == "limit" && (n < 1 || n > 200)) || (key == "offset" && n > 1_000_000) {
				writeJSONErr(w, http.StatusBadRequest, "invalid pagination")
				return
			}
			*dst = n
		}
	}
	history, err := s.auditDB.WireGuardHistory(routerID, q.Get("peer"), limit, offset, time.Now().UnixMilli())
	if err != nil {
		log.Printf("[wireguard] reading history: %v", err)
		writeJSONErr(w, http.StatusInternalServerError, "history unavailable")
		return
	}
	writeJSON(w, history)
}
