// Package wgsession derives observed WireGuard sessions from successful polls.
// WireGuard has no connect/disconnect events: these intervals are estimates.
package wgsession

import (
	"crypto/sha256"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"mikrodash/internal/routeros"
)

const (
	IdleMs        = int64(180_000)
	GapMs         = int64(90_000) // maximum collector cadence is 30 seconds
	RetentionDays = 90
)

type Peer struct {
	Key, Name, Interface, AllowedIP, Endpoint string
	RX, TX                                    int64
	HandshakeMs                               int64 // age; -1 means absent or invalid
	Disabled                                  bool
}

type Session struct {
	ID         string `json:"id"`
	PublicKey  string `json:"publicKey"`
	Name       string `json:"name"`
	Interface  string `json:"interface"`
	AllowedIP  string `json:"allowedIp"`
	Endpoint   string `json:"endpoint"`
	StartedAt  int64  `json:"startedAt"`
	LastSeenAt int64  `json:"lastSeenAt"`
	EndedAt    *int64 `json:"endedAt"`
	RX         int64  `json:"rx"` // received by the router (uploaded by the peer)
	TX         int64  `json:"tx"` // sent by the router (downloaded by the peer)
	EndReason  string `json:"endReason"`
	Partial    bool   `json:"partial"`
}

type State struct {
	At    int64                `json:"at"`
	Peers map[string]PeerState `json:"peers"`
}

type PeerState struct {
	RX, TX     int64
	ActivityAt int64
	Session    *Session
}

// Advance does not mutate its input. Counter baselines survive server restarts
// in the database. Bytes before the first observation are never attributed to
// a session, nor are deltas across an unknown monitoring interval or IP change.
func Advance(prev State, peers []Peer, now int64) (State, []Session) {
	if now <= prev.At {
		return prev, nil
	}
	next := State{At: now, Peers: make(map[string]PeerState, len(peers))}
	var changed []Session
	gap := prev.At > 0 && now-prev.At > GapMs
	closeSession := func(s *Session, reason string, partial bool) {
		end := s.LastSeenAt
		s.EndedAt, s.EndReason = &end, reason
		s.Partial = s.Partial || partial
		changed = append(changed, *s)
	}
	for _, p := range peers {
		if p.Key == "" {
			continue
		}
		key := p.Interface + "\x00" + p.Key
		old, known := prev.Peers[key]
		var active *Session
		if old.Session != nil {
			copy := *old.Session
			active = &copy
		}
		reset := known && (p.RX < old.RX || p.TX < old.TX)
		roamed := active != nil && active.Endpoint != p.Endpoint
		if active != nil {
			switch {
			case gap:
				closeSession(active, "monitoring-gap", true)
				active = nil
			case reset:
				closeSession(active, "counter-reset", true)
				active = nil
			case roamed:
				closeSession(active, "endpoint-changed", true)
				active = nil
			}
		}
		continuous := known && !gap && !reset && !roamed
		rxDelta, txDelta := int64(0), int64(0)
		if continuous {
			rxDelta, txDelta = p.RX-old.RX, p.TX-old.TX
		}
		activity := int64(0)
		if continuous {
			activity = old.ActivityAt
		}
		if p.HandshakeMs >= 0 {
			activity = max(activity, now-p.HandshakeMs)
		}
		if rxDelta > 0 {
			activity = now
		}
		live := !p.Disabled && activity > 0 && now-activity < IdleMs
		if active == nil && live {
			id := fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%s:%d", key, now))))
			active = &Session{ID: id, PublicKey: p.Key, Name: p.Name, Interface: p.Interface,
				AllowedIP: p.AllowedIP, Endpoint: p.Endpoint, StartedAt: now,
				LastSeenAt: now, Partial: !continuous}
			if continuous {
				active.StartedAt = prev.At
			}
		}
		if active != nil {
			active.Name, active.AllowedIP = p.Name, p.AllowedIP
			active.RX += rxDelta
			active.TX += txDelta
			if live {
				active.LastSeenAt = now
				changed = append(changed, *active)
			} else {
				reason := "inactive"
				if p.Disabled {
					reason = "disabled"
				}
				closeSession(active, reason, false)
				active = nil
			}
		}
		next.Peers[key] = PeerState{RX: p.RX, TX: p.TX, ActivityAt: activity, Session: active}
	}
	for key, old := range prev.Peers {
		if _, exists := next.Peers[key]; !exists && old.Session != nil {
			copy := *old.Session
			reason := "removed"
			if gap {
				reason = "monitoring-gap"
			}
			closeSession(&copy, reason, true)
		}
	}
	return next, changed
}

var durationPart = regexp.MustCompile(`(\d+(?:\.\d+)?)([wdhms])`)

func handshakeMs(raw string) int64 {
	if raw == "" || raw == "never" {
		return -1
	}
	if n, err := strconv.ParseFloat(raw, 64); err == nil && n >= 0 {
		return int64(n * 1000)
	}
	parts := durationPart.FindAllStringSubmatch(raw, -1)
	units := map[string]float64{"w": 604800, "d": 86400, "h": 3600, "m": 60, "s": 1}
	total, consumed := float64(0), ""
	for _, p := range parts {
		n, _ := strconv.ParseFloat(p[1], 64)
		total += n * units[p[2]]
		consumed += p[0]
	}
	if consumed != raw || len(parts) == 0 {
		return -1
	}
	return int64(total * 1000)
}

// Parse uses the authenticated source IP, never the configured endpoint hostname.
// https://help.mikrotik.com/docs/spaces/ROS/pages/69664792/WireGuard
func Parse(rows []routeros.Reply) []Peer {
	peers := make([]Peer, 0, len(rows))
	for _, r := range rows {
		counter := func(primary, alias string) int64 {
			v := r[primary]
			if v == "" {
				v = r[alias]
			}
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil || n < 0 {
				return 0
			}
			return n
		}
		name := strings.TrimSpace(r["name"])
		if name == "" {
			name = strings.TrimSpace(r["comment"])
		}
		if name == "" {
			name = r["allowed-address"]
		}
		endpoint := ""
		if ip, err := netip.ParseAddr(r["current-endpoint-address"]); err == nil && !ip.IsUnspecified() {
			endpoint = ip.String()
		}
		peers = append(peers, Peer{Key: r["public-key"], Name: name, Interface: r["interface"],
			AllowedIP: r["allowed-address"], Endpoint: endpoint, RX: counter("rx", "rx-bytes"),
			TX: counter("tx", "tx-bytes"), HandshakeMs: handshakeMs(r["last-handshake"]),
			Disabled: r["disabled"] == "true" || r["disabled"] == "yes"})
	}
	return peers
}

func Cutoff(now int64) int64 { return now - int64(RetentionDays*24*time.Hour/time.Millisecond) }
