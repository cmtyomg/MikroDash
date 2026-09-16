package wgsession

import (
	"mikrodash/internal/routeros"
	"testing"
)

func testPeer() Peer {
	return Peer{Key: "peer-key", Name: "Laptop", Interface: "wg0", Endpoint: "198.51.100.1", RX: 1_000_000, TX: 2_000_000, HandshakeMs: 1000}
}

func TestTrafficBaselineIdleAndReconnect(t *testing.T) {
	p := testPeer()
	state, sessions := Advance(State{}, []Peer{p}, 1_000_000)
	if len(sessions) != 1 || sessions[0].RX != 0 || !sessions[0].Partial {
		t.Fatalf("lifetime bytes attributed to session: %+v", sessions)
	}
	id := sessions[0].ID
	p.RX += 123
	p.TX += 456
	state, sessions = Advance(state, []Peer{p}, 1_010_000)
	if sessions[0].ID != id || sessions[0].RX != 123 || sessions[0].TX != 456 {
		t.Fatalf("wrong deltas: %+v", sessions)
	}
	// Receive activity keeps the session alive even if handshake age is stale.
	p.HandshakeMs = 600_000
	state, sessions = Advance(state, []Peer{p}, 1_020_000)
	if sessions[0].EndedAt != nil {
		t.Fatal("receive activity was forgotten between polls")
	}
	for now := int64(1_030_000); now <= 1_190_000; now += 10_000 {
		state, sessions = Advance(state, []Peer{p}, now)
	}
	if sessions[0].EndReason != "inactive" || sessions[0].RX != 123 {
		t.Fatalf("did not end at idle threshold: %+v", sessions)
	}
	p.HandshakeMs = 0
	p.RX += 10
	_, sessions = Advance(state, []Peer{p}, 1_200_000)
	if len(sessions) != 1 || sessions[0].ID == id || sessions[0].RX != 10 || sessions[0].Partial {
		t.Fatalf("bad reconnection: %+v", sessions)
	}
}

func TestUncertainBoundariesDoNotInventTraffic(t *testing.T) {
	for _, reason := range []string{"endpoint-changed", "counter-reset", "monitoring-gap", "removed", "disabled"} {
		t.Run(reason, func(t *testing.T) {
			p := testPeer()
			state, _ := Advance(State{}, []Peer{p}, 1_000_000)
			now := int64(1_010_000)
			p.RX += 100
			switch reason {
			case "endpoint-changed":
				p.Endpoint = "2001:db8::1"
			case "counter-reset":
				p.RX = 50
				p.TX = 100
			case "monitoring-gap":
				now += GapMs
			case "disabled":
				p.Disabled = true
			}
			peers := []Peer{p}
			if reason == "removed" {
				peers = nil
			}
			_, rows := Advance(state, peers, now)
			if len(rows) == 0 || rows[0].EndReason != reason || rows[0].EndedAt == nil {
				t.Fatalf("boundary missing: %+v", rows)
			}
			if reason != "removed" && reason != "disabled" && (len(rows) != 2 || rows[1].RX != 0 || !rows[1].Partial) {
				t.Fatalf("invented interval traffic: %+v", rows)
			}
			if state.Peers["wg0\x00peer-key"].Session.EndedAt != nil {
				t.Fatal("input mutated")
			}
		})
	}
}

func TestNeverStaleDisabledAndTransmitAloneDoNotConnect(t *testing.T) {
	for _, age := range []int64{-1, IdleMs, 600_000} {
		p := testPeer()
		p.HandshakeMs = age
		state, rows := Advance(State{}, []Peer{p}, 1_000_000)
		if len(rows) != 0 {
			t.Fatal("stale peer connected")
		}
		p.TX += 1000
		_, rows = Advance(state, []Peer{p}, 1_010_000)
		if len(rows) != 0 {
			t.Fatal("transmit alone invented a connection")
		}
	}
}

func TestPeerIdentityIncludesInterfaceAndSamplesAreIdempotent(t *testing.T) {
	a, b := testPeer(), testPeer()
	b.Interface = "wg1"
	state, rows := Advance(State{}, []Peer{a, b}, 1_000_000)
	if len(rows) != 2 || rows[0].ID == rows[1].ID {
		t.Fatal("different interfaces conflated")
	}
	_, rows = Advance(state, []Peer{a, b}, 1_000_000)
	if len(rows) != 0 {
		t.Fatal("duplicate observation written")
	}
}

func TestParseAuthenticatedEndpointAndLargeCounters(t *testing.T) {
	rows := []routeros.Reply{{"public-key": "key", "comment": " phone ", "current-endpoint-address": "2001:db8::1", "endpoint-address": "wrong.example", "rx-bytes": "5000000000", "tx": "7000000000", "last-handshake": "1m2s"}}
	p := Parse(rows)[0]
	if p.Endpoint != "2001:db8::1" || p.RX != 5_000_000_000 || p.TX != 7_000_000_000 || p.HandshakeMs != 62000 || p.Name != "phone" {
		t.Fatalf("%+v", p)
	}
	delete(rows[0], "current-endpoint-address")
	if Parse(rows)[0].Endpoint != "" {
		t.Fatal("configured hostname presented as observed IP")
	}
	for _, raw := range []string{"never", "", "broken", "1ms", "-1"} {
		if handshakeMs(raw) != -1 {
			t.Errorf("%q is valid", raw)
		}
	}
}
