package collect

import (
	"mikrodash/internal/hub"
	"mikrodash/internal/routeros"
	"testing"
	"time"
)

func TestVPNObservationsSurviveDisplayDedupeButNotReadErrors(t *testing.T) {
	f := fakeReader{rows: map[string][]routeros.Reply{vpnPeersCmd.Path: {{"public-key": "key", "name": "Laptop", "last-handshake": "1s", "rx": "100"}}}}
	v := NewVPN(f, hub.Relay{}, 10000)
	samples := 0
	v.SetOnSample(func(at time.Time, rows []routeros.Reply) {
		samples++
		if at.IsZero() || len(rows) != 1 {
			t.Fatal("invalid observation")
		}
	})
	v.RefreshNow()
	v.RefreshNow()
	if samples != 2 {
		t.Fatalf("only %d samples from two successful reads", samples)
	}
	delete(f.rows, vpnPeersCmd.Path)
	v.RefreshNow()
	if samples != 2 {
		t.Fatal("failed poll treated as peer removal")
	}
}

func TestVPNPrefersAuthenticatedSourceIP(t *testing.T) {
	rows, _ := BuildTunnels([]routeros.Reply{{"public-key": "key", "endpoint-address": "configured.example", "current-endpoint-address": "198.51.100.1"}}, nil, time.Now())
	if rows[0].Endpoint != "198.51.100.1" {
		t.Fatalf("source IP: %s", rows[0].Endpoint)
	}
}
