package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"mikrodash/internal/db"
	"mikrodash/internal/routeros"
)

func TestWireGuardHistoryAPIIsScopedToVPNReadPermission(t *testing.T) {
	st := authFixtureWithRouters(t, "wireguard-history-test")
	d, err := db.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = d.UpsertGrant(db.GrantSpec{PrincipalType: "user", PrincipalID: "u-1", ScopeType: "router", ScopeID: "r-A", RoleID: "readonly"}); err != nil {
		t.Fatal(err)
	}
	srv, err := New(st, Options{WebDir: t.TempDir(), AuditDB: d, NoPool: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Shutdown)
	h := srv.Handler()
	login := postLogin(h, "someone", "wireguard-history-test")
	if login.Code != http.StatusOK {
		t.Fatalf("login: %d", login.Code)
	}
	token := strings.SplitN(strings.TrimPrefix(login.Header().Get("Set-Cookie"), "mikrodash_sid="), ";", 2)[0]
	for _, id := range []string{"r-A", "r-B"} {
		if err = d.RecordWireGuard(id, time.Now().UnixMilli(), []routeros.Reply{{"public-key": id, "name": id, "interface": "wg0", "last-handshake": "1s", "current-endpoint-address": "198.51.100.1"}}); err != nil {
			t.Fatal(err)
		}
	}
	const api = "/api/vpn/wireguard/sessions"
	for _, tc := range []struct {
		url, cookie string
		want        int
	}{
		{api + "?routerId=r-A", "", 401},
		{api, token, 400},
		{api + "?routerId=r-B", token, 403},
		{api + "?routerId=unknown", token, 403},
		{api + "?routerId=r-A&limit=0", token, 400},
		{api + "?routerId=r-A&offset=-1", token, 400},
		{api + "?routerId=r-A&limit=201", token, 400},
		{api + "?routerId=r-A", token, 200},
	} {
		got := layoutReq(t, h, "GET", tc.url, "", tc.cookie)
		if got.Code != tc.want {
			t.Errorf("%s: status %d want %d; %s", tc.url, got.Code, tc.want, got.Body.String())
		}
		if tc.want == 200 {
			var result db.WireGuardHistory
			if err = json.Unmarshal(got.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if result.Total != 1 || len(result.Sessions) != 1 || result.Sessions[0].PublicKey != "r-A" || result.RetentionDays != 90 {
				t.Fatalf("foreign history or missing data: %+v", result)
			}
			if got.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("history is cacheable")
			}
		}
	}
	got := layoutReq(t, h, "GET", api+"?routerId=r-A&peer=r-B", "", token)
	var filtered db.WireGuardHistory
	if err = json.Unmarshal(got.Body.Bytes(), &filtered); err != nil || filtered.Total != 0 {
		t.Fatalf("peer filter: %+v %v", filtered, err)
	}
}
