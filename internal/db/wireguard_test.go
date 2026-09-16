package db

import (
	"mikrodash/internal/routeros"
	"mikrodash/internal/wgsession"
	"testing"
)

func wgRows(rx, ip string) []routeros.Reply {
	return []routeros.Reply{{"public-key": "test-key", "interface": "wg0", "name": "Laptop", "current-endpoint-address": ip, "rx": rx, "tx": "2000", "last-handshake": "1s"}}
}

func TestWireGuardPersistencePaginationIsolationAndRetention(t *testing.T) {
	dir := t.TempDir()
	d, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	record := func(id string, at int64, rx, ip string) {
		t.Helper()
		if err := d.RecordWireGuard(id, at, wgRows(rx, ip)); err != nil {
			t.Fatal(err)
		}
	}
	record("r1", 1_000_000, "1000", "198.51.100.1")
	record("r1", 1_010_000, "1123", "198.51.100.1")
	d.Close()
	d, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	record("r1", 1_020_000, "1200", "198.51.100.1")
	record("r2", 1_020_000, "999999", "198.51.100.1")
	h, err := d.WireGuardHistory("r1", "test-key", 50, 0, 1_020_000)
	if err != nil || h.Total != 1 || h.RX != 200 || len(h.Sessions) != 1 || h.ObservedAt == nil {
		t.Fatalf("history after restart: %+v %v", h, err)
	}
	record("r1", 1_030_000, "1300", "198.51.100.2")
	h, err = d.WireGuardHistory("r1", "", 1, 1, 1_030_000)
	if err != nil || h.Total != 2 || len(h.Sessions) != 1 || h.Sessions[0].EndReason != "endpoint-changed" || h.RX != 200 {
		t.Fatalf("pagination: %+v %v", h, err)
	}
	if err = d.SweepWireGuard(1_200_000); err != nil {
		t.Fatal(err)
	}
	h, err = d.WireGuardHistory("r1", "", 50, 0, 1_200_000)
	if err != nil || h.Sessions[0].EndReason != "monitoring-gap" || h.ObservedAt != nil {
		t.Fatalf("gap: %+v %v", h, err)
	}
	record("r1", 1_210_000, "2000", "198.51.100.2")
	h, err = d.WireGuardHistory("r1", "", 50, 0, 1_210_000)
	if err != nil || h.Total != 3 || h.RX != 200 {
		t.Fatalf("gap bytes were counted: %+v %v", h, err)
	}
	if err = d.SweepWireGuard(1_300_000 + int64(wgsession.RetentionDays)*86400000); err != nil {
		t.Fatal(err)
	}
	h, err = d.WireGuardHistory("r1", "", 50, 0, 1_300_000+int64(wgsession.RetentionDays)*86400000)
	if err != nil || h.Total != 0 {
		t.Fatalf("retention: %+v %v", h, err)
	}
}

func TestWireGuardMigrationFromExistingDatabase(t *testing.T) {
	d := openTest(t, newDB(t, 16, true))
	n, err := d.Migrate()
	if err != nil || n != 1 {
		t.Fatalf("migration: %d %v", n, err)
	}
	if err = d.RecordWireGuard("r1", 1_000_000, wgRows("100", "198.51.100.1")); err != nil {
		t.Fatal(err)
	}
	n, err = d.Migrate()
	if err != nil || n != 0 {
		t.Fatalf("migration repeated: %d %v", n, err)
	}
}
