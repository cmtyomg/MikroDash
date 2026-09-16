package db

import (
	"database/sql"
	"encoding/json"
	"errors"

	"mikrodash/internal/routeros"
	"mikrodash/internal/wgsession"
)

const wireGuardDDL = `
CREATE TABLE IF NOT EXISTS wireguard_sessions (
  router_id TEXT NOT NULL, id TEXT NOT NULL, public_key TEXT NOT NULL,
  name TEXT NOT NULL, interface TEXT NOT NULL, allowed_ip TEXT NOT NULL,
  endpoint TEXT NOT NULL, started_at INTEGER NOT NULL, last_seen_at INTEGER NOT NULL,
  ended_at INTEGER, rx INTEGER NOT NULL, tx INTEGER NOT NULL,
  end_reason TEXT NOT NULL, partial INTEGER NOT NULL,
  PRIMARY KEY (router_id, id)
);
CREATE INDEX IF NOT EXISTS wg_sessions_peer ON wireguard_sessions(router_id, public_key, started_at DESC);
CREATE INDEX IF NOT EXISTS wg_sessions_time ON wireguard_sessions(router_id, started_at DESC);
CREATE INDEX IF NOT EXISTS wg_sessions_end ON wireguard_sessions(ended_at);
CREATE TABLE IF NOT EXISTS wireguard_state (
  router_id TEXT PRIMARY KEY, observed_at INTEGER NOT NULL, data TEXT NOT NULL
);`

// RecordWireGuard commits the counter baseline and session changes together.
// A failed write can be retried without losing or counting a byte twice.
func (d *DB) RecordWireGuard(routerID string, now int64, rows []routeros.Reply) error {
	if d == nil || d.sql == nil {
		return errors.New("db not open")
	}
	tx, err := d.sql.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var state wgsession.State
	var raw string
	err = tx.QueryRow(`SELECT data FROM wireguard_state WHERE router_id = ?`, routerID).Scan(&raw)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err == nil {
		if err = json.Unmarshal([]byte(raw), &state); err != nil {
			return err
		}
	}
	next, changed := wgsession.Advance(state, wgsession.Parse(rows), now)
	for _, s := range changed {
		_, err = tx.Exec(`INSERT INTO wireguard_sessions
		 (router_id,id,public_key,name,interface,allowed_ip,endpoint,started_at,last_seen_at,ended_at,rx,tx,end_reason,partial)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		 ON CONFLICT(router_id,id) DO UPDATE SET name=excluded.name, allowed_ip=excluded.allowed_ip,
		 last_seen_at=excluded.last_seen_at, ended_at=excluded.ended_at, rx=excluded.rx, tx=excluded.tx,
		 end_reason=excluded.end_reason, partial=excluded.partial`,
			routerID, s.ID, s.PublicKey, s.Name, s.Interface, s.AllowedIP, s.Endpoint, s.StartedAt, s.LastSeenAt, s.EndedAt, s.RX, s.TX, s.EndReason, s.Partial)
		if err != nil {
			return err
		}
	}
	blob, err := json.Marshal(next)
	if err != nil {
		return err
	}
	_, err = tx.Exec(`INSERT INTO wireguard_state(router_id,observed_at,data) VALUES(?,?,?)
	 ON CONFLICT(router_id) DO UPDATE SET observed_at=excluded.observed_at,data=excluded.data`, routerID, next.At, string(blob))
	if err != nil {
		return err
	}
	return tx.Commit()
}

// SweepWireGuard bounds both stale open sessions and the retained history,
// including routers that have stopped responding or have no peers left.
func (d *DB) SweepWireGuard(now int64) error {
	tx, err := d.sql.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, q := range []struct {
		sql string
		at  int64
	}{
		{`UPDATE wireguard_sessions SET ended_at=last_seen_at,end_reason='monitoring-gap',partial=1
		  WHERE ended_at IS NULL AND router_id IN (SELECT router_id FROM wireguard_state WHERE observed_at < ?)`, now - wgsession.GapMs},
		{`DELETE FROM wireguard_state WHERE observed_at < ?`, now - wgsession.GapMs},
		{`DELETE FROM wireguard_sessions WHERE ended_at < ?`, wgsession.Cutoff(now)},
	} {
		if _, err = tx.Exec(q.sql, q.at); err != nil {
			return err
		}
	}
	return tx.Commit()
}

type WireGuardHistory struct {
	Sessions      []wgsession.Session `json:"sessions"`
	Peers         []WireGuardPeer     `json:"peers"`
	Total         int                 `json:"total"`
	RX            int64               `json:"rx"`
	TX            int64               `json:"tx"`
	ObservedAt    *int64              `json:"observedAt"`
	RetentionDays int                 `json:"retentionDays"`
}

type WireGuardPeer struct {
	PublicKey string `json:"publicKey"`
	Name      string `json:"name"`
}

func (d *DB) WireGuardHistory(routerID, peer string, limit, offset int, now int64) (WireGuardHistory, error) {
	out := WireGuardHistory{Sessions: []wgsession.Session{}, Peers: []WireGuardPeer{}, RetentionDays: wgsession.RetentionDays}
	if limit < 1 || limit > 200 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	// A read transaction keeps the count, totals and page consistent with a poll.
	tx, err := d.sql.Begin()
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	where := ` WHERE router_id=? AND (ended_at IS NULL OR ended_at>=?)`
	args := []any{routerID, wgsession.Cutoff(now)}
	if peer != "" {
		where += ` AND public_key=?`
		args = append(args, peer)
	}
	err = tx.QueryRow(`SELECT COUNT(*),COALESCE(SUM(rx),0),COALESCE(SUM(tx),0) FROM wireguard_sessions`+where, args...).Scan(&out.Total, &out.RX, &out.TX)
	if err != nil {
		return out, err
	}
	rows, err := tx.Query(`SELECT id,public_key,name,interface,allowed_ip,endpoint,started_at,last_seen_at,ended_at,rx,tx,end_reason,partial
	 FROM wireguard_sessions`+where+` ORDER BY started_at DESC,id DESC LIMIT ? OFFSET ?`, append(args, limit, offset)...)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var s wgsession.Session
		if err = rows.Scan(&s.ID, &s.PublicKey, &s.Name, &s.Interface, &s.AllowedIP, &s.Endpoint, &s.StartedAt, &s.LastSeenAt, &s.EndedAt, &s.RX, &s.TX, &s.EndReason, &s.Partial); err != nil {
			rows.Close()
			return out, err
		}
		out.Sessions = append(out.Sessions, s)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	rows, err = tx.Query(`SELECT public_key,name FROM wireguard_sessions WHERE router_id=? AND (ended_at IS NULL OR ended_at>=?)
	 GROUP BY public_key HAVING started_at=MAX(started_at) ORDER BY name,public_key`, routerID, wgsession.Cutoff(now))
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var p WireGuardPeer
		if err = rows.Scan(&p.PublicKey, &p.Name); err != nil {
			rows.Close()
			return out, err
		}
		out.Peers = append(out.Peers, p)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	err = tx.QueryRow(`SELECT observed_at FROM wireguard_state WHERE router_id=?`, routerID).Scan(&out.ObservedAt)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return out, err
	}
	return out, tx.Commit()
}
