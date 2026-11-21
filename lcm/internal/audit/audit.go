// Package audit appends to the append-only audit_log.
package audit

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/netip"

	"zir/lcm/internal/db"
)

type Entry struct {
	ActorType  string // user | device | system
	ActorID    *string
	Action     string
	TargetType string
	TargetID   *string
	Details    any
	IP         string
}

// Log writes an entry. It is called inside the transaction of the action, so
// the action and its audit record commit together.
func Log(ctx context.Context, q db.Q, e Entry) error {
	var details []byte
	if e.Details != nil {
		var err error
		if details, err = json.Marshal(e.Details); err != nil {
			return err
		}
	}
	var ip *netip.Addr
	if a, err := netip.ParseAddr(e.IP); err == nil {
		ip = &a
	}
	var targetType *string
	if e.TargetType != "" {
		targetType = &e.TargetType
	}
	_, err := q.Exec(ctx, `INSERT INTO audit_log (actor_type, actor_id, action, target_type, target_id, details, ip)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`, e.ActorType, e.ActorID, e.Action, targetType, e.TargetID, details, ip)
	if err != nil {
		slog.Error("audit write failed", "action", e.Action, "err", err)
	}
	return err
}

// Str is a helper for optional ids.
func Str(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
