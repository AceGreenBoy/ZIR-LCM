package core

import (
	"context"

	"github.com/jackc/pgx/v5"

	"zir/lcm/internal/audit"
	"zir/lcm/internal/db"
)

type pgxTx = pgx.Tx

const (
	RoleSuperadmin   = "superadmin"
	RoleAdmin        = "admin"
	RoleManufacturer = "manufacturer"
	RoleEngineer     = "engineer"
)

// Actor is the signed-in person performing an action.
type Actor struct {
	UserID string
	Login  string
	Name   string
	Roles  map[string]bool
	IP     string
}

// Has reports whether the actor has any of the roles. superadmin has every right.
func (a Actor) Has(roles ...string) bool {
	if a.Roles[RoleSuperadmin] {
		return true
	}
	for _, r := range roles {
		if a.Roles[r] {
			return true
		}
	}
	return false
}

func (a Actor) require(roles ...string) error {
	if !a.Has(roles...) {
		return userErr(403, "forbidden", "недостатньо прав")
	}
	return nil
}

func (a Actor) audit(ctx context.Context, q db.Q, action, targetType, targetID string, details any) error {
	return audit.Log(ctx, q, audit.Entry{
		ActorType: "user", ActorID: audit.Str(a.UserID), Action: action,
		TargetType: targetType, TargetID: audit.Str(targetID), Details: details, IP: a.IP,
	})
}

func deviceAudit(ctx context.Context, q db.Q, deviceID, action string, details any, ip string) error {
	return audit.Log(ctx, q, audit.Entry{
		ActorType: "device", ActorID: audit.Str(deviceID), Action: action,
		TargetType: "device", TargetID: audit.Str(deviceID), Details: details, IP: ip,
	})
}

func anomaly(ctx context.Context, q db.Q, deviceID, typ string, details any) error {
	var dev *string
	if deviceID != "" {
		dev = &deviceID
	}
	_, err := q.Exec(ctx, `INSERT INTO anomalies (device_id, type, details) VALUES ($1,$2,$3)`, dev, typ, details)
	return err
}
