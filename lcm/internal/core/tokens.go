package core

import (
	"context"
	"crypto/sha256"
	"strings"
	"time"

	"zir/lcm/internal/db"
)

// API tokens let lcmctl push-dev (from a developer's machine or PlatformIO)
// upload and assign dev builds without the browser login. A token acts as its
// owner with the owner's current roles, and the API it opens is limited to
// dev builds (internal/httpapi/admin.go).

const (
	apiTokenTTL    = 90 * 24 * time.Hour
	apiTokenPrefix = "zirlcm_"
)

type APIToken struct {
	ID, Name, Login string
	CreatedAt       time.Time
	ExpiresAt       time.Time
	LastUsed        *time.Time
	LastIP          string
	Revoked         bool
}

func hashAPIToken(t string) []byte {
	s := sha256.Sum256([]byte(t))
	return s[:]
}

// CreateAPIToken returns the token once; only its hash is stored.
func (c *Core) CreateAPIToken(ctx context.Context, a Actor, name string) (string, error) {
	if !a.Roles[RoleSuperadmin] {
		return "", userErr(403, "forbidden", "лише superadmin")
	}
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 64 {
		return "", userErr(400, "bad_name", "вкажіть назву токена (до 64 символів), наприклад «ноутбук Сергія»")
	}
	tok := apiTokenPrefix + b64.EncodeToString(randBytes(32))
	err := db.InTx(ctx, c.Pool, func(tx pgxTx) error {
		var id string
		if err := tx.QueryRow(ctx, `INSERT INTO api_tokens (user_id, name, token_hash, expires_at) VALUES ($1,$2,$3,$4) RETURNING id`,
			a.UserID, name, hashAPIToken(tok), c.Now().Add(apiTokenTTL)).Scan(&id); err != nil {
			return err
		}
		return a.audit(ctx, tx, "api_token.create", "api_token", id, map[string]any{"name": name})
	})
	return tok, err
}

func (c *Core) APITokens(ctx context.Context, a Actor) ([]APIToken, error) {
	if !a.Roles[RoleSuperadmin] {
		return nil, userErr(403, "forbidden", "лише superadmin")
	}
	rows, err := c.Pool.Query(ctx, `SELECT t.id, t.name, u.login, t.created_at, t.expires_at, t.last_used_at,
		COALESCE(host(t.last_ip),''), t.revoked_at IS NOT NULL
		FROM api_tokens t JOIN users u ON u.id=t.user_id ORDER BY t.created_at DESC LIMIT 100`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []APIToken
	for rows.Next() {
		var t APIToken
		if err := rows.Scan(&t.ID, &t.Name, &t.Login, &t.CreatedAt, &t.ExpiresAt, &t.LastUsed, &t.LastIP, &t.Revoked); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (c *Core) RevokeAPIToken(ctx context.Context, a Actor, id string) error {
	if !a.Roles[RoleSuperadmin] {
		return userErr(403, "forbidden", "лише superadmin")
	}
	return db.InTx(ctx, c.Pool, func(tx pgxTx) error {
		if _, err := tx.Exec(ctx, `UPDATE api_tokens SET revoked_at=now() WHERE id::text=$1 AND revoked_at IS NULL`, id); err != nil {
			return err
		}
		return a.audit(ctx, tx, "api_token.revoke", "api_token", id, nil)
	})
}

// TokenActor resolves an API token to its owner.
func (c *Core) TokenActor(ctx context.Context, tok, ip string) (Actor, error) {
	bad := userErr(401, "bad_token", "токен недійсний, відкликаний або прострочений")
	if !strings.HasPrefix(tok, apiTokenPrefix) {
		return Actor{}, bad
	}
	a := Actor{Roles: map[string]bool{}, IP: ip}
	var id, status string
	err := c.Pool.QueryRow(ctx, `SELECT t.id, u.id, u.login, u.display_name, u.status FROM api_tokens t JOIN users u ON u.id=t.user_id
		WHERE t.token_hash=$1 AND t.revoked_at IS NULL AND t.expires_at > $2`, hashAPIToken(tok), c.Now()).
		Scan(&id, &a.UserID, &a.Login, &a.Name, &status)
	if db.IsNoRows(err) {
		return Actor{}, bad
	}
	if err != nil {
		return Actor{}, err
	}
	if status != "active" {
		return Actor{}, bad
	}
	rows, err := c.Pool.Query(ctx, `SELECT role FROM user_roles WHERE user_id=$1`, a.UserID)
	if err != nil {
		return Actor{}, err
	}
	for rows.Next() {
		var r string
		rows.Scan(&r)
		a.Roles[r] = true
	}
	rows.Close()
	c.Pool.Exec(ctx, `UPDATE api_tokens SET last_used_at=now(), last_ip=$2 WHERE id=$1`, id, parseIP(ip))
	return a, nil
}
