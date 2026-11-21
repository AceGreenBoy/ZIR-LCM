package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"zir/lcm/internal/crypto/ecies"
	"zir/lcm/internal/db"
)

const (
	challengeTTL = 60 * time.Second
	sessionTTL   = 15 * time.Minute
)

// ── device authentication (ARCHITECTURE 7.1) ────────────────────────────────

type ChallengeReply struct {
	Nonce     string `json:"nonce"`
	ExpiresIn int    `json:"expires_in"`
}

func (c *Core) Challenge(ctx context.Context, deviceID string) (ChallengeReply, error) {
	var exists bool
	if err := c.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM devices WHERE id::text=$1)`, deviceID).Scan(&exists); err != nil {
		return ChallengeReply{}, err
	}
	if !exists {
		return ChallengeReply{}, userErr(401, "unknown_device", "unknown device")
	}
	nonce := randBytes(32)
	c.Pool.Exec(ctx, `DELETE FROM device_challenges WHERE expires_at < now()`)
	if _, err := c.Pool.Exec(ctx, `INSERT INTO device_challenges (nonce, device_id, expires_at) VALUES ($1,$2,$3)`,
		nonce, deviceID, c.Now().Add(challengeTTL)); err != nil {
		return ChallengeReply{}, err
	}
	return ChallengeReply{Nonce: b64.EncodeToString(nonce), ExpiresIn: int(challengeTTL.Seconds())}, nil
}

// SessionRequest is the body of POST /dev/v1/auth/session (signed with dev_sign).
type SessionRequest struct {
	DeviceID   string `json:"device_id"`
	Nonce      string `json:"nonce"`
	MAC        string `json:"mac"`
	AppVersion string `json:"app_version"` // ZIR_VERSION of the running firmware
	AppSHA256  string `json:"app_sha256"`  // hex, SHA-256 of the installed signed image as received; "" if unknown
	WWWSHA256  string `json:"www_sha256"`  // hex, SHA-256 of the installed www.tar; "" if unknown
	ReleaseID  string `json:"release_id"`  // installed release, "" if unknown
}

type SessionReply struct {
	SessionToken string `json:"session_token"`
	ExpiresIn    int    `json:"expires_in"`
	ServerTime   int64  `json:"server_time"`
}

func (c *Core) Session(ctx context.Context, body []byte, method, uri, sig, ip string) (SessionReply, error) {
	var req SessionRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return SessionReply{}, userErr(400, "bad_request", "bad json")
	}
	nonce, err := DecodeB64(req.Nonce)
	if err != nil {
		return SessionReply{}, userErr(400, "bad_request", "bad nonce")
	}
	var signPub []byte
	var mac net.HardwareAddr
	err = c.Pool.QueryRow(ctx, `SELECT dev_sign_pub, mac FROM devices WHERE id::text=$1`, req.DeviceID).Scan(&signPub, &mac)
	if db.IsNoRows(err) {
		return SessionReply{}, userErr(401, "unknown_device", "unknown device")
	}
	if err != nil {
		return SessionReply{}, err
	}
	if !VerifyDeviceSig(signPub, method, uri, body, sig) {
		anomaly(ctx, c.Pool, req.DeviceID, "bad_signature", map[string]any{"ip": ip, "where": "auth/session"})
		return SessionReply{}, userErr(401, "bad_signature", "bad signature")
	}
	tag, err := c.Pool.Exec(ctx, `DELETE FROM device_challenges WHERE nonce=$1 AND device_id::text=$2 AND expires_at > now()`, nonce, req.DeviceID)
	if err != nil {
		return SessionReply{}, err
	}
	if tag.RowsAffected() != 1 {
		return SessionReply{}, userErr(401, "bad_nonce", "nonce expired or already used")
	}
	if m, err := normMAC(req.MAC); err != nil || m != mac.String() {
		anomaly(ctx, c.Pool, req.DeviceID, "mac_mismatch", map[string]any{"reported": req.MAC, "registered": mac.String(), "ip": ip})
	}
	// Two live sessions from different addresses look like a clone.
	var otherIPs []netip.Addr
	rows, err := c.Pool.Query(ctx, `SELECT DISTINCT ip FROM device_sessions WHERE device_id::text=$1 AND expires_at > now() AND ip IS NOT NULL`, req.DeviceID)
	if err == nil {
		for rows.Next() {
			var a netip.Addr
			if rows.Scan(&a) == nil && a.String() != ip {
				otherIPs = append(otherIPs, a)
			}
		}
		rows.Close()
	}
	if len(otherIPs) > 0 {
		anomaly(ctx, c.Pool, req.DeviceID, "concurrent_sessions", map[string]any{"ip": ip, "other_ips": otherIPs})
	}

	token := randBytes(32)
	hash := sha256.Sum256(token)
	appSHA, _ := hex.DecodeString(req.AppSHA256)
	wwwSHA, _ := hex.DecodeString(req.WWWSHA256)
	var ipAddr *netip.Addr
	if a, err := netip.ParseAddr(ip); err == nil {
		ipAddr = &a
	}
	err = db.InTx(ctx, c.Pool, func(tx pgxTx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM device_sessions WHERE expires_at < now()`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO device_sessions (token_hash, device_id, expires_at, ip) VALUES ($1,$2,$3,$4)`,
			hash[:], req.DeviceID, c.Now().Add(sessionTTL), ipAddr); err != nil {
			return err
		}
		var rel *string
		if req.ReleaseID != "" {
			var ok bool
			tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM releases WHERE id::text=$1)`, req.ReleaseID).Scan(&ok)
			if ok {
				rel = &req.ReleaseID
			}
		}
		_, err := tx.Exec(ctx, `UPDATE devices SET last_seen_at=now(), last_ip=$2, current_version=NULLIF($3,''),
			current_app_sha256=$4, current_www_sha256=$5, current_release_id=COALESCE($6, current_release_id) WHERE id::text=$1`,
			req.DeviceID, ipAddr, req.AppVersion, nilIfEmpty(appSHA), nilIfEmpty(wwwSHA), rel)
		return err
	})
	if err != nil {
		return SessionReply{}, err
	}
	return SessionReply{SessionToken: b64.EncodeToString(token), ExpiresIn: int(sessionTTL.Seconds()), ServerTime: c.Now().Unix()}, nil
}

func nilIfEmpty(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return b
}

// DeviceSession is an authenticated device request.
type DeviceSession struct {
	DeviceID  string
	Revoked   bool
	ProfileID string
	Profile   string
	MAC       string
}

// Authenticate resolves a bearer token. Revoked devices get a session too:
// their telemetry is still wanted (7.1); endpoints decide what to refuse.
func (c *Core) Authenticate(ctx context.Context, bearer string) (DeviceSession, error) {
	token, err := DecodeB64(strings.TrimSpace(bearer))
	if err != nil || len(token) != 32 {
		return DeviceSession{}, userErr(401, "bad_token", "bad token")
	}
	hash := sha256.Sum256(token)
	var s DeviceSession
	var status string
	var mac net.HardwareAddr
	err = c.Pool.QueryRow(ctx, `SELECT d.id, d.status, d.profile_id, p.code, d.mac FROM device_sessions s
		JOIN devices d ON d.id = s.device_id JOIN hw_profiles p ON p.id = d.profile_id
		WHERE s.token_hash=$1 AND s.expires_at > now()`, hash[:]).Scan(&s.DeviceID, &status, &s.ProfileID, &s.Profile, &mac)
	if db.IsNoRows(err) {
		return s, userErr(401, "bad_token", "session expired")
	}
	s.Revoked = status == "revoked"
	s.MAC = mac.String()
	return s, err
}

var errRevoked = &Error{Status: 403, Code: "device_revoked", Msg: "device revoked"}

// ── config ──────────────────────────────────────────────────────────────────

type ConfigReply struct {
	Version int    `json:"version"`
	Config  string `json:"config"`
}

func (c *Core) DeviceConfig(ctx context.Context, s DeviceSession) (ConfigReply, error) {
	if s.Revoked {
		return ConfigReply{}, errRevoked
	}
	var r ConfigReply
	err := c.Pool.QueryRow(ctx, `SELECT version, signed_blob FROM device_configs WHERE device_id=$1 ORDER BY version DESC LIMIT 1`,
		s.DeviceID).Scan(&r.Version, &r.Config)
	return r, err
}

// UpdateConfig signs a new config version from the admin UI.
func (c *Core) UpdateConfig(ctx context.Context, a Actor, deviceID string, p HardParams) error {
	if err := a.require(RoleEngineer); err != nil {
		return err
	}
	return db.InTx(ctx, c.Pool, func(tx pgxTx) error {
		var mac net.HardwareAddr
		var profileCode string
		var version int
		var status string
		err := tx.QueryRow(ctx, `SELECT d.mac, p.code, d.config_version, d.status FROM devices d JOIN hw_profiles p ON p.id=d.profile_id
			WHERE d.id::text=$1 FOR UPDATE OF d`, deviceID).Scan(&mac, &profileCode, &version, &status)
		if err != nil {
			return err
		}
		if status == "revoked" {
			return userErr(409, "revoked", "прилад відкликано")
		}
		_, schema, err := c.Profile(ctx, tx, profileCode)
		if err != nil {
			return err
		}
		if err := ValidateParams(schema, p); err != nil {
			return err
		}
		version++
		if _, err := c.signConfig(ctx, tx, deviceID, mac.String(), profileCode, version, p, a.UserID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE devices SET config_version=$2 WHERE id::text=$1`, deviceID, version); err != nil {
			return err
		}
		return a.audit(ctx, tx, "device.config", "device", deviceID, map[string]any{"version": version, "params": p})
	})
}

// ── admin views ─────────────────────────────────────────────────────────────

type Device struct {
	ID, Serial, MAC, ChipRev, Profile, ProfileID, Status string
	IsTest, Pinned                                       bool
	CurrentVersion                                       string
	CurrentRelease, PendingRelease                       string // versions
	PendingReleaseID                                     string
	ConfigVersion                                        int
	Params                                               HardParams
	RegisteredAt                                         time.Time
	RegisteredBy                                         string
	LastSeen                                             *time.Time
	LastIP                                               string
	RevokeReason                                         string
	PasswordChanged                                      *time.Time
}

const deviceSelect = `SELECT d.id, d.serial, d.mac, d.chip_rev, p.code, p.id, d.status, d.is_test, d.pinned,
	COALESCE(d.current_version,''), COALESCE(cr.version,''), COALESCE(pr.version,''), COALESCE(d.pending_release_id::text,''),
	d.config_version, COALESCE(c.hard_params,'{}'), d.registered_at, COALESCE(u.login,''), d.last_seen_at,
	COALESCE(host(d.last_ip),''), COALESCE(d.revoke_reason,''), d.web_password_changed_at
	FROM devices d JOIN hw_profiles p ON p.id=d.profile_id
	LEFT JOIN releases cr ON cr.id=d.current_release_id
	LEFT JOIN releases pr ON pr.id=d.pending_release_id
	LEFT JOIN users u ON u.id=d.registered_by
	LEFT JOIN device_configs c ON c.device_id=d.id AND c.version=d.config_version`

func scanDevice(row interface{ Scan(...any) error }) (Device, error) {
	var d Device
	var mac net.HardwareAddr
	var params []byte
	err := row.Scan(&d.ID, &d.Serial, &mac, &d.ChipRev, &d.Profile, &d.ProfileID, &d.Status, &d.IsTest, &d.Pinned,
		&d.CurrentVersion, &d.CurrentRelease, &d.PendingRelease, &d.PendingReleaseID,
		&d.ConfigVersion, &params, &d.RegisteredAt, &d.RegisteredBy, &d.LastSeen, &d.LastIP, &d.RevokeReason, &d.PasswordChanged)
	d.MAC = mac.String()
	json.Unmarshal(params, &d.Params)
	return d, err
}

func (c *Core) Devices(ctx context.Context, filter string) ([]Device, error) {
	q := deviceSelect
	var args []any
	if filter != "" {
		q += ` WHERE d.serial ILIKE $1 OR d.mac::text ILIKE $1 OR p.code ILIKE $1 OR d.current_version ILIKE $1`
		args = append(args, "%"+filter+"%")
	}
	rows, err := c.Pool.Query(ctx, q+` ORDER BY d.registered_at DESC LIMIT 500`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Device
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (c *Core) Device(ctx context.Context, id string) (Device, error) {
	d, err := scanDevice(c.Pool.QueryRow(ctx, deviceSelect+` WHERE d.id::text=$1 OR d.serial=$1`, id))
	if db.IsNoRows(err) {
		return d, userErr(404, "not_found", "прилад не знайдено")
	}
	return d, err
}

type UpdateEvent struct {
	At        time.Time
	Release   string
	Initiator string
	Status    string
	Details   string
}

func (c *Core) UpdateEvents(ctx context.Context, deviceID string) ([]UpdateEvent, error) {
	rows, err := c.Pool.Query(ctx, `SELECT e.at, COALESCE(r.version,''), COALESCE(e.initiator,''), e.status, COALESCE(e.details::text,'')
		FROM update_events e LEFT JOIN releases r ON r.id=e.release_id WHERE e.device_id::text=$1 ORDER BY e.at DESC LIMIT 100`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []UpdateEvent
	for rows.Next() {
		var e UpdateEvent
		if err := rows.Scan(&e.At, &e.Release, &e.Initiator, &e.Status, &e.Details); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (c *Core) SetFlags(ctx context.Context, a Actor, deviceID string, isTest, pinned bool) error {
	if err := a.require(RoleEngineer); err != nil {
		return err
	}
	return db.InTx(ctx, c.Pool, func(tx pgxTx) error {
		if _, err := tx.Exec(ctx, `UPDATE devices SET is_test=$2, pinned=$3 WHERE id::text=$1`, deviceID, isTest, pinned); err != nil {
			return err
		}
		return a.audit(ctx, tx, "device.flags", "device", deviceID, map[string]any{"is_test": isTest, "pinned": pinned})
	})
}

// AssignRelease sets the version an engineer wants installed (any channel,
// downgrades too). An empty releaseID clears the assignment.
func (c *Core) AssignRelease(ctx context.Context, a Actor, deviceID, releaseID string) error {
	if err := a.require(RoleEngineer); err != nil {
		return err
	}
	return db.InTx(ctx, c.Pool, func(tx pgxTx) error {
		var rel *string
		if releaseID != "" {
			var ok bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM release_apps ra JOIN devices d ON d.profile_id=ra.profile_id
				WHERE ra.release_id::text=$1 AND d.id::text=$2)`, releaseID, deviceID).Scan(&ok); err != nil {
				return err
			}
			if !ok {
				return userErr(400, "no_profile_in_release", "у релізі немає збірки для профілю цього приладу")
			}
			rel = &releaseID
		}
		if _, err := tx.Exec(ctx, `UPDATE devices SET pending_release_id=$2 WHERE id::text=$1`, deviceID, rel); err != nil {
			return err
		}
		return a.audit(ctx, tx, "device.install", "device", deviceID, map[string]any{"release_id": releaseID})
	})
}

func (c *Core) SetRevoked(ctx context.Context, a Actor, deviceID string, revoke bool, reason string) error {
	if !a.Roles[RoleSuperadmin] {
		return userErr(403, "forbidden", "лише superadmin")
	}
	if strings.TrimSpace(reason) == "" {
		return userErr(400, "reason", "вкажіть причину")
	}
	return db.InTx(ctx, c.Pool, func(tx pgxTx) error {
		var err error
		action := "device.revoke"
		if revoke {
			_, err = tx.Exec(ctx, `UPDATE devices SET status='revoked', revoked_at=now(), revoked_by=$2, revoke_reason=$3 WHERE id::text=$1`,
				deviceID, a.UserID, reason)
		} else {
			action = "device.restore"
			_, err = tx.Exec(ctx, `UPDATE devices SET status='active', revoked_at=NULL, revoked_by=NULL, revoke_reason=NULL WHERE id::text=$1`, deviceID)
		}
		if err != nil {
			return err
		}
		return a.audit(ctx, tx, action, "device", deviceID, map[string]any{"reason": reason})
	})
}

// WebPassword reveals the device's access point password to an engineer.
// Every view is audited.
func (c *Core) WebPassword(ctx context.Context, a Actor, deviceID string) (string, error) {
	if err := a.require(RoleEngineer); err != nil {
		return "", err
	}
	var enc []byte
	if err := c.Pool.QueryRow(ctx, `SELECT web_password_enc FROM devices WHERE id::text=$1`, deviceID).Scan(&enc); err != nil {
		return "", err
	}
	if enc == nil {
		return "", userErr(404, "no_password", "пароль невідомий")
	}
	pw, err := c.Env.Open(enc, "device:"+deviceID+":web_password")
	if err != nil {
		return "", err
	}
	if err := a.audit(ctx, c.Pool, "device.web_password.view", "device", deviceID, nil); err != nil {
		return "", err
	}
	return string(pw), nil
}

// WebPasswordReport is the body of POST /dev/v1/web-password (ARCHITECTURE 7.10).
type WebPasswordReport struct {
	Password  ecies.Box `json:"password"` // to K_telemetry, info zir-pwd/1, aad = device_id
	ChangedAt int64     `json:"changed_at,omitempty"`
}

func (c *Core) ReportWebPassword(ctx context.Context, s DeviceSession, body []byte, ip string) error {
	var r WebPasswordReport
	if err := json.Unmarshal(body, &r); err != nil {
		return userErr(400, "bad_request", "bad json")
	}
	pw, err := c.Signer.OpenBox(ecies.InfoWebPassword, r.Password, []byte(s.DeviceID))
	if err != nil || len(pw) < webPasswordMinLen || len(pw) > webPasswordMaxLen {
		return userErr(400, "bad_password", "cannot decrypt password or bad length")
	}
	enc, err := c.Env.Seal(pw, "device:"+s.DeviceID+":web_password")
	if err != nil {
		return err
	}
	return db.InTx(ctx, c.Pool, func(tx pgxTx) error {
		if _, err := tx.Exec(ctx, `UPDATE devices SET web_password_enc=$2, web_password_changed_at=now() WHERE id::text=$1`, s.DeviceID, enc); err != nil {
			return err
		}
		return deviceAudit(ctx, tx, s.DeviceID, "device.web_password.changed", map[string]any{"changed_at": r.ChangedAt}, ip)
	})
}

func (c *Core) dropImageCache(deviceID string) {
	os.RemoveAll(c.path("cache", deviceID))
}
