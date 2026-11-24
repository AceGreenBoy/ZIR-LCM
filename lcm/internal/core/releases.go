package core

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"sort"
	"time"

	"github.com/Masterminds/semver/v3"

	"zir/lcm/internal/crypto/encimg"
	"zir/lcm/internal/crypto/espsig"
	"zir/lcm/internal/db"
	"zir/lcm/internal/signer"

	"crypto/rsa"
	"crypto/x509"
)

const manifestTTL = time.Hour

type Release struct {
	ID         string
	Version    string
	Channel    string
	Critical   bool
	Notes      string
	WWWBuildID string
	WWWVersion string
	Apps       map[string]string // profile code -> build id
	AppVers    map[string]string // profile code -> build version
	CreatedAt  time.Time
	PromotedAt *time.Time
}

type ReleaseInput struct {
	Version    string
	Notes      string
	WWWBuildID string
	Apps       map[string]string // profile id -> app build id
}

func (c *Core) CreateRelease(ctx context.Context, a Actor, in ReleaseInput) (string, error) {
	if !a.Roles[RoleSuperadmin] {
		return "", userErr(403, "forbidden", "лише superadmin")
	}
	if _, err := semver.StrictNewVersion(in.Version); err != nil {
		return "", userErr(400, "bad_version", "версія релізу має бути semver: 1.4.0 або 1.5.0-beta.1")
	}
	if len(in.Apps) == 0 {
		return "", userErr(400, "no_apps", "оберіть збірку хоча б для одного профілю")
	}
	var id string
	err := db.InTx(ctx, c.Pool, func(tx pgxTx) error {
		var www *string
		if in.WWWBuildID != "" {
			var kind string
			if err := tx.QueryRow(ctx, `SELECT kind FROM builds WHERE id::text=$1 AND status='success'`, in.WWWBuildID).Scan(&kind); err != nil || kind != "www" {
				return userErr(400, "bad_build", "збірку веб-інтерфейсу не знайдено")
			}
			www = &in.WWWBuildID
		}
		err := tx.QueryRow(ctx, `INSERT INTO releases (version, www_build_id, notes, created_by) VALUES ($1,$2,$3,$4) RETURNING id`,
			in.Version, www, in.Notes, a.UserID).Scan(&id)
		if db.IsUniqueViolation(err) {
			return userErr(409, "exists", "реліз %s уже існує", in.Version)
		}
		if err != nil {
			return err
		}
		for profileID, buildID := range in.Apps {
			var ok bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM builds WHERE id::text=$1 AND kind='app' AND status='success' AND profile_id::text=$2)`,
				buildID, profileID).Scan(&ok); err != nil {
				return err
			}
			if !ok {
				return userErr(400, "bad_build", "збірка не відповідає профілю")
			}
			if _, err := tx.Exec(ctx, `INSERT INTO release_apps (release_id, profile_id, app_build_id) VALUES ($1,$2,$3)`, id, profileID, buildID); err != nil {
				return err
			}
		}
		return a.audit(ctx, tx, "release.create", "release", id, map[string]any{"version": in.Version, "www": in.WWWBuildID, "apps": in.Apps})
	})
	return id, err
}

// Promote moves a beta release to stable (same binaries, no rebuild).
func (c *Core) Promote(ctx context.Context, a Actor, releaseID string, critical bool) error {
	if !a.Roles[RoleSuperadmin] {
		return userErr(403, "forbidden", "лише superadmin")
	}
	return db.InTx(ctx, c.Pool, func(tx pgxTx) error {
		tag, err := tx.Exec(ctx, `UPDATE releases SET channel='stable', critical=$2, promoted_by=$3, promoted_at=now()
			WHERE id::text=$1 AND channel='beta'`, releaseID, critical, a.UserID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return userErr(409, "not_beta", "реліз не знайдено або він уже stable")
		}
		return a.audit(ctx, tx, "release.promote", "release", releaseID, map[string]any{"critical": critical})
	})
}

// SetCritical marks a stable release critical (installed automatically).
func (c *Core) SetCritical(ctx context.Context, a Actor, releaseID string, critical bool) error {
	if !a.Roles[RoleSuperadmin] {
		return userErr(403, "forbidden", "лише superadmin")
	}
	return db.InTx(ctx, c.Pool, func(tx pgxTx) error {
		if _, err := tx.Exec(ctx, `UPDATE releases SET critical=$2 WHERE id::text=$1`, releaseID, critical); err != nil {
			return err
		}
		return a.audit(ctx, tx, "release.critical", "release", releaseID, map[string]any{"critical": critical})
	})
}

func (c *Core) Releases(ctx context.Context) ([]Release, error) {
	rows, err := c.Pool.Query(ctx, `SELECT r.id, r.version, r.channel, r.critical, r.notes, COALESCE(r.www_build_id::text,''),
		COALESCE(w.version,''), r.created_at, r.promoted_at,
		COALESCE(json_object_agg(p.code, ra.app_build_id) FILTER (WHERE p.code IS NOT NULL), '{}'),
		COALESCE(json_object_agg(p.code, b.version) FILTER (WHERE p.code IS NOT NULL), '{}')
		FROM releases r LEFT JOIN builds w ON w.id=r.www_build_id
		LEFT JOIN release_apps ra ON ra.release_id=r.id LEFT JOIN hw_profiles p ON p.id=ra.profile_id
		LEFT JOIN builds b ON b.id=ra.app_build_id
		GROUP BY r.id, w.version`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Release
	for rows.Next() {
		var r Release
		var apps, vers []byte
		if err := rows.Scan(&r.ID, &r.Version, &r.Channel, &r.Critical, &r.Notes, &r.WWWBuildID, &r.WWWVersion,
			&r.CreatedAt, &r.PromotedAt, &apps, &vers); err != nil {
			return nil, err
		}
		json.Unmarshal(apps, &r.Apps)
		json.Unmarshal(vers, &r.AppVers)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return semverLess(out[j].Version, out[i].Version) })
	return out, nil
}

func semverLess(a, b string) bool {
	va, ea := semver.NewVersion(a)
	vb, eb := semver.NewVersion(b)
	if ea != nil || eb != nil {
		return a < b
	}
	return va.LessThan(vb)
}

// ── update selection (ARCHITECTURE 7.3) ────────────────────────────────────

type candidate struct {
	id       string
	version  *semver.Version
	channel  string
	critical bool
}

type Offer struct {
	ReleaseID  string
	DevBuildID string // set instead of ReleaseID for a dev build
	Version    string
	Mode       string // engineer | auto | button
	Critical   bool
}

// SelectUpdate is the version-choice algorithm. "current" is the version of
// the device's installed release, or of its firmware if the release is unknown.
func (c *Core) SelectUpdate(ctx context.Context, deviceID string) (*Offer, error) {
	var status, profileID, pendingID, curRelease, curFW string
	var pinned, isTest bool
	err := c.Pool.QueryRow(ctx, `SELECT d.status, d.profile_id, COALESCE(d.pending_release_id::text,''), COALESCE(r.version,''),
		COALESCE(d.current_version,''), d.pinned, d.is_test
		FROM devices d LEFT JOIN releases r ON r.id=d.current_release_id WHERE d.id::text=$1`, deviceID).
		Scan(&status, &profileID, &pendingID, &curRelease, &curFW, &pinned, &isTest)
	if err != nil {
		return nil, err
	}
	if status == "revoked" {
		return nil, errRevoked
	}
	// A developer device with an assigned dev build gets it and stays on it.
	if offer, assigned, err := c.devOffer(ctx, deviceID); err != nil || assigned {
		return offer, err
	}
	if pendingID != "" {
		var o Offer
		if err := c.Pool.QueryRow(ctx, `SELECT id, version, critical FROM releases WHERE id::text=$1`, pendingID).
			Scan(&o.ReleaseID, &o.Version, &o.Critical); err != nil {
			return nil, err
		}
		o.Mode = "engineer"
		return &o, nil
	}
	if pinned {
		return nil, nil
	}
	cur := curRelease
	if cur == "" {
		cur = curFW
	}
	curV, err := semver.NewVersion(cur)
	if err != nil {
		curV = semver.MustParse("0.0.0")
	}
	rows, err := c.Pool.Query(ctx, `SELECT r.id, r.version, r.channel, r.critical FROM releases r
		JOIN release_apps ra ON ra.release_id=r.id WHERE ra.profile_id=$1 AND r.channel='stable'`, profileID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var crit, stable *candidate
	for rows.Next() {
		var cd candidate
		var v string
		if err := rows.Scan(&cd.id, &v, &cd.channel, &cd.critical); err != nil {
			return nil, err
		}
		if cd.version, err = semver.NewVersion(v); err != nil {
			continue
		}
		if cd.critical && (crit == nil || cd.version.GreaterThan(crit.version)) {
			cc := cd
			crit = &cc
		}
		if stable == nil || cd.version.GreaterThan(stable.version) {
			cc := cd
			stable = &cc
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if crit != nil && crit.version.GreaterThan(curV) && !isTest {
		return &Offer{ReleaseID: crit.id, Version: crit.version.Original(), Mode: "auto", Critical: true}, nil
	}
	if stable != nil && stable.version.GreaterThan(curV) {
		return &Offer{ReleaseID: stable.id, Version: stable.version.Original(), Mode: "button", Critical: stable.critical}, nil
	}
	return nil, nil
}

// Manifest is the signed update offer (ARCHITECTURE 7.3).
type Manifest struct {
	Typ       string `json:"typ"`
	DeviceID  string `json:"device_id"`
	Profile   string `json:"profile"`
	ReleaseID string `json:"release_id"`
	// Dev build offer: release_id is empty, the image is unsigned
	// (CONFIG_ZIR_DEV_BUILD) and only a device whose config has "dev": true
	// may install it. www, if present, is the dev build's own unsigned www.tar.
	DevBuildID string       `json:"dev_build_id,omitempty"`
	Dev        bool         `json:"dev,omitempty"`
	Version    string       `json:"version"`
	Mode       string       `json:"mode"`
	Critical   bool         `json:"critical"`
	App        ManifestApp  `json:"app"`
	WWW        *ManifestWWW `json:"www"`
	IAT        int64        `json:"iat"`
	EXP        int64        `json:"exp"`
}

type ManifestApp struct {
	Needed  bool   `json:"needed"`
	URL     string `json:"url"`
	Size    int    `json:"size"`     // bytes to download (encrypted)
	ImgSize int    `json:"img_size"` // decrypted signed image
	SHA256  string `json:"sha256"`   // of the decrypted signed image
	Version string `json:"version"`
	Enc     string `json:"enc"`
}

type ManifestWWW struct {
	Needed  bool   `json:"needed"`
	URL     string `json:"url"`
	Format  string `json:"format"`
	Size    int    `json:"size"`
	SHA256  string `json:"sha256"` // of www.tar
	Version string `json:"version"`
	WwwAPI  int    `json:"www_api"`
}

type UpdateReply struct {
	Manifest      *string `json:"manifest"`
	ConfigVersion int     `json:"config_version"`
	ServerTime    int64   `json:"server_time"`
	PollAfter     int     `json:"poll_after"` // seconds until the next check
}

func (c *Core) CheckUpdate(ctx context.Context, s DeviceSession) (UpdateReply, error) {
	if s.Revoked {
		return UpdateReply{}, errRevoked
	}
	reply := UpdateReply{ServerTime: c.Now().Unix()}
	var appSHA, wwwSHA []byte
	var dev bool
	if err := c.Pool.QueryRow(ctx, `SELECT config_version, current_app_sha256, current_www_sha256, dev_mode FROM devices WHERE id=$1`,
		s.DeviceID).Scan(&reply.ConfigVersion, &appSHA, &wwwSHA, &dev); err != nil {
		return reply, err
	}
	reply.PollAfter = PollRegular
	if dev {
		reply.PollAfter = PollDev
	}
	offer, err := c.SelectUpdate(ctx, s.DeviceID)
	if err != nil || offer == nil {
		return reply, err
	}
	if offer.DevBuildID != "" {
		m, err := c.devManifest(ctx, s, offer, appSHA, wwwSHA)
		if err != nil {
			return reply, err
		}
		tok, err := c.Signer.SignJWS(signer.Manifest, "zir-manifest/1", m)
		if err != nil {
			return reply, err
		}
		reply.Manifest = &tok
		return reply, nil
	}
	m := Manifest{Typ: "zir-manifest/1", DeviceID: s.DeviceID, Profile: s.Profile, ReleaseID: offer.ReleaseID,
		Version: offer.Version, Mode: offer.Mode, Critical: offer.Critical, IAT: c.Now().Unix(), EXP: c.Now().Add(manifestTTL).Unix()}
	var appSum []byte
	var appSize int
	var appVer string
	err = c.Pool.QueryRow(ctx, `SELECT b.sha256, b.size, b.version FROM release_apps ra JOIN builds b ON b.id=ra.app_build_id
		WHERE ra.release_id::text=$1 AND ra.profile_id::text=$2`, offer.ReleaseID, s.ProfileID).Scan(&appSum, &appSize, &appVer)
	if err != nil {
		return reply, err
	}
	m.App = ManifestApp{Needed: hex.EncodeToString(appSum) != hex.EncodeToString(appSHA),
		URL: "/dev/v1/artifacts/" + offer.ReleaseID + "/app", Size: encimg.HeaderSize + appSize, ImgSize: appSize,
		SHA256: hex.EncodeToString(appSum), Version: appVer, Enc: "esp_encrypted_img"}
	var wSum []byte
	var wSize, wAPI int
	var wVer string
	err = c.Pool.QueryRow(ctx, `SELECT b.sha256, b.size, b.version, b.www_api FROM releases r JOIN builds b ON b.id=r.www_build_id
		WHERE r.id::text=$1`, offer.ReleaseID).Scan(&wSum, &wSize, &wVer, &wAPI)
	if err == nil {
		m.WWW = &ManifestWWW{Needed: hex.EncodeToString(wSum) != hex.EncodeToString(wwwSHA),
			URL: "/dev/v1/artifacts/" + offer.ReleaseID + "/www", Format: "tar", Size: wSize,
			SHA256: hex.EncodeToString(wSum), Version: wVer, WwwAPI: wAPI}
	} else if !db.IsNoRows(err) {
		return reply, err
	}
	tok, err := c.Signer.SignJWS(signer.Manifest, "zir-manifest/1", m)
	if err != nil {
		return reply, err
	}
	reply.Manifest = &tok
	return reply, nil
}

// AppImagePath returns the release's app image encrypted for this device
// (cached, so HTTP Range resumes see the same bytes).
func (c *Core) AppImagePath(ctx context.Context, s DeviceSession, releaseID string) (string, error) {
	if s.Revoked {
		return "", errRevoked
	}
	var buildID, artifact string
	err := c.Pool.QueryRow(ctx, `SELECT b.id, b.artifact_path FROM release_apps ra JOIN builds b ON b.id=ra.app_build_id
		WHERE ra.release_id::text=$1 AND ra.profile_id::text=$2`, releaseID, s.ProfileID).Scan(&buildID, &artifact)
	if db.IsNoRows(err) {
		return "", userErr(404, "not_found", "no app for this device in the release")
	}
	if err != nil {
		return "", err
	}
	cache := c.path("cache", s.DeviceID, buildID+".enc")
	if _, err := os.Stat(cache); err == nil {
		return cache, nil
	}
	var pubDER []byte
	if err := c.Pool.QueryRow(ctx, `SELECT ota_pub_der FROM devices WHERE id=$1`, s.DeviceID).Scan(&pubDER); err != nil {
		return "", err
	}
	pub, err := x509.ParsePKIXPublicKey(pubDER)
	if err != nil {
		return "", err
	}
	signed, err := os.ReadFile(artifact)
	if err != nil {
		return "", err
	}
	if !espsig.HasSignature(signed) {
		return "", userErr(500, "unsigned", "artifact is not signed")
	}
	enc, err := encimg.Encrypt(signed, pub.(*rsa.PublicKey))
	if err != nil {
		return "", err
	}
	return cache, writeFile(cache, enc)
}

func (c *Core) WWWPath(ctx context.Context, s DeviceSession, releaseID string) (string, error) {
	if s.Revoked {
		return "", errRevoked
	}
	var p string
	err := c.Pool.QueryRow(ctx, `SELECT b.artifact_path FROM releases r JOIN builds b ON b.id=r.www_build_id
		JOIN release_apps ra ON ra.release_id=r.id AND ra.profile_id::text=$2 WHERE r.id::text=$1`, releaseID, s.ProfileID).Scan(&p)
	if db.IsNoRows(err) {
		return "", userErr(404, "not_found", "no www in the release")
	}
	return p, err
}

// ── install report ──────────────────────────────────────────────────────────

type UpdateReport struct {
	ReleaseID  string `json:"release_id"`
	DevBuildID string `json:"dev_build_id,omitempty"` // instead of release_id, from a dev manifest
	Status     string `json:"status"`                 // downloading | installed | failed | rolled_back
	Error      string `json:"error,omitempty"`
	Mode       string `json:"mode,omitempty"` // mode from the manifest
}

func (c *Core) ReportUpdate(ctx context.Context, s DeviceSession, body []byte, ip string) error {
	var r UpdateReport
	if err := json.Unmarshal(body, &r); err != nil {
		return userErr(400, "bad_request", "bad json")
	}
	switch r.Status {
	case "downloading", "installed", "failed", "rolled_back":
	default:
		return userErr(400, "bad_request", "bad status")
	}
	initiator := map[string]string{"engineer": "engineer", "auto": "critical", "button": "user"}[r.Mode]
	if r.DevBuildID != "" {
		var ini *string
		if initiator != "" {
			ini = &initiator
		}
		return c.reportDev(ctx, s, r, ini, ip)
	}
	return db.InTx(ctx, c.Pool, func(tx pgxTx) error {
		var ok bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM releases WHERE id::text=$1)`, r.ReleaseID).Scan(&ok); err != nil {
			return err
		}
		if !ok {
			return userErr(400, "bad_request", "unknown release")
		}
		var ini *string
		if initiator != "" {
			ini = &initiator
		}
		details, _ := json.Marshal(map[string]any{"error": r.Error, "ip": ip})
		if _, err := tx.Exec(ctx, `INSERT INTO update_events (device_id, release_id, initiator, status, details) VALUES ($1,$2,$3,$4,$5)`,
			s.DeviceID, r.ReleaseID, ini, r.Status, details); err != nil {
			return err
		}
		if r.Status == "installed" {
			_, err := tx.Exec(ctx, `UPDATE devices SET current_release_id=$2,
				pending_release_id = CASE WHEN pending_release_id=$2 THEN NULL ELSE pending_release_id END WHERE id=$1`,
				s.DeviceID, r.ReleaseID)
			return err
		}
		return nil
	})
}
