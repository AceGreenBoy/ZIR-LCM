package core

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"

	"github.com/google/uuid"

	"zir/lcm/internal/crypto/appdesc"
	"zir/lcm/internal/crypto/encimg"
	"zir/lcm/internal/crypto/espsig"
	"zir/lcm/internal/db"
)

// Developer builds (CONFIG_ZIR_DEV_BUILD) go only to developer devices: those
// whose signed config has "dev": true. The server never signs them; it only
// encrypts them with the device's K_ota, like any other image.

const (
	// PollDev is how often a developer device asks for updates, so a critical
	// dev build lands within a minute. Others keep the 6 h rhythm.
	PollDev     = 30
	PollRegular = 6 * 3600
	maxVersion  = 31 // zir_custom_desc_t.version is char[32]
)

// UploadDevApp stores an unsigned developer build after the same checks as a
// release build, except that the dev flag is required instead of forbidden.
func (c *Core) UploadDevApp(ctx context.Context, a Actor, img, elf []byte) (Build, error) {
	if !a.Roles[RoleSuperadmin] {
		return Build{}, userErr(403, "forbidden", "завантажувати збірки може лише superadmin")
	}
	if len(img) == 0 || len(img) > MaxAppSize {
		return Build{}, userErr(400, "bad_image", "розмір образу має бути до %d байт", MaxAppSize)
	}
	if espsig.HasSignature(img) {
		return Build{}, userErr(400, "signed", "образ підписано: для приладу розробника потрібна збірка esp32dev без підпису")
	}
	d, err := appdesc.Parse(img)
	if err != nil {
		return Build{}, userErr(400, "bad_image", "це не образ застосунку ESP32: %v", err)
	}
	if d.ChipID != 0 {
		return Build{}, userErr(400, "bad_image", "образ не для ESP32 (chip_id %d)", d.ChipID)
	}
	if !d.HasZir {
		return Build{}, userErr(400, "no_zir_desc", "в образі немає zir_custom_desc_t (FIRMWARE_REQUIREMENTS 6.4)")
	}
	if !d.DevBuild() {
		return Build{}, userErr(400, "not_dev_build", "це бойова збірка (без CONFIG_ZIR_DEV_BUILD): завантажте її в «Збірки», сервер її підпише")
	}
	if d.ZirVersion == "" || len(d.ZirVersion) > maxVersion {
		return Build{}, userErr(400, "bad_version", "порожня або задовга версія в zir_custom_desc_t")
	}
	prof, _, err := c.Profile(ctx, c.Pool, d.Profile)
	if err != nil {
		return Build{}, userErr(400, "no_profile", "профіль %q з образу не існує на сервері", d.Profile)
	}
	cmp, err := appdesc.ComparableHash(img)
	if err != nil {
		return Build{}, err
	}
	sum := sha256.Sum256(img)
	id := uuid.NewString()
	artifact := c.path("artifacts", id, "app.bin")
	if err := writeFile(artifact, img); err != nil {
		return Build{}, err
	}
	var elfPath *string
	if len(elf) > 0 {
		p := c.path("artifacts", id, "app.elf")
		if err := writeFile(p, elf); err != nil {
			return Build{}, err
		}
		elfPath = &p
	}
	err = db.InTx(ctx, c.Pool, func(tx pgxTx) error {
		_, err := tx.Exec(ctx, `INSERT INTO builds (id, kind, profile_id, version, www_api, status, artifact_path, elf_path,
			sha256, size, comparable_hash, created_by) VALUES ($1,'dev_app',$2,$3,$4,'success',$5,$6,$7,$8,$9,$10)`,
			id, prof.ID, d.ZirVersion, int(d.WwwAPI), artifact, elfPath, sum[:], len(img), cmp[:], a.UserID)
		if err != nil {
			return err
		}
		return a.audit(ctx, tx, "build.upload", "build", id, map[string]any{
			"kind": "dev_app", "profile": d.Profile, "version": d.ZirVersion, "sha256": hex.EncodeToString(sum[:])})
	})
	return Build{ID: id, Kind: "dev_app", Profile: prof.Code, Version: d.ZirVersion, WwwAPI: int(d.WwwAPI),
		Size: len(img), SHA256: hex.EncodeToString(sum[:])}, err
}

// SetDevMode turns a device into a developer device or back. The flag lives in
// the signed config, so a new config version is signed.
func (c *Core) SetDevMode(ctx context.Context, a Actor, deviceID string, on bool) error {
	if !a.Roles[RoleSuperadmin] {
		return userErr(403, "forbidden", "лише superadmin")
	}
	return db.InTx(ctx, c.Pool, func(tx pgxTx) error {
		var id, profileCode, status string
		var macStr string
		var version int
		var cur bool
		var params []byte
		err := tx.QueryRow(ctx, `SELECT d.id, d.mac::text, p.code, d.config_version, d.status, d.dev_mode, COALESCE(c.hard_params,'{}')
			FROM devices d JOIN hw_profiles p ON p.id=d.profile_id
			LEFT JOIN device_configs c ON c.device_id=d.id AND c.version=d.config_version
			WHERE d.id::text=$1 FOR UPDATE OF d`, deviceID).Scan(&id, &macStr, &profileCode, &version, &status, &cur, &params)
		if db.IsNoRows(err) {
			return userErr(404, "not_found", "прилад не знайдено")
		}
		if err != nil {
			return err
		}
		if status == "revoked" {
			return userErr(409, "revoked", "прилад відкликано")
		}
		if cur == on {
			return nil
		}
		var p HardParams
		if err := json.Unmarshal(params, &p); err != nil {
			return err
		}
		version++
		if _, err := c.signConfig(ctx, tx, id, macStr, profileCode, version, p, on, a.UserID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE devices SET config_version=$2, dev_mode=$3,
			dev_build_id=CASE WHEN $3 THEN dev_build_id END, dev_critical=$3 AND dev_critical WHERE id=$1`, id, version, on); err != nil {
			return err
		}
		return a.audit(ctx, tx, "device.dev_mode", "device", id, map[string]any{"dev": on, "config_version": version})
	})
}

// AssignDevBuild offers a dev build to developer devices (ids or serials; "all"
// means every active developer device of the build's profile). A critical
// build is installed without asking, within PollDev seconds.
func (c *Core) AssignDevBuild(ctx context.Context, a Actor, buildID string, devices []string, critical bool) ([]string, error) {
	if !a.Roles[RoleSuperadmin] {
		return nil, userErr(403, "forbidden", "лише superadmin")
	}
	var assigned []string
	err := db.InTx(ctx, c.Pool, func(tx pgxTx) error {
		var profileID, version string
		err := tx.QueryRow(ctx, `SELECT profile_id::text, version FROM builds WHERE id::text=$1 AND kind='dev_app' AND status='success'`,
			buildID).Scan(&profileID, &version)
		if db.IsNoRows(err) {
			return userErr(404, "not_found", "збірку розробника не знайдено")
		}
		if err != nil {
			return err
		}
		all := len(devices) == 1 && devices[0] == "all"
		if all {
			devices = nil
			rows, err := tx.Query(ctx, `SELECT id::text FROM devices WHERE dev_mode AND status='active' AND profile_id::text=$1`, profileID)
			if err != nil {
				return err
			}
			for rows.Next() {
				var id string
				rows.Scan(&id)
				devices = append(devices, id)
			}
			rows.Close()
		}
		if len(devices) == 0 {
			return userErr(400, "no_devices", "оберіть хоча б один прилад розробника")
		}
		for _, ref := range devices {
			ref = strings.TrimSpace(ref)
			var id, serial, devProfile, status string
			var dev bool
			err := tx.QueryRow(ctx, `SELECT id, serial, profile_id::text, status, dev_mode FROM devices
				WHERE id::text=$1 OR serial=$1 FOR UPDATE`, ref).Scan(&id, &serial, &devProfile, &status, &dev)
			if db.IsNoRows(err) {
				return userErr(404, "not_found", "прилад %s не знайдено", ref)
			}
			if err != nil {
				return err
			}
			switch {
			case !dev:
				return userErr(409, "not_dev_device", "%s не є приладом розробника", serial)
			case status != "active":
				return userErr(409, "revoked", "%s відкликано", serial)
			case devProfile != profileID:
				return userErr(409, "wrong_profile", "збірка для іншого профілю, ніж у %s", serial)
			}
			// A dev build replaces a release assignment.
			if _, err := tx.Exec(ctx, `UPDATE devices SET dev_build_id=$2, dev_critical=$3, dev_assigned_at=now(),
				pending_release_id=NULL WHERE id=$1`, id, buildID, critical); err != nil {
				return err
			}
			if err := a.audit(ctx, tx, "device.dev_build", "device", id, map[string]any{
				"build_id": buildID, "version": version, "critical": critical}); err != nil {
				return err
			}
			assigned = append(assigned, serial)
		}
		return nil
	})
	return assigned, err
}

// ClearDevBuild drops the dev build assignment: the device follows releases again.
func (c *Core) ClearDevBuild(ctx context.Context, a Actor, deviceID string) error {
	if !a.Roles[RoleSuperadmin] {
		return userErr(403, "forbidden", "лише superadmin")
	}
	return db.InTx(ctx, c.Pool, func(tx pgxTx) error {
		if _, err := tx.Exec(ctx, `UPDATE devices SET dev_build_id=NULL, dev_critical=false, dev_assigned_at=NULL WHERE id::text=$1`, deviceID); err != nil {
			return err
		}
		return a.audit(ctx, tx, "device.dev_build", "device", deviceID, map[string]any{"build_id": nil})
	})
}

// DevDevices lists developer devices.
func (c *Core) DevDevices(ctx context.Context) ([]Device, error) {
	rows, err := c.Pool.Query(ctx, deviceSelect+` WHERE d.dev_mode ORDER BY d.serial`)
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

// devOffer is the dev part of SelectUpdate: the assigned build until the
// device runs it, then nothing (the device stays on it).
func (c *Core) devOffer(ctx context.Context, deviceID string) (offer *Offer, assigned bool, err error) {
	var buildID, version string
	var critical, installed bool
	err = c.Pool.QueryRow(ctx, `SELECT COALESCE(d.dev_build_id::text,''), d.dev_critical, COALESCE(b.version,''),
		COALESCE(b.sha256 = d.current_app_sha256, false)
		FROM devices d LEFT JOIN builds b ON b.id=d.dev_build_id WHERE d.id::text=$1 AND d.dev_mode`, deviceID).
		Scan(&buildID, &critical, &version, &installed)
	if db.IsNoRows(err) || (err == nil && buildID == "") {
		return nil, false, nil
	}
	if err != nil || installed {
		return nil, true, err
	}
	mode := "button"
	if critical {
		mode = "auto"
	}
	return &Offer{DevBuildID: buildID, Version: version, Mode: mode, Critical: critical}, true, nil
}

func (c *Core) devManifest(ctx context.Context, s DeviceSession, offer *Offer, appSHA []byte) (Manifest, error) {
	m := Manifest{Typ: "zir-manifest/1", DeviceID: s.DeviceID, Profile: s.Profile, DevBuildID: offer.DevBuildID, Dev: true,
		Version: offer.Version, Mode: offer.Mode, Critical: offer.Critical, IAT: c.Now().Unix(), EXP: c.Now().Add(manifestTTL).Unix()}
	var sum []byte
	var size int
	if err := c.Pool.QueryRow(ctx, `SELECT sha256, size FROM builds WHERE id::text=$1`, offer.DevBuildID).Scan(&sum, &size); err != nil {
		return m, err
	}
	m.App = ManifestApp{Needed: hex.EncodeToString(sum) != hex.EncodeToString(appSHA),
		URL: "/dev/v1/dev-artifacts/" + offer.DevBuildID, Size: encimg.HeaderSize + size, ImgSize: size,
		SHA256: hex.EncodeToString(sum), Version: offer.Version, Enc: "esp_encrypted_img"}
	return m, nil
}

// DevImagePath returns the assigned dev build encrypted for this device.
// Only the build currently assigned to the device is served.
func (c *Core) DevImagePath(ctx context.Context, s DeviceSession, buildID string) (string, error) {
	if s.Revoked {
		return "", errRevoked
	}
	if _, err := uuid.Parse(buildID); err != nil {
		return "", userErr(404, "not_found", "no such build")
	}
	var artifact string
	var pubDER []byte
	err := c.Pool.QueryRow(ctx, `SELECT b.artifact_path, d.ota_pub_der FROM devices d JOIN builds b ON b.id=d.dev_build_id
		WHERE d.id::text=$1 AND d.dev_mode AND b.id::text=$2 AND b.kind='dev_app'`, s.DeviceID, buildID).Scan(&artifact, &pubDER)
	if db.IsNoRows(err) {
		return "", userErr(404, "not_found", "this dev build is not assigned to the device")
	}
	if err != nil {
		return "", err
	}
	cache := c.path("cache", s.DeviceID, buildID+".enc")
	if _, err := os.Stat(cache); err == nil {
		return cache, nil
	}
	pub, err := x509.ParsePKIXPublicKey(pubDER)
	if err != nil {
		return "", err
	}
	img, err := os.ReadFile(artifact)
	if err != nil {
		return "", err
	}
	enc, err := encimg.Encrypt(img, pub.(*rsa.PublicKey))
	if err != nil {
		return "", err
	}
	return cache, writeFile(cache, enc)
}

// reportDev records an install report for a dev build.
func (c *Core) reportDev(ctx context.Context, s DeviceSession, r UpdateReport, initiator *string, ip string) error {
	return db.InTx(ctx, c.Pool, func(tx pgxTx) error {
		var sum []byte
		err := tx.QueryRow(ctx, `SELECT sha256 FROM builds WHERE id::text=$1 AND kind='dev_app'`, r.DevBuildID).Scan(&sum)
		if db.IsNoRows(err) {
			return userErr(400, "bad_request", "unknown dev build")
		}
		if err != nil {
			return err
		}
		details, _ := json.Marshal(map[string]any{"error": r.Error, "ip": ip})
		if _, err := tx.Exec(ctx, `INSERT INTO update_events (device_id, build_id, initiator, status, details) VALUES ($1,$2,$3,$4,$5)`,
			s.DeviceID, r.DevBuildID, initiator, r.Status, details); err != nil {
			return err
		}
		if r.Status == "installed" {
			// The device no longer runs a release.
			_, err := tx.Exec(ctx, `UPDATE devices SET current_release_id=NULL, current_app_sha256=$2 WHERE id=$1`, s.DeviceID, sum)
			return err
		}
		return nil
	})
}
