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

	"zir/lcm/internal/audit"
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
// www (optional) is the web UI delivered with it: a www.tar checked like a
// release one, with www_api of the firmware; it is never signed or released.
func (c *Core) UploadDevApp(ctx context.Context, a Actor, img, elf, www []byte) (Build, error) {
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
	var wm WWWManifest
	if len(www) > 0 {
		if wm, err = CheckWWWTar(www); err != nil {
			return Build{}, err
		}
		if wm.WwwAPI != int(d.WwwAPI) {
			return Build{}, userErr(400, "www_api_mismatch", "www_api інтерфейсу (%d) не збігається з www_api прошивки (%d)", wm.WwwAPI, d.WwwAPI)
		}
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
	var wwwID *string
	var wsum string
	if len(www) > 0 {
		wid := uuid.NewString()
		if wsum, err = c.storeDevWWW(wid, www); err != nil {
			return Build{}, err
		}
		wwwID = &wid
	}
	err = db.InTx(ctx, c.Pool, func(tx pgxTx) error {
		if wwwID != nil {
			if err := c.insertDevWWW(ctx, tx, a, *wwwID, wm, www); err != nil {
				return err
			}
		}
		_, err := tx.Exec(ctx, `INSERT INTO builds (id, kind, profile_id, version, www_api, status, artifact_path, elf_path,
			sha256, size, comparable_hash, www_build_id, created_by) VALUES ($1,'dev_app',$2,$3,$4,'success',$5,$6,$7,$8,$9,$10,$11)`,
			id, prof.ID, d.ZirVersion, int(d.WwwAPI), artifact, elfPath, sum[:], len(img), cmp[:], wwwID, a.UserID)
		if err != nil {
			return err
		}
		details := map[string]any{"kind": "dev_app", "profile": d.Profile, "version": d.ZirVersion, "sha256": hex.EncodeToString(sum[:])}
		if wwwID != nil {
			details["www"] = map[string]any{"build_id": *wwwID, "version": wm.Version, "sha256": wsum}
		}
		return a.audit(ctx, tx, "build.upload", "build", id, details)
	})
	b := Build{ID: id, Kind: "dev_app", Profile: prof.Code, Version: d.ZirVersion, WwwAPI: int(d.WwwAPI),
		Size: len(img), SHA256: hex.EncodeToString(sum[:])}
	if wwwID != nil {
		b.WWWBuildID, b.WWWVersion = *wwwID, wm.Version
	}
	return b, err
}

// UploadDevWWW stores a web UI for developer devices on its own: assigned with
// AssignDevBuild, it is installed over the firmware the device already runs.
func (c *Core) UploadDevWWW(ctx context.Context, a Actor, www []byte) (Build, error) {
	if !a.Roles[RoleSuperadmin] {
		return Build{}, userErr(403, "forbidden", "завантажувати збірки може лише superadmin")
	}
	wm, err := CheckWWWTar(www)
	if err != nil {
		return Build{}, err
	}
	id := uuid.NewString()
	sum, err := c.storeDevWWW(id, www)
	if err != nil {
		return Build{}, err
	}
	err = db.InTx(ctx, c.Pool, func(tx pgxTx) error {
		if err := c.insertDevWWW(ctx, tx, a, id, wm, www); err != nil {
			return err
		}
		return a.audit(ctx, tx, "build.upload", "build", id, map[string]any{
			"kind": "dev_www", "version": wm.Version, "www_api": wm.WwwAPI, "sha256": sum})
	})
	return Build{ID: id, Kind: "dev_www", Version: wm.Version, WwwAPI: wm.WwwAPI, Size: len(www), SHA256: sum,
		WWWBuildID: id, WWWVersion: wm.Version}, err
}

func (c *Core) storeDevWWW(id string, www []byte) (string, error) {
	sum := sha256.Sum256(www)
	return hex.EncodeToString(sum[:]), writeFile(c.path("artifacts", id, "www.tar"), www)
}

func (c *Core) insertDevWWW(ctx context.Context, tx pgxTx, a Actor, id string, wm WWWManifest, www []byte) error {
	sum := sha256.Sum256(www)
	_, err := tx.Exec(ctx, `INSERT INTO builds (id, kind, version, www_api, status, artifact_path, sha256, size, created_by)
		VALUES ($1,'dev_www',$2,$3,'success',$4,$5,$6,$7)`, id, wm.Version, wm.WwwAPI,
		c.path("artifacts", id, "www.tar"), sum[:], len(www), a.UserID)
	return err
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
			dev_build_id=CASE WHEN $3 THEN dev_build_id END, dev_www_build_id=CASE WHEN $3 THEN dev_www_build_id END,
			dev_critical=$3 AND dev_critical WHERE id=$1`, id, version, on); err != nil {
			return err
		}
		return a.audit(ctx, tx, "device.dev_mode", "device", id, map[string]any{"dev": on, "config_version": version})
	})
}

// AssignDevBuild offers a dev build to developer devices (ids or serials; "all"
// means every active developer device of the build's profile). A critical
// build is installed without asking, within PollDev seconds. The device gets
// the build's own web UI with it, if it has one. A dev_www build (web UI
// alone) goes to assignDevWWW.
func (c *Core) AssignDevBuild(ctx context.Context, a Actor, buildID string, devices []string, critical bool) ([]string, error) {
	if !a.Roles[RoleSuperadmin] {
		return nil, userErr(403, "forbidden", "лише superadmin")
	}
	var kind string
	if err := c.Pool.QueryRow(ctx, `SELECT kind FROM builds WHERE id::text=$1`, buildID).Scan(&kind); err == nil && kind == "dev_www" {
		return c.assignDevWWW(ctx, a, buildID, devices, critical)
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
				WHERE id::text=$1 OR serial=upper($1) FOR UPDATE`, ref).Scan(&id, &serial, &devProfile, &status, &dev)
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
				dev_www_build_id=(SELECT www_build_id FROM builds WHERE id=$2), pending_release_id=NULL WHERE id=$1`,
				id, buildID, critical); err != nil {
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

// assignDevWWW offers a web UI alone. The device keeps its firmware: the
// assigned dev build, or else the dev build it runs (known by its hash). The
// UI must match that firmware's www_api. With "all", devices that don't fit
// (release firmware, unknown firmware, other www_api) are skipped.
func (c *Core) assignDevWWW(ctx context.Context, a Actor, wwwID string, devices []string, critical bool) ([]string, error) {
	var assigned []string
	err := db.InTx(ctx, c.Pool, func(tx pgxTx) error {
		var version string
		var api int
		err := tx.QueryRow(ctx, `SELECT version, www_api FROM builds WHERE id::text=$1 AND kind='dev_www' AND status='success'`,
			wwwID).Scan(&version, &api)
		if db.IsNoRows(err) {
			return userErr(404, "not_found", "інтерфейс розробника не знайдено")
		}
		if err != nil {
			return err
		}
		all := len(devices) == 1 && devices[0] == "all"
		if all {
			devices = nil
			rows, err := tx.Query(ctx, `SELECT id::text FROM devices WHERE dev_mode AND status='active' ORDER BY serial`)
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
		for _, ref := range devices {
			ref = strings.TrimSpace(ref)
			var id, serial, status, appID string
			var dev bool
			var appAPI int
			err := tx.QueryRow(ctx, `SELECT d.id, d.serial, d.status, d.dev_mode, COALESCE(b.id::text,''), COALESCE(b.www_api,0)
				FROM devices d LEFT JOIN builds b ON b.id = COALESCE(d.dev_build_id,
					(SELECT x.id FROM builds x WHERE x.kind='dev_app' AND x.status='success' AND x.sha256=d.current_app_sha256
						AND x.profile_id=d.profile_id ORDER BY x.created_at DESC LIMIT 1))
				WHERE d.id::text=$1 OR d.serial=upper($1) FOR UPDATE OF d`, ref).Scan(&id, &serial, &status, &dev, &appID, &appAPI)
			if db.IsNoRows(err) {
				return userErr(404, "not_found", "прилад %s не знайдено", ref)
			}
			if err != nil {
				return err
			}
			var problem error
			switch {
			case !dev:
				problem = userErr(409, "not_dev_device", "%s не є приладом розробника", serial)
			case status != "active":
				problem = userErr(409, "revoked", "%s відкликано", serial)
			case appID == "":
				problem = userErr(409, "no_dev_firmware", "на %s не збірка розробника, відома серверу: надішліть інтерфейс разом із прошивкою", serial)
			case appAPI != api:
				problem = userErr(409, "www_api_mismatch", "www_api інтерфейсу (%d) не збігається з www_api прошивки на %s (%d)", api, serial, appAPI)
			}
			if problem != nil {
				if all {
					continue
				}
				return problem
			}
			if _, err := tx.Exec(ctx, `UPDATE devices SET dev_build_id=$2, dev_www_build_id=$3, dev_critical=$4, dev_assigned_at=now(),
				pending_release_id=NULL WHERE id=$1`, id, appID, wwwID, critical); err != nil {
				return err
			}
			if err := a.audit(ctx, tx, "device.dev_www", "device", id, map[string]any{
				"www_build_id": wwwID, "version": version, "app_build_id": appID, "critical": critical}); err != nil {
				return err
			}
			assigned = append(assigned, serial)
		}
		if len(assigned) == 0 {
			if all {
				return userErr(409, "no_devices", "жоден прилад розробника не підходить: потрібна збірка розробника з www_api %d", api)
			}
			return userErr(400, "no_devices", "оберіть хоча б один прилад розробника")
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
		if _, err := tx.Exec(ctx, `UPDATE devices SET dev_build_id=NULL, dev_www_build_id=NULL, dev_critical=false, dev_assigned_at=NULL
			WHERE id::text=$1`, deviceID); err != nil {
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

// autoDevWWW gives a developer device that has no web UI at all (just out of
// bootstrap, or running a dev build pushed without one) the newest web UI that
// fits its assigned dev build by www_api: a dev UI or a release UI, whichever
// was uploaded last. It is stored as an ordinary assignment. An explicit
// assignment, or any UI already on the device, is left alone.
func (c *Core) autoDevWWW(ctx context.Context, deviceID string) error {
	return db.InTx(ctx, c.Pool, func(tx pgxTx) error {
		var wwwID, version string
		err := tx.QueryRow(ctx, `SELECT w.id::text, w.version FROM devices d JOIN builds b ON b.id=d.dev_build_id
			JOIN builds w ON w.kind IN ('dev_www','www') AND w.status='success' AND w.www_api=b.www_api
			WHERE d.id::text=$1 AND d.dev_mode AND d.status='active' AND d.dev_www_build_id IS NULL AND d.current_www_sha256 IS NULL
			ORDER BY w.created_at DESC LIMIT 1 FOR UPDATE OF d`, deviceID).Scan(&wwwID, &version)
		if db.IsNoRows(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE devices SET dev_www_build_id=$2 WHERE id::text=$1`, deviceID, wwwID); err != nil {
			return err
		}
		return audit.Log(ctx, tx, audit.Entry{ActorType: "system", Action: "device.dev_www", TargetType: "device",
			TargetID: audit.Str(deviceID), Details: map[string]any{"www_build_id": wwwID, "version": version, "auto": true}})
	})
}

// devOffer is the dev part of SelectUpdate: the assigned build until the
// device runs it (and the assigned web UI, if any), then nothing (the device
// stays on it). When only the web UI is missing, the offer is named after it.
func (c *Core) devOffer(ctx context.Context, deviceID string) (offer *Offer, assigned bool, err error) {
	var buildID, version, wwwVersion string
	var critical, appInstalled, wwwInstalled bool
	err = c.Pool.QueryRow(ctx, `SELECT COALESCE(d.dev_build_id::text,''), d.dev_critical, COALESCE(b.version,''),
		COALESCE(b.sha256 = d.current_app_sha256, false), w.id IS NULL OR COALESCE(w.sha256 = d.current_www_sha256, false),
		COALESCE(w.version,'')
		FROM devices d LEFT JOIN builds b ON b.id=d.dev_build_id LEFT JOIN builds w ON w.id=d.dev_www_build_id
		WHERE d.id::text=$1 AND d.dev_mode`, deviceID).
		Scan(&buildID, &critical, &version, &appInstalled, &wwwInstalled, &wwwVersion)
	if db.IsNoRows(err) || (err == nil && buildID == "") {
		return nil, false, nil
	}
	if err != nil || (appInstalled && wwwInstalled) {
		return nil, true, err
	}
	if appInstalled {
		version = "www " + wwwVersion
		if len(version) > maxVersion+8 { // the device keeps 39 characters
			version = version[:maxVersion+8]
		}
	}
	mode := "button"
	if critical {
		mode = "auto"
	}
	return &Offer{DevBuildID: buildID, Version: version, Mode: mode, Critical: critical}, true, nil
}

func (c *Core) devManifest(ctx context.Context, s DeviceSession, offer *Offer, appSHA, wwwSHA []byte) (Manifest, error) {
	m := Manifest{Typ: "zir-manifest/1", DeviceID: s.DeviceID, Profile: s.Profile, DevBuildID: offer.DevBuildID, Dev: true,
		Version: offer.Version, Mode: offer.Mode, Critical: offer.Critical, IAT: c.Now().Unix(), EXP: c.Now().Add(manifestTTL).Unix()}
	var sum, wSum []byte
	var size int
	var wSize, wAPI *int
	var wVer *string
	var appVer string
	if err := c.Pool.QueryRow(ctx, `SELECT b.sha256, b.size, b.version, w.sha256, w.size, w.version, w.www_api
		FROM builds b JOIN devices d ON d.id::text=$2 LEFT JOIN builds w ON w.id=d.dev_www_build_id WHERE b.id::text=$1`,
		offer.DevBuildID, s.DeviceID).Scan(&sum, &size, &appVer, &wSum, &wSize, &wVer, &wAPI); err != nil {
		return m, err
	}
	m.App = ManifestApp{Needed: hex.EncodeToString(sum) != hex.EncodeToString(appSHA),
		URL: "/dev/v1/dev-artifacts/" + offer.DevBuildID, Size: encimg.HeaderSize + size, ImgSize: size,
		SHA256: hex.EncodeToString(sum), Version: appVer, Enc: "esp_encrypted_img"}
	if wSum != nil {
		m.WWW = &ManifestWWW{Needed: hex.EncodeToString(wSum) != hex.EncodeToString(wwwSHA),
			URL: "/dev/v1/dev-artifacts/" + offer.DevBuildID + "/www", Format: "tar", Size: *wSize,
			SHA256: hex.EncodeToString(wSum), Version: *wVer, WwwAPI: *wAPI}
	}
	return m, nil
}

// DevWWWPath returns the web UI assigned to this device with the dev build.
func (c *Core) DevWWWPath(ctx context.Context, s DeviceSession, buildID string) (string, error) {
	if s.Revoked {
		return "", errRevoked
	}
	if _, err := uuid.Parse(buildID); err != nil {
		return "", userErr(404, "not_found", "no such build")
	}
	var p string
	err := c.Pool.QueryRow(ctx, `SELECT w.artifact_path FROM devices d JOIN builds b ON b.id=d.dev_build_id
		JOIN builds w ON w.id=d.dev_www_build_id
		WHERE d.id::text=$1 AND d.dev_mode AND b.id::text=$2 AND b.kind='dev_app' AND w.kind IN ('dev_www','www')`, s.DeviceID, buildID).Scan(&p)
	if db.IsNoRows(err) {
		return "", userErr(404, "not_found", "this dev build is not assigned to the device or has no www")
	}
	return p, err
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
		var sum, wSum []byte
		err := tx.QueryRow(ctx, `SELECT b.sha256, w.sha256 FROM builds b JOIN devices d ON d.id=$2
			LEFT JOIN builds w ON w.id=d.dev_www_build_id AND d.dev_build_id=b.id
			WHERE b.id::text=$1 AND b.kind='dev_app'`, r.DevBuildID, s.DeviceID).Scan(&sum, &wSum)
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
			_, err := tx.Exec(ctx, `UPDATE devices SET current_release_id=NULL, current_app_sha256=$2,
				current_www_sha256=COALESCE($3, current_www_sha256) WHERE id=$1`, s.DeviceID, sum, wSum)
			return err
		}
		return nil
	})
}
