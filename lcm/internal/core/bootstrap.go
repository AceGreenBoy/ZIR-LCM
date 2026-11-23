package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/google/uuid"

	"zir/lcm/internal/db"
	"zir/lcm/internal/flashimg"
	"zir/lcm/internal/signer"
)

// Bootstrap builds: the single image written at 0x0 by USB
// (ZIR_3M/bootstrap, zir3m-bootstrap-<version>.bin). The admin UI flashes it
// from the browser (Web Serial), lcmctl push-bootstrap uploads it.
//
// The image is stored as is, without a signature: at L0 the ROM bootloader
// checks nothing, and the bootstrap carries no secrets (ARCHITECTURE 10).
// What matters is that it was built for this server: it must embed the
// server's config key, or it could not verify its device config.

const (
	BootstrapProject = "zir_bootstrap"
	MaxBootstrapSize = 0x190000 // end of ota_0
)

type BootstrapInfo struct {
	Version   string
	FlashSize string
	FlashMode string
	Size      int
}

// CheckBootstrap validates a merged bootstrap image. keys are the server's
// public keys; nil skips the "built for this server" check (lcmctl, offline).
func CheckBootstrap(img []byte, keys []signer.PublicKey) (BootstrapInfo, error) {
	in := BootstrapInfo{Size: len(img)}
	if len(img) == 0 || len(img) > MaxBootstrapSize {
		return in, userErr(400, "bad_image", "розмір образу має бути до %d байт", MaxBootstrapSize)
	}
	fi, err := flashimg.Parse(img)
	if err != nil {
		return in, userErr(400, "bad_image", "%v", err)
	}
	if fi.Desc.Project != BootstrapProject {
		return in, userErr(400, "not_bootstrap", "в ota_0 застосунок %q, а не bootstrap (%s)", fi.Desc.Project, BootstrapProject)
	}
	if fi.FlashSize != "4MB" {
		return in, userErr(400, "bad_image", "образ зібрано для flash %s, у приладу 4MB", fi.FlashSize)
	}
	if _, err := semver.StrictNewVersion(fi.Desc.Version); err != nil {
		return in, userErr(400, "bad_version", "версія bootstrap %q не є semver (bootstrap/version.txt)", fi.Desc.Version)
	}
	in.Version, in.FlashSize, in.FlashMode = fi.Desc.Version, fi.FlashSize, fi.FlashMode
	if keys == nil {
		return in, nil
	}
	for _, k := range keys {
		if k.Purpose != signer.Config {
			continue
		}
		pemData, err := signer.PublicPEM(k.Key)
		if err != nil {
			return in, err
		}
		if bytes.Contains(img, bytes.TrimSpace(pemData)) {
			return in, nil
		}
	}
	return in, userErr(400, "foreign_server", "bootstrap зібрано для іншого сервера: у ньому немає ключа конфігурацій цього сервера "+
		"(lcm_server/zir_server_keys.h і url.txt мають бути з lcmctl export-pubkeys цього сервера)")
}

// UploadBootstrap stores a bootstrap image after CheckBootstrap.
func (c *Core) UploadBootstrap(ctx context.Context, a Actor, img []byte) (Build, error) {
	if !a.Roles[RoleSuperadmin] {
		return Build{}, userErr(403, "forbidden", "завантажувати збірки може лише superadmin")
	}
	in, err := CheckBootstrap(img, c.Signer.PublicKeys())
	if err != nil {
		return Build{}, err
	}
	sum := sha256.Sum256(img)
	var dup string
	err = c.Pool.QueryRow(ctx, `SELECT version FROM builds WHERE kind='bootstrap' AND status='success' AND sha256=$1 LIMIT 1`, sum[:]).Scan(&dup)
	if err == nil {
		return Build{}, userErr(409, "duplicate", "цей образ уже завантажено (bootstrap %s)", dup)
	}
	if !db.IsNoRows(err) {
		return Build{}, err
	}
	id := uuid.NewString()
	p := c.path("artifacts", id, "bootstrap.bin")
	if err := writeFile(p, img); err != nil {
		return Build{}, err
	}
	err = db.InTx(ctx, c.Pool, func(tx pgxTx) error {
		_, err := tx.Exec(ctx, `INSERT INTO builds (id, kind, version, status, artifact_path, sha256, size, created_by)
			VALUES ($1,'bootstrap',$2,'success',$3,$4,$5,$6)`, id, in.Version, p, sum[:], len(img), a.UserID)
		if err != nil {
			return err
		}
		return a.audit(ctx, tx, "build.upload", "build", id, map[string]any{
			"kind": "bootstrap", "version": in.Version, "sha256": hex.EncodeToString(sum[:])})
	})
	return Build{ID: id, Kind: "bootstrap", Version: in.Version, Size: len(img), SHA256: hex.EncodeToString(sum[:])}, err
}

// BootstrapFlashed records that the admin UI wrote a bootstrap to a chip, so
// the audit log ties a MAC to the image and the person (the browser reports
// it; nothing here is trusted beyond that).
func (c *Core) BootstrapFlashed(ctx context.Context, a Actor, buildID, mac, chip string, erased bool) error {
	if err := a.require(RoleManufacturer, RoleEngineer); err != nil {
		return err
	}
	if _, err := uuid.Parse(buildID); err != nil {
		return userErr(404, "not_found", "немає такої збірки")
	}
	mac = strings.ToLower(strings.TrimSpace(mac))
	if !macRe.MatchString(mac) {
		return userErr(400, "bad_mac", "невірний MAC")
	}
	if len(chip) > 80 {
		chip = chip[:80]
	}
	var version string
	if err := c.Pool.QueryRow(ctx, `SELECT version FROM builds WHERE id::text=$1 AND kind='bootstrap'`, buildID).Scan(&version); err != nil {
		if db.IsNoRows(err) {
			return userErr(404, "not_found", "немає такої збірки")
		}
		return err
	}
	return a.audit(ctx, c.Pool, "bootstrap.flash", "build", buildID, map[string]any{
		"version": version, "mac": mac, "chip": chip, "erase_all": erased})
}

var macRe = regexp.MustCompile(`^[0-9a-f]{2}(:[0-9a-f]{2}){5}$`)
