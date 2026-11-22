package core

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/google/uuid"

	"zir/lcm/internal/crypto/appdesc"
	"zir/lcm/internal/crypto/espsig"
	"zir/lcm/internal/db"
	"zir/lcm/internal/signer"
)

const (
	MaxAppSize = 0x180000 // OTA slot
	// www partition is 0xd8000 (864 KB); keep room for LittleFS metadata
	// (one 4 KB block per small file plus directories).
	MaxWWWContent = 0xd8000 - 96*1024
	zwwwMagic     = "ZWWW"
)

type Build struct {
	ID             string
	Kind           string
	Profile        string
	Version        string
	WwwAPI         int
	Size           int
	SHA256         string
	ComparableHash string
	CreatedAt      time.Time
	CreatedBy      string
	HasELF         bool
	Unchanged      bool // comparable hash equals the previous build of the profile
}

// UploadApp accepts an unsigned app image built for a profile (PlatformIO or
// idf.py with sdkconfig.release.defaults), checks its description and signs it.
func (c *Core) UploadApp(ctx context.Context, a Actor, img, elf []byte) (string, error) {
	if !a.Roles[RoleSuperadmin] {
		return "", userErr(403, "forbidden", "завантажувати збірки може лише superadmin")
	}
	if len(img) == 0 || len(img) > MaxAppSize-espsig.SectorSize {
		return "", userErr(400, "bad_image", "розмір образу має бути до %d байт", MaxAppSize-espsig.SectorSize)
	}
	if espsig.HasSignature(img) {
		return "", userErr(400, "signed", "образ уже підписано: завантажте непідписаний (CONFIG_SECURE_BOOT_BUILD_SIGNED_BINARIES=n)")
	}
	d, err := appdesc.Parse(img)
	if err != nil {
		return "", userErr(400, "bad_image", "це не образ застосунку ESP32: %v", err)
	}
	if d.ChipID != 0 {
		return "", userErr(400, "bad_image", "образ не для ESP32 (chip_id %d)", d.ChipID)
	}
	if !d.HasZir {
		return "", userErr(400, "no_zir_desc", "в образі немає zir_custom_desc_t (FIRMWARE_REQUIREMENTS 6.4)")
	}
	if d.DevBuild() {
		return "", userErr(400, "dev_build", "збірка для розробки (CONFIG_ZIR_DEV_BUILD) не підписується")
	}
	if _, err := semver.StrictNewVersion(d.ZirVersion); err != nil {
		return "", userErr(400, "bad_version", "ZIR_VERSION %q не є semver (наприклад 1.4.0 або 1.5.0-beta.1)", d.ZirVersion)
	}
	prof, _, err := c.Profile(ctx, c.Pool, d.Profile)
	if err != nil {
		return "", userErr(400, "no_profile", "профіль %q з образу не існує на сервері", d.Profile)
	}
	cmp, err := appdesc.ComparableHash(img)
	if err != nil {
		return "", err
	}
	signed, err := c.Signer.SignApp(img)
	if err != nil {
		return "", err
	}
	if _, err := espsig.Verify(signed, c.Signer.FirmwarePublicKey()); err != nil {
		return "", fmt.Errorf("self-check of signature failed: %w", err)
	}
	sum := sha256.Sum256(signed)
	id := uuid.NewString()
	if err := writeFile(c.path("artifacts", id, "app.bin"), signed); err != nil {
		return "", err
	}
	if err := writeFile(c.path("artifacts", id, "unsigned.bin"), img); err != nil {
		return "", err
	}
	var elfPath *string
	if len(elf) > 0 {
		p := c.path("artifacts", id, "app.elf")
		if err := writeFile(p, elf); err != nil {
			return "", err
		}
		elfPath = &p
	}
	err = db.InTx(ctx, c.Pool, func(tx pgxTx) error {
		_, err := tx.Exec(ctx, `INSERT INTO builds (id, kind, profile_id, version, www_api, status, artifact_path, elf_path,
			sha256, size, comparable_hash, signed_at, created_by) VALUES ($1,'app',$2,$3,$4,'success',$5,$6,$7,$8,$9,now(),$10)`,
			id, prof.ID, d.ZirVersion, int(d.WwwAPI), c.path("artifacts", id, "app.bin"), elfPath, sum[:], len(signed), cmp[:], a.UserID)
		if err != nil {
			return err
		}
		return a.audit(ctx, tx, "build.upload", "build", id, map[string]any{
			"kind": "app", "profile": d.Profile, "version": d.ZirVersion, "app_version": d.Version, "sha256": hex.EncodeToString(sum[:])})
	})
	return id, err
}

// WWWManifest is dist/manifest.json of the web UI.
type WWWManifest struct {
	Version string `json:"version"`
	WwwAPI  int    `json:"www_api"`
}

// CheckWWWTar validates a web UI archive the way the device will unpack it.
func CheckWWWTar(data []byte) (WWWManifest, error) {
	var m WWWManifest
	tr := tar.NewReader(bytes.NewReader(data))
	total := 0
	found := false
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return m, userErr(400, "bad_tar", "файл не є архівом .tar: %v", err)
		}
		name := strings.TrimPrefix(path.Clean("/"+h.Name), "/")
		if strings.Contains(h.Name, "..") || strings.HasPrefix(h.Name, "/") {
			return m, userErr(400, "bad_tar", "недопустимий шлях в архіві: %s", h.Name)
		}
		switch h.Typeflag {
		case tar.TypeDir:
			continue
		case tar.TypeReg:
		default:
			return m, userErr(400, "bad_tar", "в архіві дозволені лише файли й каталоги: %s", h.Name)
		}
		if strings.HasPrefix(path.Base(name), "._") {
			continue
		}
		total += int(h.Size)
		if name == "manifest.json" {
			body, _ := io.ReadAll(io.LimitReader(tr, 4096))
			if err := json.Unmarshal(body, &m); err != nil {
				return m, userErr(400, "bad_manifest", "manifest.json не розбирається: %v", err)
			}
			found = true
		}
	}
	if !found {
		return m, userErr(400, "no_manifest", "в архіві немає нестиснутого manifest.json (scripts/gzip.mjs не має його стискати)")
	}
	if _, err := semver.NewVersion(m.Version); err != nil || m.WwwAPI <= 0 {
		return m, userErr(400, "bad_manifest", "manifest.json: потрібні version (semver) і www_api > 0")
	}
	if total > MaxWWWContent {
		return m, userErr(400, "too_big", "інтерфейс займає %d КБ, у розділ www вміщується близько %d КБ", total/1024, MaxWWWContent/1024)
	}
	return m, nil
}

// ZWWWHeader is the signed header of a .zwww container (ARCHITECTURE 7.8).
type ZWWWHeader struct {
	Typ     string `json:"typ"`
	Kid     string `json:"kid"`
	Version string `json:"version"`
	WwwAPI  int    `json:"www_api"`
	Size    int    `json:"size"`
	SHA256  string `json:"sha256"`
}

// MakeZWWW wraps a tar: "ZWWW" | u16 hlen | header | u16 slen | ES256(K_www, header) | tar.
func MakeZWWW(s *signer.Signer, m WWWManifest, tarData []byte) ([]byte, error) {
	sum := sha256.Sum256(tarData)
	h := ZWWWHeader{Typ: "zir-www/1", Version: m.Version, WwwAPI: m.WwwAPI, Size: len(tarData), SHA256: hex.EncodeToString(sum[:])}
	h.Kid = s.ActiveKid(signer.WWW)
	hdr, _ := json.Marshal(h)
	_, sig, err := s.SignRaw(signer.WWW, hdr)
	if err != nil {
		return nil, err
	}
	out := []byte(zwwwMagic)
	out = binary.LittleEndian.AppendUint16(out, uint16(len(hdr)))
	out = append(out, hdr...)
	out = binary.LittleEndian.AppendUint16(out, uint16(len(sig)))
	out = append(out, sig...)
	return append(out, tarData...), nil
}

// ParseZWWW splits and verifies a container (used by tests and the simulator).
func ParseZWWW(data []byte, verify func(kid string, msg, sig []byte) bool) (ZWWWHeader, []byte, error) {
	var h ZWWWHeader
	if len(data) < 8 || string(data[:4]) != zwwwMagic {
		return h, nil, errors.New("not a zwww container")
	}
	hl := int(binary.LittleEndian.Uint16(data[4:6]))
	if len(data) < 6+hl+2 {
		return h, nil, errors.New("truncated")
	}
	hdr := data[6 : 6+hl]
	sl := int(binary.LittleEndian.Uint16(data[6+hl : 8+hl]))
	if len(data) < 8+hl+sl {
		return h, nil, errors.New("truncated")
	}
	sig := data[8+hl : 8+hl+sl]
	if err := json.Unmarshal(hdr, &h); err != nil {
		return h, nil, err
	}
	if !verify(h.Kid, hdr, sig) {
		return h, nil, errors.New("bad signature")
	}
	body := data[8+hl+sl:]
	sum := sha256.Sum256(body)
	if len(body) != h.Size || hex.EncodeToString(sum[:]) != h.SHA256 {
		return h, nil, errors.New("hash mismatch")
	}
	return h, body, nil
}

func (c *Core) UploadWWW(ctx context.Context, a Actor, tarData []byte) (string, error) {
	if !a.Roles[RoleSuperadmin] {
		return "", userErr(403, "forbidden", "завантажувати збірки може лише superadmin")
	}
	m, err := CheckWWWTar(tarData)
	if err != nil {
		return "", err
	}
	zwww, err := MakeZWWW(c.Signer, m, tarData)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(tarData)
	id := uuid.NewString()
	tarPath, zPath := c.path("artifacts", id, "www.tar"), c.path("artifacts", id, "www.zwww")
	if err := writeFile(tarPath, tarData); err != nil {
		return "", err
	}
	if err := writeFile(zPath, zwww); err != nil {
		return "", err
	}
	err = db.InTx(ctx, c.Pool, func(tx pgxTx) error {
		_, err := tx.Exec(ctx, `INSERT INTO builds (id, kind, version, www_api, status, artifact_path, zwww_path, sha256, size, signed_at, created_by)
			VALUES ($1,'www',$2,$3,'success',$4,$5,$6,$7,now(),$8)`, id, m.Version, m.WwwAPI, tarPath, zPath, sum[:], len(tarData), a.UserID)
		if err != nil {
			return err
		}
		return a.audit(ctx, tx, "build.upload", "build", id, map[string]any{"kind": "www", "version": m.Version, "www_api": m.WwwAPI})
	})
	return id, err
}

func (c *Core) Builds(ctx context.Context, kind string) ([]Build, error) {
	rows, err := c.Pool.Query(ctx, `SELECT b.id, b.kind, COALESCE(p.code,''), b.version, COALESCE(b.www_api,0), COALESCE(b.size,0),
		encode(b.sha256,'hex'), COALESCE(encode(b.comparable_hash,'hex'),''), b.created_at, COALESCE(u.login,''), b.elf_path IS NOT NULL,
		COALESCE(b.comparable_hash = (SELECT p2.comparable_hash FROM builds p2 WHERE p2.kind=b.kind AND p2.profile_id=b.profile_id
			AND p2.created_at < b.created_at ORDER BY p2.created_at DESC LIMIT 1), false)
		FROM builds b LEFT JOIN hw_profiles p ON p.id=b.profile_id LEFT JOIN users u ON u.id=b.created_by
		WHERE b.status='success' AND ($1='' OR b.kind=$1) ORDER BY b.created_at DESC LIMIT 200`, kind)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Build
	for rows.Next() {
		var b Build
		if err := rows.Scan(&b.ID, &b.Kind, &b.Profile, &b.Version, &b.WwwAPI, &b.Size, &b.SHA256, &b.ComparableHash,
			&b.CreatedAt, &b.CreatedBy, &b.HasELF, &b.Unchanged); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// BuildFile returns the path of a downloadable build file: "app.bin"
// (signed, for USB flashing), "app.elf", "www.tar", "www.zwww".
func (c *Core) BuildFile(ctx context.Context, a Actor, buildID, name string) (string, error) {
	if err := a.require(RoleEngineer); err != nil {
		return "", err
	}
	switch name {
	case "app.bin", "app.elf", "www.tar", "www.zwww":
	default:
		return "", userErr(404, "not_found", "немає такого файлу")
	}
	if _, err := uuid.Parse(buildID); err != nil {
		return "", userErr(404, "not_found", "немає такої збірки")
	}
	p := c.path("artifacts", buildID, name)
	if _, err := os.Stat(p); err != nil {
		return "", userErr(404, "not_found", "файл відсутній")
	}
	c.Pool.Exec(ctx, `INSERT INTO audit_log (actor_type, actor_id, action, target_type, target_id, details) VALUES
		('user',$1,'build.download','build',$2,$3)`, a.UserID, buildID, map[string]any{"file": name})
	return p, nil
}
