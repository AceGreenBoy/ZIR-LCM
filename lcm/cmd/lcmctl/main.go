// lcmctl is the server administration CLI. It runs on the server host (or in
// the lcm container) with the same DATABASE_URL and MASTER_KEY_FILE.
package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/term"

	"zir/lcm/internal/auth"
	"zir/lcm/internal/config"
	"zir/lcm/internal/core"
	"zir/lcm/internal/crypto/appdesc"
	"zir/lcm/internal/crypto/espsig"
	"zir/lcm/internal/db"
	"zir/lcm/internal/signer"
)

const usage = `lcmctl — адміністрування сервера прошивок

  gen-master-key <file>            створити мастер-ключ (32 байти, hex)
  migrate                          застосувати міграції БД
  init-keys                        створити ключі сервера, яких ще немає
  export-pubkeys <dir>             публічні ключі: PEM і zir_server_keys.h для прошивки
  export-signing-key <file>        приватний ключ підпису прошивок (офлайн-копія!)
  sign-app <in.bin> <out.bin>      підписати образ для прошивки по USB
  inspect-app <firmware.bin>       що сервер прочитає з образу і чи прийме його (без БД)
  create-user -login L -name N -roles superadmin,engineer   (пароль читається з stdin)
  set-roles <login> <ролі>         замінити ролі користувача (superadmin,admin,manufacturer,engineer)
  reset-totp <login>               скинути TOTP (втрачено телефон): налаштування при наступному вході

Через API працюючого сервера (LCM_URL, LCM_TOKEN; БД не потрібна):
  push-dev [-devices S1,S2|all] [-critical] <firmware.bin>
                                   завантажити збірку для розробки й призначити приладам розробника
  dev-devices                      прилади розробника і їхні збірки
  push-bootstrap <zir3m-bootstrap-X.bin>
                                   завантажити bootstrap (один образ з 0x0) для «Прошивка USB»
  bootstrap-builds                 збірки bootstrap на сервері

Змінні: DATABASE_URL, MASTER_KEY_FILE.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err := run(context.Background(), os.Args[1], os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, cmd string, args []string) error {
	if cmd == "inspect-app" {
		if len(args) != 1 {
			return fmt.Errorf("usage: inspect-app <firmware.bin>")
		}
		return inspectApp(args[0])
	}
	switch cmd {
	case "push-dev":
		return pushDev(args)
	case "dev-devices":
		return devDevices()
	case "push-bootstrap":
		return pushBootstrap(args)
	case "bootstrap-builds":
		return bootstrapBuilds()
	}
	if cmd == "gen-master-key" {
		if len(args) != 1 {
			return fmt.Errorf("usage: gen-master-key <file>")
		}
		return genMasterKey(args[0])
	}
	cfg, err := config.FromEnv()
	if err != nil {
		return err
	}
	env, err := config.LoadMasterKey(cfg.MasterKeyFile)
	if err != nil {
		return err
	}
	pool, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()

	switch cmd {
	case "migrate":
		return db.Migrate(ctx, pool)
	case "init-keys":
		if err := db.Migrate(ctx, pool); err != nil {
			return err
		}
		created, err := signer.Init(ctx, pool, env)
		if err != nil {
			return err
		}
		if len(created) == 0 {
			fmt.Println("усі ключі вже є, нічого не створено")
		}
		for _, kid := range created {
			fmt.Println("створено", kid)
		}
		if len(created) > 0 {
			fmt.Println("\nНЕГАЙНО зробіть офлайн-копію ключа підпису прошивок: lcmctl export-signing-key <file>")
		}
		return nil
	case "export-pubkeys":
		if len(args) != 1 {
			return fmt.Errorf("usage: export-pubkeys <dir>")
		}
		s, err := signer.Load(ctx, pool, env)
		if err != nil {
			return err
		}
		return exportPubkeys(s, args[0])
	case "export-signing-key":
		if len(args) != 1 {
			return fmt.Errorf("usage: export-signing-key <file>")
		}
		s, err := signer.Load(ctx, pool, env)
		if err != nil {
			return err
		}
		pemData, kid, err := s.ExportPrivatePEM(signer.FwSign)
		if err != nil {
			return err
		}
		if err := os.WriteFile(args[0], pemData, 0o600); err != nil {
			return err
		}
		fmt.Printf("ключ %s записано в %s. Збережіть офлайн і видаліть файл із сервера.\n", kid, args[0])
		return nil
	case "sign-app":
		if len(args) != 2 {
			return fmt.Errorf("usage: sign-app <in.bin> <out.bin>")
		}
		s, err := signer.Load(ctx, pool, env)
		if err != nil {
			return err
		}
		return signApp(s, args[0], args[1])
	case "create-user":
		return createUser(ctx, pool, args)
	case "set-roles":
		if len(args) != 2 {
			return fmt.Errorf("usage: set-roles <login> <ролі через кому>")
		}
		return setRoles(ctx, pool, args[0], args[1])
	case "reset-totp":
		if len(args) != 1 {
			return fmt.Errorf("usage: reset-totp <login>")
		}
		tag, err := pool.Exec(ctx, `UPDATE users SET totp_secret_enc=NULL, totp_enabled=false WHERE login=$1`, args[0])
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return fmt.Errorf("користувача %s не знайдено", args[0])
		}
		pool.Exec(ctx, `DELETE FROM web_sessions WHERE user_id=(SELECT id FROM users WHERE login=$1)`, args[0])
		pool.Exec(ctx, `INSERT INTO audit_log (actor_type, action, target_type, target_id, details)
			SELECT 'system','user.totp_reset','user',id,'{"via":"lcmctl"}' FROM users WHERE login=$1`, args[0])
		fmt.Println("TOTP скинуто, сесії завершено")
		return nil
	default:
		fmt.Fprint(os.Stderr, usage)
		return fmt.Errorf("unknown command %q", cmd)
	}
}

func genMasterKey(path string) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%s already exists, not overwriting", path)
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(k)+"\n"), 0o600); err != nil {
		return err
	}
	fmt.Printf("мастер-ключ записано в %s. Зробіть офлайн-копію окремо від бекапів БД.\n", path)
	return nil
}

func signApp(s *signer.Signer, in, out string) error {
	img, err := os.ReadFile(in)
	if err != nil {
		return err
	}
	d, err := appdesc.Parse(img)
	if err != nil {
		return err
	}
	if d.HasZir && d.DevBuild() {
		return fmt.Errorf("образ зібрано з CONFIG_ZIR_DEV_BUILD: такі збірки не підписуються")
	}
	signed, err := s.SignApp(img)
	if err != nil {
		return err
	}
	if err := os.WriteFile(out, signed, 0o644); err != nil {
		return err
	}
	fmt.Printf("підписано: %s → %s\n", d, out)
	return nil
}

var cPurposes = []struct {
	p    signer.Purpose
	name string
}{
	{signer.Manifest, "MANIFEST"},
	{signer.Config, "CONFIG"},
	{signer.EngToken, "ENGTOKEN"},
	{signer.WWW, "WWW"},
	{signer.Telemetry, "TELEMETRY"},
}

func exportPubkeys(s *signer.Signer, dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	var h strings.Builder
	h.WriteString("/* Generated by `lcmctl export-pubkeys`. Server public keys for the ZIR firmware.\n")
	h.WriteString(" * Several keys per purpose are allowed (key rotation): pick by the JWS \"kid\".\n")
	h.WriteString(" * ZIR_KEYS_FWSIGN: firmware signing keys, for the bootstrap; a release app\n")
	h.WriteString(" * takes the key from its own signature block. */\n#pragma once\n\n")
	h.WriteString("typedef struct {\n    const char *kid;\n    const char *pem;\n} zir_server_key_t;\n\n")

	byPurpose := map[signer.Purpose][]signer.PublicKey{}
	for _, k := range s.PublicKeys() {
		byPurpose[k.Purpose] = append(byPurpose[k.Purpose], k)
		pemData, err := signer.PublicPEM(k.Key)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, k.Kid+".pem"), pemData, 0o644); err != nil {
			return err
		}
	}
	for _, cp := range cPurposes {
		keys := byPurpose[cp.p]
		fmt.Fprintf(&h, "static const zir_server_key_t ZIR_KEYS_%s[] = {\n", cp.name)
		for _, k := range keys {
			if _, ok := k.Key.(*ecdsa.PublicKey); !ok {
				continue
			}
			pemData, _ := signer.PublicPEM(k.Key)
			fmt.Fprintf(&h, "    { %q,\n      ", k.Kid)
			for _, line := range strings.SplitAfter(strings.TrimRight(string(pemData), "\n"), "\n") {
				fmt.Fprintf(&h, "%q\n      ", line)
			}
			h.WriteString("\"\\n\" },\n")
		}
		fmt.Fprintf(&h, "};\n#define ZIR_KEYS_%s_COUNT %d\n\n", cp.name, len(keys))
	}
	// Firmware signing keys (RSA-3072): the running release app takes the key
	// from its own signature block, but the bootstrap may run unsigned and
	// checks Secure Boot V2 signatures of what it installs with these.
	fw := byPurpose[signer.FwSign]
	h.WriteString("static const zir_server_key_t ZIR_KEYS_FWSIGN[] = {\n")
	for _, k := range fw {
		pemData, _ := signer.PublicPEM(k.Key)
		fmt.Fprintf(&h, "    { %q,\n      ", k.Kid)
		for _, line := range strings.SplitAfter(strings.TrimRight(string(pemData), "\n"), "\n") {
			fmt.Fprintf(&h, "%q\n      ", line)
		}
		h.WriteString("\"\\n\" },\n")
	}
	fmt.Fprintf(&h, "};\n#define ZIR_KEYS_FWSIGN_COUNT %d\n\n", len(fw))
	if fw, ok := byPurpose[signer.FwSign]; ok {
		pemData, _ := signer.PublicPEM(fw[0].Key.(*rsa.PublicKey))
		os.WriteFile(filepath.Join(dir, "firmware_signing_pub.pem"), pemData, 0o644)
	}
	path := filepath.Join(dir, "zir_server_keys.h")
	if err := os.WriteFile(path, []byte(h.String()), 0o644); err != nil {
		return err
	}
	fmt.Println("записано", path, "і PEM-файли в", dir)
	return nil
}

// inspectApp prints the descriptions the server reads from an app image and
// the same checks the upload runs (except "profile exists on the server").
func inspectApp(path string) error {
	img, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	d, err := appdesc.Parse(img)
	if err != nil {
		return err
	}
	fmt.Printf("esp_app_desc_t: project=%q version=%q idf=%q built=%s %s chip_id=%d size=%d\n",
		d.Project, d.Version, d.IDF, d.Date, d.Time, d.ChipID, len(img))
	var problems []string
	if d.HasZir {
		fmt.Printf("zir_custom_desc_t: desc_version=%d profile=%q version=%q www_api=%d flags=%#x dev_build=%v\n",
			d.ZirDescVer, d.Profile, d.ZirVersion, d.WwwAPI, d.Flags, d.DevBuild())
		if d.DevBuild() {
			problems = append(problems, "збірка для розробки (CONFIG_ZIR_DEV_BUILD=y) — сервер не підписує")
		}
		if _, err := semver.StrictNewVersion(d.ZirVersion); err != nil {
			problems = append(problems, fmt.Sprintf("version %q не є semver", d.ZirVersion))
		}
		if d.Version != d.ZirVersion {
			problems = append(problems, fmt.Sprintf("PROJECT_VER %q не збігається з ZIR_VERSION %q", d.Version, d.ZirVersion))
		}
		if d.Profile == "" {
			problems = append(problems, "порожній profile")
		}
	} else {
		problems = append(problems, "немає zir_custom_desc_t одразу після esp_app_desc_t (FIRMWARE_REQUIREMENTS 6.4)")
	}
	if d.ChipID != 0 {
		problems = append(problems, "образ не для ESP32")
	}
	if espsig.HasSignature(img) {
		problems = append(problems, "образ уже підписано — потрібен непідписаний (CONFIG_SECURE_BOOT_BUILD_SIGNED_BINARIES=n)")
	}
	if len(img) > core.MaxAppSize-espsig.SectorSize {
		problems = append(problems, fmt.Sprintf("образ %d байт, максимум %d", len(img), core.MaxAppSize-espsig.SectorSize))
	}
	if len(problems) == 0 {
		fmt.Println("OK: сервер прийме образ, якщо профіль", d.Profile, "існує")
		return nil
	}
	for _, p := range problems {
		fmt.Println("ПОМИЛКА:", p)
	}
	return fmt.Errorf("сервер не прийме образ")
}

// readPassword reads a password from the terminal without echo (asked
// twice), or one line from stdin when it is piped.
func readPassword() (string, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return "", fmt.Errorf("пароль не передано в stdin")
		}
		return strings.TrimRight(line, "\r\n"), nil
	}
	fmt.Fprint(os.Stderr, "пароль (від 12 символів): ")
	a, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	fmt.Fprint(os.Stderr, "ще раз: ")
	b, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	if string(a) != string(b) {
		return "", fmt.Errorf("паролі не збігаються")
	}
	return string(a), nil
}

func createUser(ctx context.Context, pool *pgxpool.Pool, args []string) error {
	fs := flag.NewFlagSet("create-user", flag.ContinueOnError)
	login := fs.String("login", "", "логін")
	name := fs.String("name", "", "ім'я")
	roles := fs.String("roles", "", "ролі через кому: superadmin,admin,manufacturer,engineer")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *login == "" || *roles == "" {
		return fmt.Errorf("потрібні -login і -roles")
	}
	roleList, err := parseRoles(*roles)
	if err != nil {
		return err
	}
	pw, err := readPassword()
	if err != nil {
		return err
	}
	if err := auth.ValidatePassword(pw); err != nil {
		return err
	}
	hash, err := auth.HashPassword(pw)
	if err != nil {
		return err
	}
	var id string
	err = db.InTx(ctx, pool, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `INSERT INTO users (login, display_name, password_hash) VALUES ($1,$2,$3) RETURNING id`,
			*login, *name, hash).Scan(&id)
		if db.IsUniqueViolation(err) {
			return fmt.Errorf("користувач %s уже існує (ролі змінює: lcmctl set-roles %s <ролі>)", *login, *login)
		}
		if err != nil {
			return err
		}
		for _, r := range roleList {
			if _, err := tx.Exec(ctx, `INSERT INTO user_roles (user_id, role) VALUES ($1,$2)`, id, r); err != nil {
				return err
			}
		}
		_, err = tx.Exec(ctx, `INSERT INTO audit_log (actor_type, action, target_type, target_id, details)
			VALUES ('system','user.create','user',$1,$2)`, id, map[string]any{"login": *login, "roles": roleList, "via": "lcmctl"})
		return err
	})
	if err != nil {
		return err
	}
	fmt.Printf("користувача %s створено (%s), ролі: %s. TOTP налаштовується при першому вході.\n", *login, id, strings.Join(roleList, ","))
	return nil
}

var validRoles = []string{"superadmin", "admin", "manufacturer", "engineer"}

// parseRoles normalizes "SuperAdmin, engineer" and rejects unknown roles.
func parseRoles(s string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, r := range strings.Split(s, ",") {
		r = strings.ToLower(strings.TrimSpace(r))
		if r == "" || seen[r] {
			continue
		}
		ok := false
		for _, v := range validRoles {
			ok = ok || r == v
		}
		if !ok {
			return nil, fmt.Errorf("невідома роль %q; допустимі: %s", r, strings.Join(validRoles, ", "))
		}
		seen[r] = true
		out = append(out, r)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("вкажіть хоча б одну роль: %s", strings.Join(validRoles, ", "))
	}
	return out, nil
}

// setRoles replaces a user's roles.
func setRoles(ctx context.Context, pool *pgxpool.Pool, login, roles string) error {
	roleList, err := parseRoles(roles)
	if err != nil {
		return err
	}
	return db.InTx(ctx, pool, func(tx pgx.Tx) error {
		var id string
		if err := tx.QueryRow(ctx, `SELECT id FROM users WHERE login=$1`, login).Scan(&id); err != nil {
			if db.IsNoRows(err) {
				return fmt.Errorf("користувача %s не знайдено", login)
			}
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM user_roles WHERE user_id=$1`, id); err != nil {
			return err
		}
		for _, r := range roleList {
			if _, err := tx.Exec(ctx, `INSERT INTO user_roles (user_id, role) VALUES ($1,$2)`, id, r); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `INSERT INTO audit_log (actor_type, action, target_type, target_id, details)
			VALUES ('system','user.roles','user',$1,$2)`, id, map[string]any{"roles": roleList, "via": "lcmctl"}); err != nil {
			return err
		}
		fmt.Printf("ролі %s: %s\n", login, strings.Join(roleList, ","))
		return nil
	})
}
