// End-to-end test: real PostgreSQL, real HTTP device API, device simulator.
// Needs TEST_DATABASE_URL pointing to a server where the user may create
// databases (make db; see Makefile).
package e2e

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"zir/lcm/internal/core"
	"zir/lcm/internal/crypto/appdesc"
	"zir/lcm/internal/crypto/envelope"
	"zir/lcm/internal/db"
	"zir/lcm/internal/devicesim"
	"zir/lcm/internal/httpapi"
	"zir/lcm/internal/signer"
)

type env struct {
	t      *testing.T
	ctx    context.Context
	core   *core.Core
	srv    *httptest.Server
	keys   devicesim.Keys
	super  core.Actor
	maker  core.Actor
	eng    core.Actor
	viewer core.Actor
}

func setup(t *testing.T) *env {
	base := os.Getenv("TEST_DATABASE_URL")
	if base == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("fwtest_%x", randBytes(4))
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		admin.Exec(context.Background(), "DROP DATABASE "+name+" WITH (FORCE)")
		admin.Close(context.Background())
	})
	u, _ := url.Parse(base)
	u.Path = "/" + name
	pool, err := db.Open(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := db.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	envKey, _ := envelope.New(randBytes(32))
	if _, err := signer.Init(ctx, pool, envKey); err != nil {
		t.Fatal(err)
	}
	s, err := signer.Load(ctx, pool, envKey)
	if err != nil {
		t.Fatal(err)
	}
	c := core.New(pool, s, envKey, t.TempDir())

	r := chi.NewRouter()
	r.Mount("/dev/v1", (&httpapi.API{Core: c}).Routes())
	r.Mount("/api/v1", (&httpapi.AdminAPI{Core: c}).Routes())
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)

	keys := devicesim.Keys{ES256: map[string]*ecdsa.PublicKey{}, Telemetry: s.TelemetryPublic(), Firmware: s.FirmwarePublicKey()}
	for _, k := range s.PublicKeys() {
		if ek, ok := k.Key.(*ecdsa.PublicKey); ok && k.Purpose != signer.Telemetry {
			keys.ES256[k.Kid] = ek
		}
	}
	e := &env{t: t, ctx: ctx, core: c, srv: srv, keys: keys}
	e.super = e.user("root", core.RoleSuperadmin)
	e.maker = e.user("maker", core.RoleManufacturer)
	e.eng = e.user("eng", core.RoleEngineer)
	e.viewer = e.user("viewer", core.RoleAdmin)
	return e
}

func randBytes(n int) []byte { b := make([]byte, n); rand.Read(b); return b }

// Random, not sequential (core.newSerial).
var serialRe = regexp.MustCompile(`^ZIR-[0-9A-HJKMNP-TV-Z]{7}$`)

func (e *env) user(login, role string) core.Actor {
	var id string
	if err := e.core.Pool.QueryRow(e.ctx, `INSERT INTO users (login, password_hash) VALUES ($1,'x') RETURNING id`, login).Scan(&id); err != nil {
		e.t.Fatal(err)
	}
	e.core.Pool.Exec(e.ctx, `INSERT INTO user_roles VALUES ($1,$2)`, id, role)
	return core.Actor{UserID: id, Login: login, Roles: map[string]bool{role: true}, IP: "127.0.0.1"}
}

func (e *env) must(err error) {
	e.t.Helper()
	if err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) wantCode(err error, code string) {
	e.t.Helper()
	var ae *devicesim.APIError
	if ce, ok := core.AsError(err); ok && ce.Code == code {
		return
	}
	if errors.As(err, &ae) && ae.Code == code {
		return
	}
	e.t.Fatalf("want error %q, got %v", code, err)
}

func (e *env) registerDevice(mac string) *devicesim.Device {
	e.t.Helper()
	d, err := devicesim.New(e.srv.URL, e.keys, mac, "zir3m-full")
	e.must(err)
	code, err := d.Register(e.ctx)
	e.must(err)
	st, err := d.PollRegistration(e.ctx)
	e.must(err)
	if st != "pending" {
		e.t.Fatalf("status %s", st)
	}
	cl, err := e.core.ClaimCode(e.ctx, e.maker, "", strings.ToLower(core.FormatClaim(code)))
	e.must(err)
	_, err = e.core.Approve(e.ctx, e.maker, core.ApproveInput{RequestID: cl.RequestID, Profile: "zir3m-full",
		Params: core.DefaultParams(core.DefaultModules())})
	e.must(err)
	st, err = d.PollRegistration(e.ctx)
	e.must(err)
	if st != "approved" || d.State.DeviceID == "" || !serialRe.MatchString(d.State.Serial) {
		e.t.Fatalf("registration: %s %+v", st, d.State)
	}
	e.must(d.Auth(e.ctx))
	return d
}

func wwwTar(t *testing.T, version string, api int) []byte {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	add := func(name, body string) {
		tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
		tw.Write([]byte(body))
	}
	add("./manifest.json", fmt.Sprintf(`{"version":%q,"www_api":%d}`, version, api))
	add("./index.html.gz", "fake-gzip")
	add("./assets/app.js.gz", strings.Repeat("x", 5000))
	tw.Close()
	return buf.Bytes()
}

func (e *env) uploadApp(version string, body byte) string {
	e.t.Helper()
	id, err := e.core.UploadApp(e.ctx, e.super, appdesc.Build(version, "zir3m-full", 3, 0, bytes.Repeat([]byte{body}, 20000)), nil)
	e.must(err)
	return id
}

func (e *env) profileID() string {
	p, _, err := e.core.Profile(e.ctx, e.core.Pool, "zir3m-full")
	e.must(err)
	return p.ID
}

func (e *env) release(version, app, www string) string {
	e.t.Helper()
	id, err := e.core.CreateRelease(e.ctx, e.super, core.ReleaseInput{Version: version, WWWBuildID: www, Apps: map[string]string{e.profileID(): app}})
	e.must(err)
	return id
}

func TestFullCycle(t *testing.T) {
	e := setup(t)
	ctx := e.ctx

	// Profile.
	mods := core.DefaultModules()
	_, err := e.core.SaveProfile(ctx, e.super, "", core.ProfileInput{Code: "zir3m-full", Name: "ZIR-3M, усі модулі", Modules: mods, Defaults: core.DefaultParams(mods)})
	e.must(err)

	// An unregistered device has no id: it cannot even start a session.
	ghost, _ := devicesim.New(e.srv.URL, e.keys, "28:05:a5:00:00:99", "zir3m-full")
	ghost.State.DeviceID = "00000000-0000-0000-0000-000000000000"
	e.wantCode(ghost.Auth(ctx), "unknown_device")

	// Only manufacturers approve; wrong codes are counted.
	_, err = e.core.ClaimCode(ctx, e.eng, "", "AAAA-AAAA")
	e.wantCode(err, "forbidden")
	_, err = e.core.ClaimCode(ctx, e.maker, "", "ZZZZ-ZZZZ")
	e.wantCode(err, "not_found")

	d1 := e.registerDevice("28:05:A5:2C:CA:30")
	d2 := e.registerDevice("28:05:a5:2c:ca:31")

	// No releases yet.
	m, err := d1.CheckUpdate(ctx)
	e.must(err)
	if m != nil {
		t.Fatal("unexpected offer")
	}

	// Build checks.
	_, err = e.core.UploadApp(ctx, e.super, appdesc.Build("1.0.0", "zir3m-full", 3, appdesc.FlagDevBuild, make([]byte, 100)), nil)
	e.wantCode(err, "dev_build")
	_, err = e.core.UploadApp(ctx, e.super, appdesc.Build("1.0.0", "other", 3, 0, make([]byte, 100)), nil)
	e.wantCode(err, "no_profile")
	_, err = e.core.UploadApp(ctx, e.super, appdesc.Build("main-dirty", "zir3m-full", 3, 0, make([]byte, 100)), nil)
	e.wantCode(err, "bad_version")
	signed, _ := e.core.Signer.SignApp(appdesc.Build("1.0.0", "zir3m-full", 3, 0, make([]byte, 100)))
	_, err = e.core.UploadApp(ctx, e.super, signed, nil)
	e.wantCode(err, "signed")
	_, err = e.core.UploadApp(ctx, e.eng, appdesc.Build("1.0.0", "zir3m-full", 3, 0, make([]byte, 100)), nil)
	e.wantCode(err, "forbidden")
	_, err = e.core.UploadWWW(ctx, e.super, []byte("not a tar"))
	e.wantCode(err, "bad_tar")

	app100 := e.uploadApp("1.0.0", 1)
	www100, err := e.core.UploadWWW(ctx, e.super, wwwTar(t, "1.0.0", 3))
	e.must(err)

	// .zwww container verifies with the www key.
	zpath, err := e.core.BuildFile(ctx, e.eng, www100, "www.zwww")
	e.must(err)
	zdata, _ := os.ReadFile(zpath)
	if _, _, err := core.ParseZWWW(zdata, func(kid string, msg, sig []byte) bool {
		k := e.keys.Lookup("www")(kid)
		return k != nil && verifyRaw(k, msg, sig)
	}); err != nil {
		t.Fatalf("zwww: %v", err)
	}

	// Beta is not offered to users.
	r100 := e.release("1.0.0", app100, www100)
	if m, _ := d1.CheckUpdate(ctx); m != nil {
		t.Fatal("beta offered")
	}
	e.must(e.core.Promote(ctx, e.super, r100, false))
	m, err = d1.CheckUpdate(ctx)
	e.must(err)
	if m == nil || m.Mode != "button" || m.Version != "1.0.0" || !m.App.Needed || m.WWW == nil || !m.WWW.Needed {
		t.Fatalf("offer: %+v", m)
	}

	// Core property: the image d1 gets is useless on d2.
	enc1, err := d1.Download(ctx, m.App.URL)
	e.must(err)
	if err := devicesim.DecryptWith(enc1, d2.State.OTAKeyPEM); err == nil {
		t.Fatal("d1 image decrypted with d2 key")
	}
	if err := devicesim.DecryptWith(enc1, d1.State.OTAKeyPEM); err != nil {
		t.Fatalf("d1 cannot decrypt own image: %v", err)
	}
	// Without a session nothing is served.
	noAuth, _ := http.Get(e.srv.URL + m.App.URL)
	if noAuth.StatusCode != 401 {
		t.Fatalf("artifact without session: %d", noAuth.StatusCode)
	}
	// The encrypted image is cached, so a resumed download (HTTP Range) sees the same bytes.
	again, err := d1.Download(ctx, m.App.URL)
	e.must(err)
	if !bytes.Equal(again, enc1) {
		t.Fatal("cached image changed between downloads")
	}

	e.must(d1.Install(ctx, m))
	e.must(d1.Auth(ctx))
	if m, _ := d1.CheckUpdate(ctx); m != nil {
		t.Fatalf("offered again after install: %+v", m)
	}

	// www-only release: app not needed, www needed; no endless re-offer.
	www101, err := e.core.UploadWWW(ctx, e.super, wwwTar(t, "1.0.1", 3))
	e.must(err)
	r101 := e.release("1.0.1", app100, www101)
	e.must(e.core.Promote(ctx, e.super, r101, false))
	m, err = d1.CheckUpdate(ctx)
	e.must(err)
	if m == nil || m.App.Needed || !m.WWW.Needed {
		t.Fatalf("www-only offer: %+v", m)
	}
	e.must(d1.Install(ctx, m))
	e.must(d1.Auth(ctx))
	if m, _ := d1.CheckUpdate(ctx); m != nil {
		t.Fatal("www-only release offered again")
	}

	// Engineer assigns a beta, then a downgrade.
	app110 := e.uploadApp("1.1.0-beta.1", 2)
	r110 := e.release("1.1.0-beta.1", app110, www101)
	e.must(e.core.AssignRelease(ctx, e.eng, d1.State.DeviceID, r110))
	m, _ = d1.CheckUpdate(ctx)
	if m == nil || m.Mode != "engineer" || m.Version != "1.1.0-beta.1" {
		t.Fatalf("engineer offer: %+v", m)
	}
	e.must(d1.Install(ctx, m))
	e.must(d1.Auth(ctx))
	if m, _ := d1.CheckUpdate(ctx); m != nil {
		t.Fatalf("stable 1.0.1 offered over beta 1.1.0-beta.1: %+v", m)
	}
	e.must(e.core.AssignRelease(ctx, e.eng, d1.State.DeviceID, r100))
	m, _ = d1.CheckUpdate(ctx)
	e.must(d1.Install(ctx, m))
	e.must(d1.Auth(ctx))
	if d1.State.AppVersion != "1.0.0" {
		t.Fatalf("downgrade: %s", d1.State.AppVersion)
	}
	// After the downgrade the user sees the newest stable (rule "а"); pinning hides it.
	if m, _ := d1.CheckUpdate(ctx); m == nil || m.Version != "1.0.1" {
		t.Fatalf("after downgrade: %+v", m)
	}
	e.must(e.core.SetFlags(ctx, e.eng, d1.State.DeviceID, false, true))
	if m, _ := d1.CheckUpdate(ctx); m != nil {
		t.Fatal("pinned device got an offer")
	}
	e.must(e.core.SetFlags(ctx, e.eng, d1.State.DeviceID, false, false))

	// Critical: auto for normal devices, a button for test devices.
	app120 := e.uploadApp("1.2.0", 3)
	r120 := e.release("1.2.0", app120, www101)
	e.must(e.core.Promote(ctx, e.super, r120, true))
	if m, _ := d1.CheckUpdate(ctx); m == nil || m.Mode != "auto" || !m.Critical {
		t.Fatalf("critical: %+v", m)
	}
	e.must(e.core.SetFlags(ctx, e.eng, d2.State.DeviceID, true, false))
	if m, _ := d2.CheckUpdate(ctx); m == nil || m.Mode != "button" {
		t.Fatalf("critical on test device: %+v", m)
	}

	// Config change reaches the device on the next check.
	p := core.DefaultParams(mods)
	p.Ranges["rx5808"] = core.Range{Min: 5600, Max: 6000}
	e.must(e.core.UpdateConfig(ctx, e.eng, d1.State.DeviceID, p))
	bad := core.DefaultParams(mods)
	bad.Ranges["rx5808"] = core.Range{Min: 100, Max: 6000}
	e.wantCode(e.core.UpdateConfig(ctx, e.eng, d1.State.DeviceID, bad), "bad_params")
	before := d1.State.ConfigVer
	d1.CheckUpdate(ctx)
	if d1.State.ConfigVer != before+1 {
		t.Fatalf("config version %d, want %d", d1.State.ConfigVer, before+1)
	}

	// Password change is visible to engineers only, and audited.
	e.must(d1.ChangeWebPassword(ctx, "new-secret-1"))
	pw, err := e.core.WebPassword(ctx, e.eng, d1.State.DeviceID)
	e.must(err)
	if pw != "new-secret-1" {
		t.Fatalf("password %q", pw)
	}
	_, err = e.core.WebPassword(ctx, e.viewer, d1.State.DeviceID)
	e.wantCode(err, "forbidden")

	// Revocation: no updates, no artifacts.
	e.wantCode(e.core.SetRevoked(ctx, e.eng, d2.State.DeviceID, true, "test"), "forbidden")
	e.must(e.core.SetRevoked(ctx, e.super, d2.State.DeviceID, true, "клон"))
	_, err = d2.CheckUpdate(ctx)
	e.wantCode(err, "device_revoked")
	_, err = d2.Download(ctx, "/dev/v1/artifacts/"+r120+"/app")
	e.wantCode(err, "device_revoked")

	// Re-registration of the same MAC needs the explicit choice, and new keys
	// make the old identity useless.
	d1b, _ := devicesim.New(e.srv.URL, e.keys, d1.State.MAC, "zir3m-full")
	code, err := d1b.Register(ctx)
	e.must(err)
	cl, err := e.core.ClaimCode(ctx, e.maker, "", code)
	e.must(err)
	if cl.ExistingDevice != d1.State.DeviceID {
		t.Fatal("duplicate MAC not detected")
	}
	_, err = e.core.Approve(ctx, e.maker, core.ApproveInput{RequestID: cl.RequestID, Profile: "zir3m-full", Params: p})
	e.wantCode(err, "mac_exists")
	_, err = e.core.Approve(ctx, e.maker, core.ApproveInput{RequestID: cl.RequestID, Profile: "zir3m-full", Params: p, Reregister: true})
	e.must(err)
	_, err = d1b.PollRegistration(ctx)
	e.must(err)
	e.wantCode(d1.Auth(ctx), "bad_signature") // old dev_sign key no longer accepted
	e.must(d1b.Auth(ctx))

	var anomalies int
	e.core.Pool.QueryRow(ctx, `SELECT count(*) FROM anomalies WHERE type IN ('duplicate_registration','bad_signature')`).Scan(&anomalies)
	if anomalies < 2 {
		t.Fatalf("anomalies: %d", anomalies)
	}
	var audits int
	e.core.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_log`).Scan(&audits)
	t.Logf("audit records: %d", audits)
}

func verifyRaw(k *ecdsa.PublicKey, msg, sig []byte) bool {
	return jwsVerify(k, msg, sig)
}
