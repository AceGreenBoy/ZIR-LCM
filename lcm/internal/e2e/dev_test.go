package e2e

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"

	"zir/lcm/internal/core"
	"zir/lcm/internal/crypto/appdesc"
	"zir/lcm/internal/devicesim"
	"zir/lcm/internal/httpapi"
)

func (e *env) profile() {
	mods := core.DefaultModules()
	_, err := e.core.SaveProfile(e.ctx, e.super, "", core.ProfileInput{Code: "zir3m-full", Name: "ZIR-3M", Modules: mods, Defaults: core.DefaultParams(mods)})
	e.must(err)
}

func devImage(version string, body byte) []byte {
	return appdesc.Build(version, "zir3m-full", 3, appdesc.FlagDevBuild, bytes.Repeat([]byte{body}, 20000))
}

// A bootstrap shows up in the waiting list; the code from its screen must
// match the picked device; a restarted bootstrap replaces its old request.
func TestWaitingList(t *testing.T) {
	e := setup(t)
	ctx := e.ctx
	e.profile()

	d, _ := devicesim.New(e.srv.URL, e.keys, "28:05:a5:10:00:01", "zir3m-full")
	_, err := d.Register(ctx)
	e.must(err)
	oldReq := d.State.RequestID
	code, err := d.Register(ctx) // bootstrap restarted
	e.must(err)

	_, err = e.core.PendingRegistrations(ctx, e.eng)
	e.wantCode(err, "forbidden")
	list, err := e.core.PendingRegistrations(ctx, e.maker)
	e.must(err)
	if len(list) != 1 || list[0].RequestID != d.State.RequestID || list[0].MAC != "28:05:a5:10:00:01" || list[0].IP == "" {
		t.Fatalf("waiting list: %+v", list)
	}
	other, _ := devicesim.New(e.srv.URL, e.keys, "28:05:a5:10:00:02", "zir3m-full")
	otherCode, err := other.Register(ctx)
	e.must(err)

	// The old request of the restarted device is gone.
	_, err = e.core.ClaimCode(ctx, e.maker, oldReq, code)
	e.wantCode(err, "not_found")
	// Another device's valid code does not unlock the picked one.
	_, err = e.core.ClaimCode(ctx, e.maker, d.State.RequestID, otherCode)
	e.wantCode(err, "not_found")
	cl, err := e.core.ClaimCode(ctx, e.maker, d.State.RequestID, strings.ToLower(core.FormatClaim(code)))
	e.must(err)
	if cl.RequestID != d.State.RequestID {
		t.Fatal("claimed another request")
	}

	// Only superadmin makes a developer device.
	_, err = e.core.Approve(ctx, e.maker, core.ApproveInput{RequestID: cl.RequestID, Profile: "zir3m-full",
		Params: core.DefaultParams(core.DefaultModules()), Dev: true})
	e.wantCode(err, "forbidden")
	_, err = e.core.Approve(ctx, e.super, core.ApproveInput{RequestID: cl.RequestID, Profile: "zir3m-full",
		Params: core.DefaultParams(core.DefaultModules()), Dev: true})
	e.must(err)
	st, err := d.PollRegistration(ctx)
	e.must(err)
	if st != "approved" || !d.State.Dev {
		t.Fatalf("dev registration: %s dev=%v", st, d.State.Dev)
	}
	if list, _ := e.core.PendingRegistrations(ctx, e.maker); len(list) != 1 || list[0].MAC != "28:05:a5:10:00:02" {
		t.Fatalf("after approval: %+v", list)
	}

	// Wrong codes still count towards the limit.
	for i := 0; i < 5; i++ {
		e.core.ClaimCode(ctx, e.maker, other.State.RequestID, "AAAA-AAAA")
	}
	_, err = e.core.ClaimCode(ctx, e.maker, other.State.RequestID, otherCode)
	e.wantCode(err, "too_many")
}

func (e *env) registerDev(mac string, dev bool) *devicesim.Device {
	e.t.Helper()
	d, err := devicesim.New(e.srv.URL, e.keys, mac, "zir3m-full")
	e.must(err)
	code, err := d.Register(e.ctx)
	e.must(err)
	cl, err := e.core.ClaimCode(e.ctx, e.super, d.State.RequestID, code)
	e.must(err)
	_, err = e.core.Approve(e.ctx, e.super, core.ApproveInput{RequestID: cl.RequestID, Profile: "zir3m-full",
		Params: core.DefaultParams(core.DefaultModules()), Dev: dev})
	e.must(err)
	_, err = d.PollRegistration(e.ctx)
	e.must(err)
	e.must(d.Auth(e.ctx))
	return d
}

func TestDevBuilds(t *testing.T) {
	e := setup(t)
	ctx := e.ctx
	e.profile()
	dev := e.registerDev("28:05:a5:20:00:01", true)
	user := e.registerDev("28:05:a5:20:00:02", false)

	// Upload checks: dev flag required, superadmin only.
	_, err := e.core.UploadDevApp(ctx, e.super, appdesc.Build("1.0.0", "zir3m-full", 3, 0, make([]byte, 100)), nil)
	e.wantCode(err, "not_dev_build")
	_, err = e.core.UploadDevApp(ctx, e.eng, devImage("0.9.0-dev", 1), nil)
	e.wantCode(err, "forbidden")
	b1, err := e.core.UploadDevApp(ctx, e.super, devImage("main-3f2a1c", 1), nil)
	e.must(err)

	// Only developer devices take dev builds.
	_, err = e.core.AssignDevBuild(ctx, e.super, b1.ID, []string{user.State.Serial}, false)
	e.wantCode(err, "not_dev_device")
	_, err = e.core.AssignDevBuild(ctx, e.eng, b1.ID, []string{dev.State.Serial}, false)
	e.wantCode(err, "forbidden")

	// A stable release exists; the dev device still gets its dev build.
	r100 := e.release("1.0.0", e.uploadApp("1.0.0", 7), "")
	e.must(e.core.Promote(ctx, e.super, r100, false))

	got, err := e.core.AssignDevBuild(ctx, e.super, b1.ID, []string{dev.State.Serial}, false)
	e.must(err)
	if len(got) != 1 || got[0] != dev.State.Serial {
		t.Fatalf("assigned %v", got)
	}
	m, err := dev.CheckUpdate(ctx)
	e.must(err)
	if m == nil || !m.Dev || m.DevBuildID != b1.ID || m.ReleaseID != "" || m.Mode != "button" || m.WWW != nil || dev.State.PollAfter != core.PollDev {
		t.Fatalf("dev offer: %+v poll=%d", m, dev.State.PollAfter)
	}
	if m, _ := user.CheckUpdate(ctx); m == nil || m.Dev || user.State.PollAfter != core.PollRegular {
		t.Fatalf("regular device: %+v poll=%d", m, user.State.PollAfter)
	}
	// The dev image is served only to the device it is assigned to.
	_, err = user.Download(ctx, m.App.URL)
	e.wantCode(err, "not_found")
	enc, err := dev.Download(ctx, m.App.URL)
	e.must(err)
	if err := devicesim.DecryptWith(enc, user.State.OTAKeyPEM); err == nil {
		t.Fatal("dev image decrypted with another device key")
	}
	e.must(dev.Install(ctx, m))
	e.must(dev.Auth(ctx))
	if m, _ := dev.CheckUpdate(ctx); m != nil {
		t.Fatalf("offer after dev install (stable must not replace the dev build): %+v", m)
	}
	dd, _ := e.core.Device(ctx, dev.State.DeviceID)
	if !dd.DevInstalled || dd.CurrentRelease != "" {
		t.Fatalf("device view: %+v", dd)
	}

	// Critical: installed without asking, "all" picks every developer device.
	b2, err := e.core.UploadDevApp(ctx, e.super, devImage("main-4b0c9d", 2), nil)
	e.must(err)
	_, err = e.core.AssignDevBuild(ctx, e.super, b2.ID, []string{"all"}, true)
	e.must(err)
	m, err = dev.CheckUpdate(ctx)
	e.must(err)
	if m == nil || m.Mode != "auto" || !m.Critical || m.DevBuildID != b2.ID {
		t.Fatalf("critical dev offer: %+v", m)
	}
	e.must(dev.Install(ctx, m))
	e.must(dev.Auth(ctx))
	if dev.State.AppVersion != "main-4b0c9d" {
		t.Fatalf("installed %s", dev.State.AppVersion)
	}

	// Without an assignment the dev device follows releases again.
	e.must(e.core.ClearDevBuild(ctx, e.super, dev.State.DeviceID))
	if m, _ := dev.CheckUpdate(ctx); m == nil || m.Dev || m.Version != "1.0.0" {
		t.Fatalf("after clearing: %+v", m)
	}
	// A release assignment replaces a dev assignment and vice versa.
	_, err = e.core.AssignDevBuild(ctx, e.super, b1.ID, []string{dev.State.DeviceID}, false)
	e.must(err)
	e.must(e.core.AssignRelease(ctx, e.eng, dev.State.DeviceID, r100))
	if m, _ := dev.CheckUpdate(ctx); m == nil || m.Dev || m.Mode != "engineer" {
		t.Fatalf("release over dev: %+v", m)
	}

	// Turning the flag off signs a new config; the device drops the dev right.
	_, err = e.core.AssignDevBuild(ctx, e.super, b1.ID, []string{dev.State.DeviceID}, false)
	e.must(err)
	e.wantCode(e.core.SetDevMode(ctx, e.eng, dev.State.DeviceID, false), "forbidden")
	before := dev.State.ConfigVer
	e.must(e.core.SetDevMode(ctx, e.super, dev.State.DeviceID, false))
	m, err = dev.CheckUpdate(ctx)
	e.must(err)
	if dev.State.Dev || dev.State.ConfigVer != before+1 || (m != nil && m.Dev) {
		t.Fatalf("dev off: dev=%v cfg=%d offer=%+v", dev.State.Dev, dev.State.ConfigVer, m)
	}
	_, err = e.core.AssignDevBuild(ctx, e.super, b1.ID, []string{dev.State.DeviceID}, false)
	e.wantCode(err, "not_dev_device")
	e.must(e.core.SetDevMode(ctx, e.super, user.State.DeviceID, true))
	user.CheckUpdate(ctx)
	if !user.State.Dev {
		t.Fatal("dev on not delivered in config")
	}
}

// lcmctl push-dev goes through /api/v1 with an API token.
func TestPushDevAPI(t *testing.T) {
	e := setup(t)
	ctx := e.ctx
	e.profile()
	dev := e.registerDev("28:05:a5:30:00:01", true)

	_, err := e.core.CreateAPIToken(ctx, e.eng, "x")
	e.wantCode(err, "forbidden")
	tok, err := e.core.CreateAPIToken(ctx, e.super, "ноутбук")
	e.must(err)

	push := func(token string, img []byte, devices, critical string) (int, map[string]any) {
		var body bytes.Buffer
		mw := multipart.NewWriter(&body)
		fw, _ := mw.CreateFormFile("app", "firmware.bin")
		fw.Write(img)
		mw.WriteField("devices", devices)
		mw.WriteField("critical", critical)
		mw.Close()
		req, _ := http.NewRequest("POST", e.srv.URL+"/api/v1/dev-builds", &body)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		e.must(err)
		defer resp.Body.Close()
		out := map[string]any{}
		json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	if code, _ := push("zirlcm_bogus", devImage("a", 1), "", ""); code != 401 {
		t.Fatalf("bogus token: %d", code)
	}
	code, out := push(tok, devImage("main-aaaa", 1), dev.State.Serial, "1")
	if code != 200 || out["critical"] != true || len(out["assigned"].([]any)) != 1 {
		t.Fatalf("push: %d %v", code, out)
	}
	if m, _ := dev.CheckUpdate(ctx); m == nil || m.Mode != "auto" || m.Version != "main-aaaa" {
		t.Fatalf("pushed build not offered: %+v", m)
	}

	req, _ := http.NewRequest("GET", e.srv.URL+"/api/v1/dev-devices", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	e.must(err)
	var devs []httpapi.DevDevice
	json.NewDecoder(resp.Body).Decode(&devs)
	resp.Body.Close()
	if len(devs) != 1 || devs[0].Serial != dev.State.Serial || devs[0].DevBuild != "main-aaaa" {
		t.Fatalf("dev-devices: %+v", devs)
	}

	// A token is worth no more than its owner: losing superadmin disables it.
	e.core.Pool.Exec(ctx, `DELETE FROM user_roles WHERE user_id=$1`, e.super.UserID)
	if code, _ := push(tok, devImage("main-bbbb", 2), "", ""); code != 403 {
		t.Fatalf("token of a demoted user: %d", code)
	}
	e.core.Pool.Exec(ctx, `INSERT INTO user_roles VALUES ($1,'superadmin')`, e.super.UserID)
	list, _ := e.core.APITokens(ctx, e.super)
	e.must(e.core.RevokeAPIToken(ctx, e.super, list[0].ID))
	if code, _ := push(tok, devImage("main-cccc", 3), "", ""); code != 401 {
		t.Fatalf("revoked token: %d", code)
	}
}
