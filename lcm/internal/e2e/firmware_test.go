package e2e

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"zir/lcm/internal/core"
	"zir/lcm/internal/signer"
)

// TestFirmwareClient runs the firmware's own LCM client (ZIR_3M
// components/lcm_client, built for the host by test/lcm_host/run.sh) against
// this server: registration by code, a release with web UI for a regular
// device, an unsigned dev build for a developer device.
//
//	ZIR_FW_CLIENT=<lcm_host_client> ZIR_FW_WWW=<its www dir> TEST_DATABASE_URL=... go test ./internal/e2e -run Firmware
func TestFirmwareClient(t *testing.T) {
	bin, wwwDir := os.Getenv("ZIR_FW_CLIENT"), os.Getenv("ZIR_FW_WWW")
	if bin == "" || wwwDir == "" {
		t.Skip("ZIR_FW_CLIENT / ZIR_FW_WWW not set (ZIR_3M test/lcm_host/run.sh)")
	}
	e := setup(t)
	ctx := e.ctx
	e.profile()

	dir := t.TempDir()
	keysPath := e.writeFirmwareKeys(dir)

	// run starts the client, approves it as the given user and waits for DONE.
	run := func(mac string, dev bool, afterApprove func(deviceID string)) (string, string) {
		otaOut := filepath.Join(dir, strings.ReplaceAll(mac, ":", "")+".bin")
		cmd := exec.Command(bin, e.srv.URL, keysPath)
		cmd.Env = append(os.Environ(), "LCM_MAC="+mac, "LCM_OTA_OUT="+otaOut)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, _ := cmd.StdoutPipe()
		e.must(cmd.Start())
		sc := bufio.NewScanner(out)
		var done string
		for sc.Scan() {
			f := strings.Fields(sc.Text())
			switch {
			case len(f) == 3 && f[0] == "CODE":
				// The engineer picks the device from the waiting list and types the code.
				list, err := e.core.PendingRegistrations(ctx, e.maker)
				e.must(err)
				found := false
				for _, p := range list {
					found = found || (p.RequestID == f[2] && p.MAC == mac)
				}
				if !found {
					t.Fatalf("device %s not in the waiting list", mac)
				}
				actor := e.maker
				if dev {
					actor = e.super
				}
				cl, err := e.core.ClaimCode(ctx, actor, f[2], core.FormatClaim(f[1]))
				e.must(err)
				id, err := e.core.Approve(ctx, actor, core.ApproveInput{RequestID: cl.RequestID, Profile: "zir3m-full",
					Params: core.DefaultParams(core.DefaultModules()), Dev: dev})
				e.must(err)
				if afterApprove != nil {
					afterApprove(id)
				}
			case len(f) > 0 && f[0] == "DONE":
				done = sc.Text()
			case len(f) > 0 && f[0] == "FAIL":
				t.Errorf("client: %s", sc.Text())
			}
		}
		if err := cmd.Wait(); err != nil {
			t.Fatalf("client %s: %v\n%s", mac, err, stderr.String())
		}
		img, _ := os.ReadFile(otaOut)
		return done, string(img)
	}

	// Developer device first, while there is no release: it waits for an
	// offer, gets the dev build assigned after the approval, unsigned.
	devImg := devImage("main-host1", 5)
	devBuild, err := e.core.UploadDevApp(ctx, e.super, devImg, nil)
	e.must(err)
	done, img := run("28:05:a5:40:00:02", true, func(id string) {
		time.Sleep(300 * time.Millisecond) // the client is already asking /update
		_, err := e.core.AssignDevBuild(ctx, e.super, devBuild.ID, []string{id}, true)
		e.must(err)
	})
	if !strings.Contains(done, "DONE main-host1 dev=1 www=0") || !strings.Contains(done, "poll=30") {
		t.Fatalf("developer device: %q", done)
	}
	if img != string(devImg) {
		t.Fatal("installed dev image differs from the uploaded build")
	}

	// A stable release with web UI.
	app := e.uploadApp("1.0.0", 9)
	www, err := e.core.UploadWWW(ctx, e.super, wwwTar(t, "1.0.0", 3))
	e.must(err)
	rel := e.release("1.0.0", app, www)
	e.must(e.core.Promote(ctx, e.super, rel, false))

	// Regular device: the stable release, app and web UI.
	done, img = run("28:05:a5:40:00:01", false, nil)
	if !strings.Contains(done, "DONE 1.0.0 dev=0 www=1") || !strings.Contains(done, "poll=21600") {
		t.Fatalf("regular device: %q", done)
	}
	signedPath, err := e.core.BuildFile(ctx, e.eng, app, "app.bin")
	e.must(err)
	signed, _ := os.ReadFile(signedPath)
	if img != string(signed) {
		t.Fatalf("installed image differs from the signed build (%d vs %d bytes)", len(img), len(signed))
	}
	for _, f := range []string{"manifest.json", "index.html.gz", "assets/app.js.gz", ".valid"} {
		if _, err := os.Stat(filepath.Join(wwwDir, f)); err != nil {
			t.Fatalf("www: %v", err)
		}
	}
	var events int
	e.core.Pool.QueryRow(ctx, `SELECT count(*) FROM update_events WHERE status='downloading'`).Scan(&events)
	if events != 2 {
		t.Fatalf("downloading reports: %d", events)
	}

}

// writeFirmwareKeys writes the server public keys as keys.json for the host
// builds of the firmware client (what zir_server_keys.h holds on a device).
func (e *env) writeFirmwareKeys(dir string) string {
	keys := map[string]any{}
	add := func(name string, k signer.PublicKey) {
		pemData, _ := signer.PublicPEM(k.Key)
		list, _ := keys[name].([]map[string]string)
		keys[name] = append(list, map[string]string{"kid": k.Kid, "pem": string(pemData)})
	}
	for _, k := range e.core.Signer.PublicKeys() {
		switch k.Purpose {
		case signer.Config:
			add("config", k)
		case signer.Manifest:
			add("manifest", k)
		case signer.FwSign:
			add("fwsign", k)
		case signer.Telemetry:
			pemData, _ := signer.PublicPEM(k.Key)
			keys["telemetry"] = string(pemData)
		}
	}
	keysPath := filepath.Join(dir, "keys.json")
	data, _ := json.Marshal(keys)
	e.must(os.WriteFile(keysPath, data, 0o644))
	return keysPath
}
