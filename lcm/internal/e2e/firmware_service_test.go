package e2e

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"zir/lcm/internal/core"
)

// The working firmware's LCM service (ZIR_3M components/lcm_service) built for
// the host by test/lcm_host/run.sh: a dev build and a release build.
//
//	ZIR_FW_SERVICE_DEV=... ZIR_FW_SERVICE_RELEASE=... TEST_DATABASE_URL=... go test ./internal/e2e -run FirmwareService

type svcStatus struct {
	Server      int    `json:"server"`
	Reg         int    `json:"reg"` // 0 none, 1 code, 2 registered
	Code        string `json:"code"`
	Serial      string `json:"serial"`
	ConfigValid bool   `json:"config_valid"`
	DevDevice   bool   `json:"dev_device"`
	Update      int    `json:"update"` // 0 unknown, 1 none, 2 available, 3 installing, 4 revoked
	Version     string `json:"version"`
	Mode        string `json:"mode"`
	Locked      bool   `json:"locked"`
	Left        int    `json:"left"`
	Reason      string `json:"reason"`
	Error       string `json:"error"`
	WiFi        bool   `json:"wifi"`
}

type svcProc struct {
	t      *testing.T
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	lines  chan string
	last   svcStatus
	exited chan struct{}
}

type svcRun struct {
	bin, nvs, running, mac, otaOut string
	url                            string // "" = the test server
	onS, boots, battery            int
}

func (e *env) startService(keys string, r svcRun) *svcProc {
	e.t.Helper()
	cmd := exec.Command(r.bin)
	url := r.url
	if url == "" {
		url = e.srv.URL
	}
	cmd.Env = append(os.Environ(), "LCM_URL="+url, "LCM_KEYS="+keys, "LCM_NVS_FILE="+r.nvs,
		"LCM_RUNNING="+r.running, "LCM_MAC="+r.mac, "LCM_OTA_OUT="+r.otaOut,
		fmt.Sprintf("LCM_ON_S=%d", r.onS), fmt.Sprintf("LCM_BOOTS=%d", r.boots), fmt.Sprintf("LCM_BATTERY=%d", r.battery))
	stdin, _ := cmd.StdinPipe()
	out, _ := cmd.StdoutPipe()
	cmd.Stderr = os.Stderr
	e.must(cmd.Start())
	p := &svcProc{t: e.t, cmd: cmd, stdin: stdin, lines: make(chan string, 1000), exited: make(chan struct{})}
	go func() {
		sc := bufio.NewScanner(out)
		for sc.Scan() {
			p.lines <- sc.Text()
		}
		cmd.Wait()
		close(p.exited)
		close(p.lines)
	}()
	e.t.Cleanup(func() { cmd.Process.Kill() })
	return p
}

func (p *svcProc) send(cmd string) { fmt.Fprintln(p.stdin, cmd) }

// until reads output until a STATUS line satisfies ok (or a plain line equals want).
func (p *svcProc) until(what string, timeout time.Duration, ok func(s svcStatus, line string) bool) string {
	p.t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case line, open := <-p.lines:
			if !open {
				p.t.Fatalf("service exited while waiting for %s (last %+v)", what, p.last)
			}
			if rest, found := strings.CutPrefix(line, "STATUS "); found {
				json.Unmarshal([]byte(rest), &p.last)
			}
			if ok(p.last, line) {
				return line
			}
		case <-deadline:
			p.t.Fatalf("timeout waiting for %s (last %+v)", what, p.last)
		}
	}
}

func (p *svcProc) waitExit() {
	p.t.Helper()
	for range p.lines {
	}
	select {
	case <-p.exited:
	case <-time.After(10 * time.Second):
		p.t.Fatal("service did not exit")
	}
}

func (e *env) eventCount(deviceID, status string) int {
	var n int
	e.core.Pool.QueryRow(e.ctx, `SELECT count(*) FROM update_events WHERE device_id::text=$1 AND status=$2`, deviceID, status).Scan(&n)
	return n
}

func (e *env) deviceByMAC(mac string) core.Device {
	e.t.Helper()
	list, err := e.core.Devices(e.ctx, mac)
	e.must(err)
	if len(list) != 1 {
		e.t.Fatalf("device %s: %d found", mac, len(list))
	}
	return list[0]
}

func TestFirmwareService(t *testing.T) {
	devBin, relBin := os.Getenv("ZIR_FW_SERVICE_DEV"), os.Getenv("ZIR_FW_SERVICE_RELEASE")
	if devBin == "" || relBin == "" {
		t.Skip("ZIR_FW_SERVICE_DEV / ZIR_FW_SERVICE_RELEASE not set (ZIR_3M test/lcm_host/run.sh)")
	}
	e := setup(t)
	ctx := e.ctx
	e.profile()
	dir := t.TempDir()
	keys := e.writeFirmwareKeys(dir)
	sec := time.Second

	t.Run("dev", func(t *testing.T) {
		e.t = t
		run := svcRun{bin: devBin, nvs: filepath.Join(dir, "dev.nvs"), running: "ota_0", mac: "28:05:a5:50:00:01",
			otaOut: filepath.Join(dir, "dev.bin"), onS: 100000, boots: 7, battery: 5}
		p := e.startService(keys, run)
		// No identity: the dev build turns Wi-Fi on, has its first hour, registers.
		p.until("registration code", 20*sec, func(s svcStatus, _ string) bool { return s.Reg == 1 && s.Code != "" })
		if !p.last.WiFi || p.last.Locked || p.last.Left < 3500 {
			t.Fatalf("first start of a dev build: %+v", p.last)
		}
		pend, err := e.core.PendingRegistrations(ctx, e.super)
		e.must(err)
		if len(pend) != 1 || pend[0].MAC != run.mac {
			t.Fatalf("waiting list: %+v", pend)
		}
		cl, err := e.core.ClaimCode(ctx, e.super, pend[0].RequestID, p.last.Code)
		e.must(err)
		devID, err := e.core.Approve(ctx, e.super, core.ApproveInput{RequestID: cl.RequestID, Profile: "zir3m-full",
			Params: core.DefaultParams(core.DefaultModules()), Dev: true})
		e.must(err)
		p.until("registered developer device", 20*sec, func(s svcStatus, _ string) bool { return s.Reg == 2 && s.DevDevice && s.Server == 2 })

		// A critical dev build: installed at once, battery 5 % does not matter.
		devImg := devImage("main-svc1", 6)
		b, err := e.core.UploadDevApp(ctx, e.super, devImg, nil, nil)
		e.must(err)
		_, err = e.core.AssignDevBuild(ctx, e.super, b.ID, []string{devID}, true)
		e.must(err)
		p.send("check")
		p.until("boot into ota_1", 30*sec, func(_ svcStatus, line string) bool { return line == "BOOT ota_1" })
		p.waitExit()
		if img, _ := os.ReadFile(run.otaOut); string(img) != string(devImg) {
			t.Fatal("installed dev image differs")
		}

		// "Reboot" into the new image: it reports installed.
		run.running, run.boots = "ota_1", 8
		p = e.startService(keys, run)
		p.until("synced after reboot", 20*sec, func(s svcStatus, _ string) bool { return s.Server == 2 && s.Update == 1 })
		if e.eventCount(devID, "installed") != 1 {
			t.Fatal("installed not reported")
		}
		if d := e.deviceByMAC(run.mac); !d.DevInstalled {
			t.Fatalf("server does not see the dev build installed: %+v", d)
		}
		if p.last.Left < 3500 || p.last.Locked {
			t.Fatalf("after sync: %+v", p.last)
		}

		// An hour of operation without a sync: detection stops; a sync lifts it.
		p.send(fmt.Sprintf("ons %d", 100000+3700))
		p.until("locked by time", 10*sec, func(s svcStatus, _ string) bool { return s.Locked && strings.Contains(s.Reason, "1 год") })
		p.send("check")
		p.until("unlocked by a sync", 20*sec, func(s svcStatus, _ string) bool { return !s.Locked && s.Left > 3500 })

		// The server takes the dev flag away: locked at once.
		e.must(e.core.SetDevMode(ctx, e.super, devID, false))
		p.send("check")
		p.until("locked: not a developer device", 20*sec, func(s svcStatus, _ string) bool { return s.Locked && !s.DevDevice })
		e.must(e.core.SetDevMode(ctx, e.super, devID, true))
		p.send("check")
		p.until("unlocked: developer device again", 20*sec, func(s svcStatus, _ string) bool { return !s.Locked && s.DevDevice })

		// Revoked: locked, no more updates.
		e.must(e.core.SetRevoked(ctx, e.super, devID, true, "тест"))
		p.send("check")
		p.until("locked: revoked", 20*sec, func(s svcStatus, _ string) bool { return s.Locked && s.Update == 4 })
		p.cmd.Process.Kill()
		p.waitExit()

		// Reboot with no server: locked from the first status, not after a sync.
		firstStatus := func(p *svcProc) svcStatus {
			p.until("first status", 10*sec, func(_ svcStatus, line string) bool { return strings.HasPrefix(line, "STATUS ") })
			return p.last
		}
		run.boots++
		run.url = "http://127.0.0.1:1"
		p = e.startService(keys, run)
		if s := firstStatus(p); !s.Locked || s.Update != 4 || !strings.Contains(s.Reason, "відкликано") {
			t.Fatalf("revoked device after reboot, offline: %+v", s)
		}
		p.cmd.Process.Kill()
		p.waitExit()

		// Restored on the server: the one check after boot lifts the lock.
		e.must(e.core.SetRevoked(ctx, e.super, devID, false, "тест"))
		run.boots++
		run.url = ""
		p = e.startService(keys, run)
		if s := firstStatus(p); !s.Locked {
			t.Fatalf("still revoked as far as the device knows: %+v", s)
		}
		p.until("unlocked: restored", 20*sec, func(s svcStatus, _ string) bool { return !s.Locked && s.Update == 1 })
		p.cmd.Process.Kill()
		p.waitExit()

		// And the next reboot starts unlocked.
		run.boots++
		run.url = "http://127.0.0.1:1"
		p = e.startService(keys, run)
		if s := firstStatus(p); s.Locked || s.Update == 4 {
			t.Fatalf("restored device after reboot: %+v", s)
		}
		p.cmd.Process.Kill()
	})

	t.Run("release", func(t *testing.T) {
		e.t = t
		run := svcRun{bin: relBin, nvs: filepath.Join(dir, "rel.nvs"), running: "ota_0", mac: "28:05:a5:50:00:02",
			otaOut: filepath.Join(dir, "rel.bin"), onS: 5000, boots: 3, battery: 25}
		p := e.startService(keys, run)
		p.until("registration code", 20*sec, func(s svcStatus, _ string) bool { return s.Reg == 1 && s.Code != "" })
		if p.last.Locked {
			t.Fatal("a release build is never locked")
		}
		cl, err := e.core.ClaimCode(ctx, e.maker, "", p.last.Code)
		e.must(err)
		devID, err := e.core.Approve(ctx, e.maker, core.ApproveInput{RequestID: cl.RequestID, Profile: "zir3m-full",
			Params: core.DefaultParams(core.DefaultModules())})
		e.must(err)
		p.until("registered", 20*sec, func(s svcStatus, _ string) bool { return s.Reg == 2 && s.Server == 2 })
		// The AP password the device made for itself reached the server.
		pw, err := e.core.WebPassword(ctx, e.eng, devID)
		e.must(err)
		if !strings.HasPrefix(pw, "zir-") || len(pw) != 9 {
			t.Fatalf("AP password on the server: %q", pw)
		}

		app := e.uploadApp("1.0.0", 11)
		www, err := e.core.UploadWWW(ctx, e.super, wwwTar(t, "1.0.0", 3))
		e.must(err)
		rel := e.release("1.0.0", app, www)
		e.must(e.core.Promote(ctx, e.super, rel, false))
		p.send("check")
		p.until("update offered", 20*sec, func(s svcStatus, _ string) bool { return s.Update == 2 && s.Mode == "button" && s.Version == "1.0.0" })
		// The button needs 30 %.
		p.send("install")
		p.until("battery refused", 5*sec, func(_ svcStatus, line string) bool { return line == "INSTALL 260" }) // ESP_ERR_INVALID_SIZE
		p.cmd.Process.Kill()
		p.waitExit()

		run.battery = 80
		p = e.startService(keys, run)
		p.until("update offered", 20*sec, func(s svcStatus, _ string) bool { return s.Update == 2 })
		p.send("install")
		p.until("boot into ota_1", 30*sec, func(_ svcStatus, line string) bool { return line == "BOOT ota_1" })
		p.waitExit()
		signedPath, _ := e.core.BuildFile(ctx, e.eng, app, "app.bin")
		signed, _ := os.ReadFile(signedPath)
		if img, _ := os.ReadFile(run.otaOut); string(img) != string(signed) {
			t.Fatal("installed image differs from the signed build")
		}

		run.running = "ota_1"
		p = e.startService(keys, run)
		p.until("synced, nothing to offer", 20*sec, func(s svcStatus, _ string) bool { return s.Server == 2 && s.Update == 1 })
		if e.eventCount(devID, "installed") != 1 {
			t.Fatal("installed not reported")
		}
		if d := e.deviceByMAC(run.mac); d.CurrentRelease != "1.0.0" {
			t.Fatalf("current release on the server: %q", d.CurrentRelease)
		}

		// A critical release whose image fails the self-check: the bootloader
		// rolls back, the old image runs and reports rolled_back.
		app2 := e.uploadApp("1.1.0", 12)
		rel2 := e.release("1.1.0", app2, www)
		e.must(e.core.Promote(ctx, e.super, rel2, true))
		p.send("check")
		p.until("critical installed", 30*sec, func(_ svcStatus, line string) bool { return line == "BOOT ota_0" })
		p.waitExit()
		// Otherwise the same critical release would be installed again at once.
		e.must(e.core.SetCritical(ctx, e.super, rel2, false))
		p = e.startService(keys, run) // still ota_1: rolled back
		p.until("synced after rollback", 20*sec, func(s svcStatus, _ string) bool { return s.Server == 2 })
		time.Sleep(500 * time.Millisecond)
		if e.eventCount(devID, "rolled_back") != 1 {
			t.Fatal("rolled_back not reported")
		}

		// A dev build cannot reach a release firmware over the air.
		e.must(e.core.SetDevMode(ctx, e.super, devID, true))
		b, err := e.core.UploadDevApp(ctx, e.super, devImage("main-svc2", 7), nil, nil)
		e.must(err)
		_, err = e.core.AssignDevBuild(ctx, e.super, b.ID, []string{devID}, true)
		e.must(err)
		p.send("check")
		p.until("dev build refused", 20*sec, func(s svcStatus, _ string) bool { return strings.Contains(s.Error, "USB") })
		if p.last.Locked {
			t.Fatal("release build locked")
		}
		p.cmd.Process.Kill()
	})
}
