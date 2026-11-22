// devicesim plays a ZIR device against a running server.
//
//	devicesim -keys .dev/pubkeys -state dev1.json register   # prints the claim code, waits for approval
//	devicesim -state dev1.json update                         # auth, check, install if offered
//	devicesim -state dev1.json password <new>                 # report a changed AP password
//	devicesim -state dev1.json watch                          # a running device: checks every poll_after s, installs auto offers
//	devicesim -state dev1.json show
//	devicesim -dev fake-app <version> <out.bin>               # fake image; -dev marks it CONFIG_ZIR_DEV_BUILD
package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"zir/lcm/internal/core"
	"zir/lcm/internal/crypto/appdesc"
	"zir/lcm/internal/devicesim"
)

func main() {
	server := flag.String("server", "http://localhost:8090", "server URL")
	keysDir := flag.String("keys", ".dev/pubkeys", "directory from `lcmctl export-pubkeys`")
	statePath := flag.String("state", "device.json", "device state file")
	mac := flag.String("mac", "", "MAC for a new device (random if empty)")
	profile := flag.String("profile", "zir3m-full", "profile compiled into the simulated firmware")
	devBuild := flag.Bool("dev", false, "fake-app: make a dev build (CONFIG_ZIR_DEV_BUILD)")
	flag.Parse()
	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(context.Background(), *server, *keysDir, *statePath, *mac, *profile, *devBuild, flag.Args()); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, server, keysDir, statePath, mac, profile string, devBuild bool, args []string) error {
	if args[0] == "fake-app" {
		// A fake unsigned app image with a zir_custom_desc_t, to try the
		// server's upload, signing and OTA without a firmware build.
		if len(args) != 3 {
			return fmt.Errorf("usage: fake-app <version> <out.bin>")
		}
		body := make([]byte, 200*1024)
		rand.Read(body)
		var flags uint32
		if devBuild {
			flags = appdesc.FlagDevBuild
		}
		return os.WriteFile(args[2], appdesc.Build(args[1], profile, 3, flags, body), 0o644)
	}
	keys, err := devicesim.LoadKeys(keysDir)
	if err != nil {
		return err
	}
	var d *devicesim.Device
	if data, err := os.ReadFile(statePath); err == nil {
		var st devicesim.State
		if err := json.Unmarshal(data, &st); err != nil {
			return err
		}
		if d, err = devicesim.Restore(server, keys, st); err != nil {
			return err
		}
	} else {
		if mac == "" {
			b := make([]byte, 3)
			rand.Read(b)
			mac = fmt.Sprintf("28:05:a5:%02x:%02x:%02x", b[0], b[1], b[2])
		}
		if d, err = devicesim.New(server, keys, mac, profile); err != nil {
			return err
		}
	}
	save := func() error {
		data, _ := json.MarshalIndent(d.State, "", "  ")
		return os.WriteFile(statePath, data, 0o600)
	}
	defer save()

	switch args[0] {
	case "register":
		code, err := d.Register(ctx)
		if err != nil {
			return err
		}
		save()
		fmt.Printf("MAC %s, пароль %s\nКод реєстрації: %s — введіть його в адмінці (Реєстрація)\n", d.State.MAC, d.State.WebPassword, core.FormatClaim(code))
		for {
			st, err := d.PollRegistration(ctx)
			if err != nil {
				return err
			}
			if st == "approved" {
				fmt.Printf("зареєстровано: %s (%s), конфігурація v%d\n", d.State.Serial, d.State.DeviceID, d.State.ConfigVer)
				return nil
			}
			if st != "pending" {
				return fmt.Errorf("реєстрація: %s", st)
			}
			time.Sleep(5 * time.Second)
		}
	case "update":
		if err := d.Auth(ctx); err != nil {
			return err
		}
		m, err := d.CheckUpdate(ctx)
		if err != nil {
			return err
		}
		if m == nil {
			fmt.Printf("оновлень немає (реліз %s, прошивка %s, конфігурація v%d)\n", d.State.ReleaseID, d.State.AppVersion, d.State.ConfigVer)
			return nil
		}
		fmt.Printf("пропозиція: %s, режим %s, app needed=%v, www needed=%v\n", m.Version, m.Mode, m.App.Needed, m.WWW != nil && m.WWW.Needed)
		if err := d.Install(ctx, m); err != nil {
			return err
		}
		fmt.Printf("встановлено %s (прошивка %s)\n", m.Version, d.State.AppVersion)
	case "watch":
		// Like the firmware: auth, check, install "auto" offers at once, show
		// "button" offers, sleep poll_after. Ctrl+C to stop.
		for {
			if err := d.Auth(ctx); err != nil {
				return err
			}
			m, err := d.CheckUpdate(ctx)
			if err != nil {
				return err
			}
			save()
			now := time.Now().Format("15:04:05")
			switch {
			case m == nil:
				fmt.Printf("%s оновлень немає (прошивка %s, dev=%v)\n", now, d.State.AppVersion, d.State.Dev)
			case m.Mode == "auto" || m.Mode == "engineer":
				fmt.Printf("%s %s %s, ставлю (dev=%v)\n", now, m.Mode, m.Version, m.Dev)
				if err := d.Install(ctx, m); err != nil {
					return err
				}
				fmt.Printf("%s встановлено %s\n", now, d.State.AppVersion)
				save()
				continue
			default:
				fmt.Printf("%s доступне оновлення %s — кнопка «Оновити» (devicesim update)\n", now, m.Version)
			}
			wait := d.State.PollAfter
			if wait <= 0 {
				wait = core.PollRegular
			}
			time.Sleep(time.Duration(wait) * time.Second)
		}
	case "password":
		if len(args) != 2 {
			return fmt.Errorf("usage: password <new>")
		}
		if err := d.Auth(ctx); err != nil {
			return err
		}
		return d.ChangeWebPassword(ctx, args[1])
	case "show":
		data, _ := json.MarshalIndent(map[string]any{"device_id": d.State.DeviceID, "serial": d.State.Serial, "mac": d.State.MAC,
			"profile": d.State.Profile, "app_version": d.State.AppVersion, "release_id": d.State.ReleaseID, "config_version": d.State.ConfigVer,
			"dev": d.State.Dev, "dev_build_id": d.State.DevBuildID}, "", "  ")
		fmt.Println(string(data))
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
	return nil
}
