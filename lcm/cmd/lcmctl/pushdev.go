package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"zir/lcm/internal/core"
	"zir/lcm/internal/crypto/appdesc"
	"zir/lcm/internal/httpapi"
)

// Remote commands: they talk to a running server over /api/v1 with an API
// token (admin UI → Розробка → Токени API), no database access needed.

func apiEnv() (base, token string, err error) {
	base = strings.TrimRight(os.Getenv("LCM_URL"), "/")
	token = os.Getenv("LCM_TOKEN")
	if base == "" || token == "" {
		return "", "", fmt.Errorf("задайте LCM_URL (адреса сервера) і LCM_TOKEN (адмінка → Розробка → Токени API)")
	}
	return base, token, nil
}

func apiDo(req *http.Request, token string, out any) error {
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := (&http.Client{Timeout: 2 * time.Minute}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		var e struct{ Error, Message string }
		if json.Unmarshal(data, &e) == nil && e.Message != "" {
			return fmt.Errorf("%s (%d %s)", e.Message, resp.StatusCode, e.Error)
		}
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	return json.Unmarshal(data, out)
}

func pushDev(args []string) error {
	fs := flag.NewFlagSet("push-dev", flag.ContinueOnError)
	devices := fs.String("devices", "", "серійні номери через кому, all — усі прилади розробника профілю; порожньо — лише завантажити")
	critical := fs.Bool("critical", false, "критична: прилади ставлять її одразу, без кнопки")
	elf := fs.String("elf", "", "firmware.elf (за замовчуванням — поруч із .bin, якщо є)")
	www := fs.String("www", "", "www.tar веб-інтерфейсу: прилад поставить його разом зі збіркою")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 1 || (fs.NArg() == 0 && *www == "") {
		return fmt.Errorf("usage: push-dev [-devices S1,S2|all] [-critical] [-elf firmware.elf] [-www www.tar] <firmware.bin>\n" +
			"       push-dev [-devices S1,S2|all] [-critical] -www www.tar   (лише інтерфейс, поверх прошивки на приладі)")
	}
	base, token, err := apiEnv()
	if err != nil {
		return err
	}
	// Check locally first: a clear message beats a round trip.
	var wwwTar []byte
	var wm core.WWWManifest
	if *www != "" {
		if wwwTar, err = os.ReadFile(*www); err != nil {
			return err
		}
		if wm, err = core.CheckWWWTar(wwwTar); err != nil {
			return fmt.Errorf("%s: %w", *www, err)
		}
	}
	var img []byte
	if fs.NArg() == 1 {
		if img, err = os.ReadFile(fs.Arg(0)); err != nil {
			return err
		}
		d, err := appdesc.Parse(img)
		if err != nil {
			return err
		}
		if !d.HasZir || !d.DevBuild() {
			return fmt.Errorf("%s — не збірка для розробки (потрібен CONFIG_ZIR_DEV_BUILD=y, env esp32dev)", fs.Arg(0))
		}
		if wwwTar != nil && wm.WwwAPI != int(d.WwwAPI) {
			return fmt.Errorf("www_api інтерфейсу (%d) не збігається з www_api прошивки (%d)", wm.WwwAPI, d.WwwAPI)
		}
	}
	elfPath := *elf
	if elfPath == "" && img != nil {
		cand := strings.TrimSuffix(fs.Arg(0), filepath.Ext(fs.Arg(0))) + ".elf"
		if _, err := os.Stat(cand); err == nil {
			elfPath = cand
		}
	}

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	if img != nil {
		fw, _ := mw.CreateFormFile("app", filepath.Base(fs.Arg(0)))
		fw.Write(img)
	}
	if elfPath != "" {
		e, err := os.ReadFile(elfPath)
		if err != nil {
			return err
		}
		fw, _ := mw.CreateFormFile("elf", filepath.Base(elfPath))
		fw.Write(e)
	}
	if wwwTar != nil {
		fw, _ := mw.CreateFormFile("www", filepath.Base(*www))
		fw.Write(wwwTar)
	}
	mw.WriteField("devices", *devices)
	if *critical {
		mw.WriteField("critical", "1")
	}
	mw.Close()
	req, err := http.NewRequest("POST", base+"/api/v1/dev-builds", &body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	var rep httpapi.DevBuildReply
	if err := apiDo(req, token, &rep); err != nil {
		return err
	}
	if rep.Kind == "dev_www" {
		fmt.Printf("завантажено інтерфейс %s, збірка %s, sha256 %s\n", rep.Version, rep.BuildID, rep.SHA256[:16])
	} else {
		fmt.Printf("завантажено %s (%s), збірка %s, sha256 %s\n", rep.Version, rep.Profile, rep.BuildID, rep.SHA256[:16])
		if rep.WWW != "" {
			fmt.Printf("з інтерфейсом %s\n", rep.WWW)
		}
	}
	switch {
	case len(rep.Assigned) == 0:
		fmt.Println("не призначено жодному приладу (див. -devices)")
	case rep.Critical:
		fmt.Printf("критична, призначено: %s — прилади поставлять її протягом хвилини\n", strings.Join(rep.Assigned, ", "))
	default:
		fmt.Printf("призначено: %s — на приладі з'явиться кнопка «Оновити»\n", strings.Join(rep.Assigned, ", "))
	}
	return nil
}

func devDevices() error {
	base, token, err := apiEnv()
	if err != nil {
		return err
	}
	req, err := http.NewRequest("GET", base+"/api/v1/dev-devices", nil)
	if err != nil {
		return err
	}
	var list []httpapi.DevDevice
	if err := apiDo(req, token, &list); err != nil {
		return err
	}
	if len(list) == 0 {
		fmt.Println("приладів розробника немає")
	}
	for _, d := range list {
		state := "—"
		if d.DevBuild != "" {
			state = d.DevBuild
			if d.DevCritical {
				state += " критична"
			}
			if d.DevInstalled {
				state += ", встановлено"
			} else {
				state += ", очікує"
			}
		}
		seen := "ніколи"
		if d.LastSeen != nil {
			seen = d.LastSeen.Local().Format("02.01 15:04:05")
		}
		fmt.Printf("%-14s %-12s прошивка %-16s збірка розробника: %-28s зв'язок %s\n", d.Serial, d.Profile, d.Version, state, seen)
	}
	return nil
}
