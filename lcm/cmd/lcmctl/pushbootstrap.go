package main

import (
	"bytes"
	"flag"
	"fmt"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"

	"zir/lcm/internal/core"
	"zir/lcm/internal/httpapi"
)

// push-bootstrap uploads the merged bootstrap image (zir3m-bootstrap-<v>.bin)
// over /api/v1; the admin UI flashes it by USB (Прошивка USB).
func pushBootstrap(args []string) error {
	fs := flag.NewFlagSet("push-bootstrap", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: push-bootstrap <zir3m-bootstrap-X.bin>")
	}
	img, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	// Local check first; the server also checks that the image embeds its keys.
	in, err := core.CheckBootstrap(img, nil)
	if err != nil {
		if e, ok := core.AsError(err); ok {
			return fmt.Errorf("%s: %s", fs.Arg(0), e.Msg)
		}
		return err
	}
	base, token, err := apiEnv()
	if err != nil {
		return err
	}
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, _ := mw.CreateFormFile("image", filepath.Base(fs.Arg(0)))
	fw.Write(img)
	mw.Close()
	req, err := http.NewRequest("POST", base+"/api/v1/bootstrap-builds", &body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	var rep httpapi.BootstrapBuild
	if err := apiDo(req, token, &rep); err != nil {
		return err
	}
	fmt.Printf("завантажено bootstrap %s (%s %s, %d КБ), збірка %s, sha256 %s\n", rep.Version, in.FlashSize, in.FlashMode,
		rep.Size/1024, rep.BuildID, rep.SHA256[:16])
	if rep.Replaced {
		fmt.Println("замінено образ цієї версії, що вже був на сервері")
	}
	fmt.Println("тепер саме його пише публічна сторінка /bootstrap (і адмінка → «Прошивка USB»)")
	return nil
}

func bootstrapBuilds() error {
	base, token, err := apiEnv()
	if err != nil {
		return err
	}
	req, err := http.NewRequest("GET", base+"/api/v1/bootstrap-builds", nil)
	if err != nil {
		return err
	}
	var list []httpapi.BootstrapBuild
	if err := apiDo(req, token, &list); err != nil {
		return err
	}
	if len(list) == 0 {
		fmt.Println("збірок bootstrap немає")
	}
	for _, b := range list {
		fmt.Printf("%-12s %s  %6d КБ  sha256 %s  %s\n", b.Version, b.CreatedAt.Local().Format("02.01.2006 15:04"), b.Size/1024, b.SHA256[:16], b.CreatedBy)
	}
	return nil
}
