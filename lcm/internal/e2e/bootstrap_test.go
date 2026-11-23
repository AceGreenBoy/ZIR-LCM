package e2e

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"os"
	"testing"

	"zir/lcm/internal/core"
	"zir/lcm/internal/flashimg"
	"zir/lcm/internal/httpapi"
	"zir/lcm/internal/signer"
)

// bootstrapImage embeds the server's config key like zir_server_keys.h does.
func (e *env) bootstrapImage(version string) []byte {
	var pemData []byte
	for _, k := range e.core.Signer.PublicKeys() {
		if k.Purpose == signer.Config {
			pemData, _ = signer.PublicPEM(k.Key)
		}
	}
	return flashimg.Build(core.BootstrapProject, version, pemData)
}

// Bootstrap uploads: checks, roles, the token API and the flash record.
func TestBootstrapBuilds(t *testing.T) {
	e := setup(t)
	ctx := e.ctx

	_, err := e.core.UploadBootstrap(ctx, e.eng, e.bootstrapImage("0.1.0"))
	e.wantCode(err, "forbidden")
	_, err = e.core.UploadBootstrap(ctx, e.super, flashimg.Build(core.BootstrapProject, "0.1.0", []byte("other server")))
	e.wantCode(err, "foreign_server")
	_, err = e.core.UploadBootstrap(ctx, e.super, flashimg.Build("ZIR_3M", "0.1.0", nil))
	e.wantCode(err, "not_bootstrap")
	_, err = e.core.UploadBootstrap(ctx, e.super, flashimg.Build(core.BootstrapProject, "v1", nil))
	e.wantCode(err, "bad_version")
	_, err = e.core.UploadBootstrap(ctx, e.super, e.bootstrapImage("0.1.0")[0x10000:])
	e.wantCode(err, "bad_image")

	b, err := e.core.UploadBootstrap(ctx, e.super, e.bootstrapImage("0.1.0"))
	e.must(err)
	if b.Version != "0.1.0" {
		t.Fatalf("%+v", b)
	}
	_, err = e.core.UploadBootstrap(ctx, e.super, e.bootstrapImage("0.1.0"))
	e.wantCode(err, "duplicate")

	// The manufacturer downloads it (USB flashing page); an admin without
	// production roles does not.
	if _, err := e.core.BuildFile(ctx, e.maker, b.ID, "bootstrap.bin"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.core.BuildFile(ctx, e.maker, b.ID, "app.bin"); err == nil {
		t.Fatal("manufacturer got app.bin")
	}
	_, err = e.core.BuildFile(ctx, e.viewer, b.ID, "bootstrap.bin")
	e.wantCode(err, "forbidden")

	e.must(e.core.BootstrapFlashed(ctx, e.maker, b.ID, "24:0A:C4:12:34:56", "ESP32-D0WD-V3 (revision v3.1)", false))
	e.wantCode(e.core.BootstrapFlashed(ctx, e.maker, b.ID, "nonsense", "", false), "bad_mac")
	var mac string
	e.must(e.core.Pool.QueryRow(ctx, `SELECT details->>'mac' FROM audit_log WHERE action='bootstrap.flash'`).Scan(&mac))
	if mac != "24:0a:c4:12:34:56" {
		t.Fatalf("audit mac %q", mac)
	}

	// lcmctl push-bootstrap
	tok, err := e.core.CreateAPIToken(ctx, e.super, "ci")
	e.must(err)
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, _ := mw.CreateFormFile("image", "zir3m-bootstrap-0.2.0.bin")
	fw.Write(e.bootstrapImage("0.2.0"))
	mw.Close()
	req, _ := http.NewRequest("POST", e.srv.URL+"/api/v1/bootstrap-builds", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	e.must(err)
	var rep httpapi.BootstrapBuild
	json.NewDecoder(resp.Body).Decode(&rep)
	resp.Body.Close()
	if resp.StatusCode != 200 || rep.Version != "0.2.0" {
		t.Fatalf("push-bootstrap: %d %+v", resp.StatusCode, rep)
	}
	req, _ = http.NewRequest("GET", e.srv.URL+"/api/v1/bootstrap-builds", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err = http.DefaultClient.Do(req)
	e.must(err)
	var list []httpapi.BootstrapBuild
	json.NewDecoder(resp.Body).Decode(&list)
	resp.Body.Close()
	if len(list) != 2 || list[0].Version != "0.2.0" {
		t.Fatalf("bootstrap-builds: %+v", list)
	}
}

// ZIR_BOOTSTRAP_BIN: a real build is accepted only if made for this server,
// so here it must be refused as foreign (the test server has fresh keys).
func TestRealBootstrapForeign(t *testing.T) {
	p := os.Getenv("ZIR_BOOTSTRAP_BIN")
	if p == "" {
		t.Skip("ZIR_BOOTSTRAP_BIN not set")
	}
	e := setup(t)
	img, err := os.ReadFile(p)
	e.must(err)
	_, err = e.core.UploadBootstrap(e.ctx, e.super, img)
	e.wantCode(err, "foreign_server")
}
