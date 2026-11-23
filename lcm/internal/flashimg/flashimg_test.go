package flashimg

import (
	"os"
	"testing"
)

func TestBuildParse(t *testing.T) {
	in, err := Parse(Build("zir_bootstrap", "0.1.0", []byte("key")))
	if err != nil {
		t.Fatal(err)
	}
	if in.Desc.Project != "zir_bootstrap" || in.Desc.Version != "0.1.0" || in.App.Label != "ota_0" || in.FlashSize != "4MB" {
		t.Fatalf("%+v", in)
	}
	app := Build("x", "1", nil)[0x10000:]
	if _, err := Parse(app); err == nil {
		t.Fatal("bare app accepted")
	}
}

// ZIR_BOOTSTRAP_BIN=.../zir3m-bootstrap-0.1.0.bin checks a real build.
func TestRealImage(t *testing.T) {
	p := os.Getenv("ZIR_BOOTSTRAP_BIN")
	if p == "" {
		t.Skip("ZIR_BOOTSTRAP_BIN not set")
	}
	img, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	in, err := Parse(img)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%s %s, %s %s, app in %s at 0x%x", in.Desc.Project, in.Desc.Version, in.FlashSize, in.FlashMode, in.App.Label, in.App.Offset)
}
