// fwvectors makes test vectors for the firmware's LCM client (ZIR_3M
// test/lcm_host) with the server's own crypto packages, and checks what the
// firmware code produced. Nothing here touches the database.
//
//	fwvectors gen <dir>     vectors.json and encrypted images
//	fwvectors check <dir>   verify results.json written by the C test
package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"zir/lcm/internal/core"
	"zir/lcm/internal/crypto/appdesc"
	"zir/lcm/internal/crypto/ecies"
	"zir/lcm/internal/crypto/encimg"
	"zir/lcm/internal/crypto/espsig"
	"zir/lcm/internal/crypto/jws"
)

type key struct {
	Kid string `json:"kid"`
	PEM string `json:"pem"`
}

type image struct {
	Name    string `json:"name"`
	File    string `json:"file"`
	ImgSize int    `json:"img_size"`
	SHA256  string `json:"sha256"`
	Profile string `json:"profile"`
	Dev     bool   `json:"dev"`
	Expect  string `json:"expect"` // ok | sig | format
}

type vectors struct {
	Config        []key     `json:"config"`
	Manifest      []key     `json:"manifest"`
	FwSign        []key     `json:"fwsign"`
	JWSConfig     string    `json:"jws_config"`
	JWSBadSig     string    `json:"jws_bad_sig"`
	JWSManifest   string    `json:"jws_manifest"`
	DevKexPriv    string    `json:"dev_kex_priv"`
	Box           ecies.Box `json:"box"`
	BoxPlain      string    `json:"box_plain"`
	BoxAAD        string    `json:"box_aad"`
	TelemetryPub  string    `json:"telemetry_pub"`
	TelemetryPriv string    `json:"telemetry_priv"` // test only: check uses it
	OTAKeyPEM     string    `json:"ota_key_pem"`
	Images        []image   `json:"images"`
}

type results struct {
	SignPub    string    `json:"sign_pub"` // hex 65
	SigMsg     string    `json:"sig_msg"`
	Sig        string    `json:"sig"` // b64url r||s
	ReqMethod  string    `json:"req_method"`
	ReqURI     string    `json:"req_uri"`
	ReqBody    string    `json:"req_body"`
	ReqSig     string    `json:"req_sig"`
	Box        ecies.Box `json:"box"`
	BoxPlain   string    `json:"box_plain"`
	BoxAAD     string    `json:"box_aad"`
	Generated  string    `json:"generated_pub"`  // hex 65 from lcm_p256_generate
	GenPriv    string    `json:"generated_priv"` // hex 32, must match the pub
	ImagesPass int       `json:"images_pass"`
}

func pubPEM(k any) string {
	der, _ := x509.MarshalPKIXPublicKey(k)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: fwvectors gen|check <dir>")
		os.Exit(2)
	}
	dir := os.Args[2]
	switch os.Args[1] {
	case "gen":
		must(gen(dir))
	case "check":
		must(check(dir))
	default:
		fmt.Fprintln(os.Stderr, "usage: fwvectors gen|check <dir>")
		os.Exit(2)
	}
}

func gen(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	cfgKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	manKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	fwKey, _ := rsa.GenerateKey(rand.Reader, 3072)
	otherFw, _ := rsa.GenerateKey(rand.Reader, 3072)
	otaKey, _ := rsa.GenerateKey(rand.Reader, 3072)
	otherOta, _ := rsa.GenerateKey(rand.Reader, 3072)
	kex, _ := ecdh.P256().GenerateKey(rand.Reader)
	tlm, _ := ecdh.P256().GenerateKey(rand.Reader)

	v := vectors{
		Config:   []key{{"config-test1", pubPEM(&cfgKey.PublicKey)}},
		Manifest: []key{{"manifest-test1", pubPEM(&manKey.PublicKey)}},
		FwSign:   []key{{"fw-other", pubPEM(&otherFw.PublicKey)}, {"fw-test1", pubPEM(&fwKey.PublicKey)}},
	}
	payload := core.ConfigPayload{Typ: "zir-config/1", DeviceID: "11111111-2222-3333-4444-555555555555",
		MAC: "28:05:a5:2c:ca:30", Profile: "zir3m-full", Version: 3, IAT: 1762600000, Dev: true,
		Modules: map[string]bool{"rx5808": true}, Ranges: map[string]core.Range{"rx5808": {Min: 4900, Max: 6184}}}
	var err error
	if v.JWSConfig, err = jws.Sign(cfgKey, "config-test1", "zir-config/1", payload); err != nil {
		return err
	}
	parts := strings.Split(v.JWSConfig, ".")
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	sig[10] ^= 1
	v.JWSBadSig = parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(sig)
	if v.JWSManifest, err = jws.Sign(manKey, "manifest-test1", "zir-manifest/1", map[string]any{"typ": "zir-manifest/1"}); err != nil {
		return err
	}

	v.DevKexPriv = hex.EncodeToString(kex.Bytes())
	v.BoxPlain = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(otaKey)}))
	v.BoxAAD = payload.DeviceID
	if v.Box, err = ecies.Seal(kex.PublicKey(), ecies.InfoOTAKey, []byte(v.BoxPlain), []byte(v.BoxAAD)); err != nil {
		return err
	}
	v.OTAKeyPEM = v.BoxPlain
	v.TelemetryPub = hex.EncodeToString(tlm.PublicKey().Bytes())
	v.TelemetryPriv = hex.EncodeToString(tlm.Bytes())

	body := make([]byte, 60000)
	rand.Read(body)
	release := appdesc.Build("1.0.0", "zir3m-full", 3, 0, body)
	signed, err := espsig.Sign(release, fwKey)
	if err != nil {
		return err
	}
	signedOther, _ := espsig.Sign(release, otherFw)
	devImg := appdesc.Build("main-abc", "zir3m-full", 3, appdesc.FlagDevBuild, body[:33333])

	add := func(name string, plain []byte, to *rsa.PublicKey, profile string, dev bool, expect string, tamper bool) error {
		enc, err := encimg.Encrypt(plain, to)
		if err != nil {
			return err
		}
		if tamper {
			enc[len(enc)/2] ^= 0x40
		}
		sum := sha256.Sum256(plain)
		f := name + ".enc"
		v.Images = append(v.Images, image{Name: name, File: f, ImgSize: len(plain), SHA256: hex.EncodeToString(sum[:]),
			Profile: profile, Dev: dev, Expect: expect})
		return os.WriteFile(filepath.Join(dir, f), enc, 0o644)
	}
	steps := []error{
		add("release_ok", signed, &otaKey.PublicKey, "zir3m-full", false, "ok", false),
		add("release_second_key", signedOther, &otaKey.PublicKey, "zir3m-full", false, "ok", false), // fw-other is trusted too
		add("release_wrong_profile", signed, &otaKey.PublicKey, "other", false, "format", false),
		add("release_other_device", signed, &otherOta.PublicKey, "zir3m-full", false, "sig", false),
		add("release_tampered", signed, &otaKey.PublicKey, "zir3m-full", false, "sig", true),
		add("dev_ok", devImg, &otaKey.PublicKey, "zir3m-full", true, "ok", false),
		add("dev_manifest_release_image", signed, &otaKey.PublicKey, "zir3m-full", true, "format", false),
	}
	// A release manifest with an unsigned (but padded) image: signature check fails.
	padded := append(bytes.Clone(release), bytes.Repeat([]byte{0xFF}, 4096-len(release)%4096+4096)...)
	steps = append(steps, add("release_unsigned", padded, &otaKey.PublicKey, "zir3m-full", false, "sig", false))
	for _, err := range steps {
		if err != nil {
			return err
		}
	}
	data, _ := json.MarshalIndent(v, "", "  ")
	return os.WriteFile(filepath.Join(dir, "vectors.json"), data, 0o644)
}

func check(dir string) error {
	var v vectors
	var r results
	data, err := os.ReadFile(filepath.Join(dir, "vectors.json"))
	if err != nil {
		return err
	}
	json.Unmarshal(data, &v)
	if data, err = os.ReadFile(filepath.Join(dir, "results.json")); err != nil {
		return err
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return err
	}
	pubRaw, _ := hex.DecodeString(r.SignPub)
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), pubRaw)
	if err != nil {
		return fmt.Errorf("sign_pub: %w", err)
	}
	sig, _ := base64.RawURLEncoding.DecodeString(r.Sig)
	if !jws.VerifyRaw(pub, []byte(r.SigMsg), sig) {
		return fmt.Errorf("ES256 signature from the firmware does not verify")
	}
	if !core.VerifyDeviceSig(pubRaw, r.ReqMethod, r.ReqURI, []byte(r.ReqBody), r.ReqSig) {
		return fmt.Errorf("X-Zir-Sig from the firmware does not verify")
	}
	tp, _ := hex.DecodeString(v.TelemetryPriv)
	tlm, err := ecdh.P256().NewPrivateKey(tp)
	if err != nil {
		return err
	}
	plain, err := ecies.Open(tlm, ecies.InfoRegPassword, r.Box, []byte(r.BoxAAD))
	if err != nil || string(plain) != r.BoxPlain {
		return fmt.Errorf("box from the firmware: %v %q", err, plain)
	}
	gp, _ := hex.DecodeString(r.GenPriv)
	gk, err := ecdh.P256().NewPrivateKey(gp)
	if err != nil || hex.EncodeToString(gk.PublicKey().Bytes()) != r.Generated {
		return fmt.Errorf("generated key pair does not match")
	}
	if r.ImagesPass != len(v.Images) {
		return fmt.Errorf("images: %d of %d as expected", r.ImagesPass, len(v.Images))
	}
	fmt.Println("OK: firmware ES256, X-Zir-Sig, zir box, key generation verified by the server code;", r.ImagesPass, "image cases")
	return nil
}
