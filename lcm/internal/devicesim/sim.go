// Package devicesim implements the device side of the protocol in Go: the
// same checks the firmware must do. It drives integration tests and the
// devicesim CLI, so the server can be developed without hardware.
package devicesim

import (
	"bytes"
	"context"
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
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"zir/lcm/internal/core"
	"zir/lcm/internal/crypto/appdesc"
	"zir/lcm/internal/crypto/ecies"
	"zir/lcm/internal/crypto/encimg"
	"zir/lcm/internal/crypto/espsig"
	"zir/lcm/internal/crypto/jws"
)

var b64 = base64.RawURLEncoding

// Keys are the server public keys compiled into the firmware.
type Keys struct {
	ES256     map[string]*ecdsa.PublicKey // kid -> key (manifest, config, engtoken, www)
	Telemetry *ecdh.PublicKey
	Firmware  *rsa.PublicKey // stands for the key in the running app's signature block
}

func (k Keys) Lookup(prefix string) jws.KeyFunc {
	return func(kid string) *ecdsa.PublicKey {
		if !strings.HasPrefix(kid, prefix+"-") {
			return nil // a config key must not verify a manifest, etc.
		}
		return k.ES256[kid]
	}
}

// LoadKeys reads the PEM files written by `lcmctl export-pubkeys`.
func LoadKeys(dir string) (Keys, error) {
	k := Keys{ES256: map[string]*ecdsa.PublicKey{}}
	files, err := filepath.Glob(filepath.Join(dir, "*.pem"))
	if err != nil {
		return k, err
	}
	for _, f := range files {
		data, _ := os.ReadFile(f)
		blk, _ := pem.Decode(data)
		if blk == nil {
			continue
		}
		pub, err := x509.ParsePKIXPublicKey(blk.Bytes)
		if err != nil {
			return k, err
		}
		kid := strings.TrimSuffix(filepath.Base(f), ".pem")
		switch p := pub.(type) {
		case *rsa.PublicKey:
			k.Firmware = p
		case *ecdsa.PublicKey:
			if strings.HasPrefix(kid, "telemetry-") {
				k.Telemetry, _ = p.ECDH()
			} else {
				k.ES256[kid] = p
			}
		}
	}
	if k.Telemetry == nil || k.Firmware == nil {
		return k, fmt.Errorf("no telemetry or firmware key in %s", dir)
	}
	return k, nil
}

// State is what the device keeps in flash (identity + nvs).
type State struct {
	MAC         string `json:"mac"`
	Profile     string `json:"profile"`     // compiled into the firmware
	AppVersion  string `json:"app_version"` // running firmware
	SignPriv    []byte `json:"sign_priv"`   // PKCS#8
	KexPriv     []byte `json:"kex_priv"`    // PKCS#8
	WebPassword string `json:"web_password"`
	RequestID   string `json:"request_id,omitempty"`
	ClaimCode   string `json:"claim_code,omitempty"`
	DeviceID    string `json:"device_id,omitempty"`
	Serial      string `json:"serial,omitempty"`
	Config      string `json:"config,omitempty"`
	ConfigVer   int    `json:"config_version,omitempty"`
	OTAKeyPEM   []byte `json:"ota_key,omitempty"`
	AppSHA256   string `json:"app_sha256,omitempty"`
	WWWSHA256   string `json:"www_sha256,omitempty"`
	ReleaseID   string `json:"release_id,omitempty"`
	DevBuildID  string `json:"dev_build_id,omitempty"` // installed dev build
	Dev         bool   `json:"dev,omitempty"`          // signed config says "developer device"
	PollAfter   int    `json:"poll_after,omitempty"`   // from the last update check
}

type Device struct {
	Base  string
	HTTP  *http.Client
	Keys  Keys
	State State
	Now   func() time.Time

	token   string
	sign    *ecdsa.PrivateKey
	kex     *ecdh.PrivateKey
	Revoked bool
	LastWWW []byte // installed www.tar
	LastApp []byte // installed signed app image
}

// New creates a factory-fresh device (bootstrap generates its keys).
func New(base string, keys Keys, mac, profile string) (*Device, error) {
	sign, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	kex, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	sp, _ := x509.MarshalPKCS8PrivateKey(sign)
	kp, _ := x509.MarshalPKCS8PrivateKey(kex)
	d := &Device{Base: strings.TrimRight(base, "/"), HTTP: http.DefaultClient, Keys: keys, Now: time.Now,
		State: State{MAC: mac, Profile: profile, AppVersion: "0.0.0", SignPriv: sp, KexPriv: kp, WebPassword: "zir-" + randomPassword()},
		sign:  sign, kex: kex}
	return d, nil
}

// Restore loads a device from saved state.
func Restore(base string, keys Keys, st State) (*Device, error) {
	sp, err := x509.ParsePKCS8PrivateKey(st.SignPriv)
	if err != nil {
		return nil, err
	}
	kp, err := x509.ParsePKCS8PrivateKey(st.KexPriv)
	if err != nil {
		return nil, err
	}
	// PKCS#8 has one encoding for P-256 keys; it parses back as ECDSA.
	kex, err := kp.(*ecdsa.PrivateKey).ECDH()
	if err != nil {
		return nil, err
	}
	return &Device{Base: strings.TrimRight(base, "/"), HTTP: http.DefaultClient, Keys: keys, Now: time.Now,
		State: st, sign: sp.(*ecdsa.PrivateKey), kex: kex}, nil
}

func randomPassword() string {
	const alphabet = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"
	b := make([]byte, 5)
	rand.Read(b)
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}

// APIError is a non-2xx reply.
type APIError struct {
	Status  int
	Code    string `json:"error"`
	Message string `json:"message"`
}

func (e *APIError) Error() string { return fmt.Sprintf("%d %s: %s", e.Status, e.Code, e.Message) }

func (d *Device) do(ctx context.Context, method, uri string, body any, signed bool, out any) error {
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, d.Base+uri, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if signed {
		sig, err := jws.SignRaw(d.sign, core.DeviceSigMessage(method, uri, raw))
		if err != nil {
			return err
		}
		req.Header.Set("X-Zir-Sig", b64.EncodeToString(sig))
	}
	if d.token != "" {
		req.Header.Set("Authorization", "Bearer "+d.token)
	}
	resp, err := d.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		e := &APIError{Status: resp.StatusCode}
		json.Unmarshal(data, e)
		return e
	}
	if out != nil {
		if b, ok := out.(*[]byte); ok {
			*b = data
			return nil
		}
		return json.Unmarshal(data, out)
	}
	return nil
}

// Register sends the registration request and returns the claim code.
func (d *Device) Register(ctx context.Context) (string, error) {
	box, err := ecies.Seal(d.Keys.Telemetry, ecies.InfoRegPassword, []byte(d.State.WebPassword), []byte(strings.ToLower(d.State.MAC)))
	if err != nil {
		return "", err
	}
	kexPub := d.kex.PublicKey().Bytes()
	signPub, _ := d.sign.PublicKey.Bytes()
	var rep core.RegisterReply
	err = d.do(ctx, "POST", "/dev/v1/register/request", core.RegisterRequest{
		MAC: d.State.MAC, ChipRev: "3.1", BootstrapVersion: "sim",
		DevSignPub: b64.EncodeToString(signPub), DevKexPub: b64.EncodeToString(kexPub), WebPassword: box,
	}, true, &rep)
	if err != nil {
		return "", err
	}
	d.State.RequestID, d.State.ClaimCode = rep.RequestID, rep.ClaimCode
	return rep.ClaimCode, nil
}

// PollRegistration asks once. done=true once approved and stored.
func (d *Device) PollRegistration(ctx context.Context) (status string, err error) {
	var st core.RegisterStatus
	uri := "/dev/v1/register/status?request_id=" + url.QueryEscape(d.State.RequestID)
	if err := d.do(ctx, "GET", uri, nil, true, &st); err != nil {
		return "", err
	}
	if st.Status != "approved" {
		return st.Status, nil
	}
	// Bootstrap checks: config signature, device id and MAC; decrypt K_ota.
	cfg, err := d.verifyConfig(st.Config, st.DeviceID)
	if err != nil {
		return "", err
	}
	if st.OTAKey == nil {
		return "", errors.New("no ota_key in reply")
	}
	otaPEM, err := ecies.Open(d.kex, ecies.InfoOTAKey, *st.OTAKey, []byte(st.DeviceID))
	if err != nil {
		return "", fmt.Errorf("decrypt ota_key: %w", err)
	}
	d.State.DeviceID, d.State.Serial, d.State.Config, d.State.ConfigVer, d.State.OTAKeyPEM = st.DeviceID, st.Serial, st.Config, cfg.Version, otaPEM
	d.State.Dev = cfg.Dev
	d.State.RequestID, d.State.ClaimCode = "", ""
	return "approved", nil
}

func (d *Device) verifyConfig(tok, deviceID string) (core.ConfigPayload, error) {
	var cfg core.ConfigPayload
	if _, err := jws.Verify(tok, d.Keys.Lookup("config"), &cfg); err != nil {
		return cfg, fmt.Errorf("config: %w", err)
	}
	if cfg.Typ != "zir-config/1" || cfg.DeviceID != deviceID || !strings.EqualFold(cfg.MAC, d.State.MAC) || cfg.Profile != d.State.Profile {
		return cfg, fmt.Errorf("config is for another device or profile (%s %s %s)", cfg.DeviceID, cfg.MAC, cfg.Profile)
	}
	return cfg, nil
}

// Auth runs challenge/response and keeps the session token.
func (d *Device) Auth(ctx context.Context) error {
	d.token = ""
	var ch core.ChallengeReply
	if err := d.do(ctx, "POST", "/dev/v1/auth/challenge", map[string]string{"device_id": d.State.DeviceID}, false, &ch); err != nil {
		return err
	}
	var s core.SessionReply
	err := d.do(ctx, "POST", "/dev/v1/auth/session", core.SessionRequest{
		DeviceID: d.State.DeviceID, Nonce: ch.Nonce, MAC: d.State.MAC, AppVersion: d.State.AppVersion,
		AppSHA256: d.State.AppSHA256, WWWSHA256: d.State.WWWSHA256, ReleaseID: d.State.ReleaseID,
	}, true, &s)
	if err != nil {
		return err
	}
	d.token = s.SessionToken
	return nil
}

// CheckUpdate returns the verified manifest, or nil when there is none.
// It also fetches a newer config if the server has one.
func (d *Device) CheckUpdate(ctx context.Context) (*core.Manifest, error) {
	var rep core.UpdateReply
	if err := d.do(ctx, "GET", "/dev/v1/update", nil, false, &rep); err != nil {
		var ae *APIError
		if errors.As(err, &ae) && ae.Code == "device_revoked" {
			d.Revoked = true
		}
		return nil, err
	}
	d.State.PollAfter = rep.PollAfter
	if rep.ConfigVersion > d.State.ConfigVer {
		if err := d.FetchConfig(ctx); err != nil {
			return nil, err
		}
	}
	if rep.Manifest == nil {
		return nil, nil
	}
	var m core.Manifest
	if _, err := jws.Verify(*rep.Manifest, d.Keys.Lookup("manifest"), &m); err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	if m.Typ != "zir-manifest/1" || m.DeviceID != d.State.DeviceID || m.Profile != d.State.Profile {
		return nil, errors.New("manifest is for another device or profile")
	}
	if d.Now().Unix() > m.EXP {
		return nil, errors.New("manifest expired")
	}
	// An unsigned dev image is acceptable only on a developer device, and the
	// flag must come from the signed config, not from the manifest alone.
	if m.Dev && !d.State.Dev {
		return nil, errors.New("dev build offered, but the config does not allow it")
	}
	if m.Dev != (m.DevBuildID != "") || (m.Dev && m.ReleaseID != "") {
		return nil, errors.New("inconsistent dev manifest")
	}
	return &m, nil
}

func (d *Device) FetchConfig(ctx context.Context) error {
	var r core.ConfigReply
	if err := d.do(ctx, "GET", "/dev/v1/config", nil, false, &r); err != nil {
		return err
	}
	cfg, err := d.verifyConfig(r.Config, d.State.DeviceID)
	if err != nil {
		return err
	}
	if cfg.Version <= d.State.ConfigVer {
		return fmt.Errorf("config version %d not newer than %d", cfg.Version, d.State.ConfigVer)
	}
	d.State.Config, d.State.ConfigVer, d.State.Dev = r.Config, cfg.Version, cfg.Dev
	return nil
}

// Install follows FIRMWARE_REQUIREMENTS 6.2: app, then www, then report.
func (d *Device) Install(ctx context.Context, m *core.Manifest) error {
	report := func(status, msg string) {
		d.do(ctx, "POST", "/dev/v1/update/report", core.UpdateReport{ReleaseID: m.ReleaseID, DevBuildID: m.DevBuildID,
			Status: status, Error: msg, Mode: m.Mode}, false, nil)
	}
	var app []byte
	if m.App.Needed {
		var enc []byte
		if err := d.do(ctx, "GET", m.App.URL, nil, false, &enc); err != nil {
			report("failed", err.Error())
			return err
		}
		blk, _ := pem.Decode(d.State.OTAKeyPEM)
		if blk == nil {
			return errors.New("no ota key")
		}
		otaKey, err := x509.ParsePKCS1PrivateKey(blk.Bytes)
		if err != nil {
			return err
		}
		plain, err := encimg.Decrypt(enc, otaKey)
		if err != nil {
			report("failed", err.Error())
			return err
		}
		if m.Dev {
			// Developer device: no signature, but it must really be a dev build.
			if desc, err := appdesc.Parse(plain); err != nil || !desc.HasZir || !desc.DevBuild() {
				report("failed", "not a dev build")
				return errors.New("dev manifest, but the image is not a dev build")
			}
		} else if _, err := espsig.Verify(plain, d.Keys.Firmware); err != nil {
			report("failed", err.Error())
			return err
		}
		sum := sha256.Sum256(plain)
		if hex.EncodeToString(sum[:]) != m.App.SHA256 {
			report("failed", "sha256 mismatch")
			return errors.New("app sha256 mismatch")
		}
		desc, err := appdesc.Parse(plain)
		if err != nil || desc.Profile != d.State.Profile {
			report("failed", "wrong profile in image")
			return fmt.Errorf("image profile %q, device %q", desc.Profile, d.State.Profile)
		}
		app = plain
	}
	var www []byte
	if m.WWW != nil && m.WWW.Needed {
		if err := d.do(ctx, "GET", m.WWW.URL, nil, false, &www); err != nil {
			report("failed", err.Error())
			return err
		}
		sum := sha256.Sum256(www)
		if hex.EncodeToString(sum[:]) != m.WWW.SHA256 {
			report("failed", "www sha256 mismatch")
			return errors.New("www sha256 mismatch")
		}
		if _, err := core.CheckWWWTar(www); err != nil {
			report("failed", err.Error())
			return err
		}
	}
	// "Reboot" into the new slot; self-check passes.
	if app != nil {
		d.LastApp = app
		desc, _ := appdesc.Parse(app)
		d.State.AppVersion = desc.ZirVersion
		d.State.AppSHA256 = m.App.SHA256
	}
	if www != nil {
		d.LastWWW = www
		d.State.WWWSHA256 = m.WWW.SHA256
	}
	d.State.ReleaseID, d.State.DevBuildID = m.ReleaseID, m.DevBuildID
	report("installed", "")
	return nil
}

// ChangeWebPassword is the user changing the AP password; the device tells the server.
func (d *Device) ChangeWebPassword(ctx context.Context, pw string) error {
	box, err := ecies.Seal(d.Keys.Telemetry, ecies.InfoWebPassword, []byte(pw), []byte(d.State.DeviceID))
	if err != nil {
		return err
	}
	if err := d.do(ctx, "POST", "/dev/v1/web-password", core.WebPasswordReport{Password: box, ChangedAt: d.Now().Unix()}, false, nil); err != nil {
		return err
	}
	d.State.WebPassword = pw
	return nil
}

// TryImageFor checks the core security property: an image fetched for this
// device must not decrypt with another device's key.
func DecryptWith(enc []byte, otaKeyPEM []byte) error {
	blk, _ := pem.Decode(otaKeyPEM)
	if blk == nil {
		return errors.New("no key")
	}
	k, err := x509.ParsePKCS1PrivateKey(blk.Bytes)
	if err != nil {
		return err
	}
	_, err = encimg.Decrypt(enc, k)
	return err
}

// Download fetches a raw artifact (for tests).
func (d *Device) Download(ctx context.Context, uri string) ([]byte, error) {
	var out []byte
	err := d.do(ctx, "GET", uri, nil, false, &out)
	return out, err
}
