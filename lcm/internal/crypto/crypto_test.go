package crypto_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"

	"zir/lcm/internal/crypto/appdesc"
	"zir/lcm/internal/crypto/ecies"
	"zir/lcm/internal/crypto/envelope"
	"zir/lcm/internal/crypto/jws"
)

func TestEnvelope(t *testing.T) {
	mk := make([]byte, 32)
	rand.Read(mk)
	k, _ := envelope.New(mk)
	sealed, err := k.Seal([]byte("secret"), "device:1:ota_key")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := k.Open(sealed, "device:1:ota_key"); err != nil || string(got) != "secret" {
		t.Fatalf("open: %v", err)
	}
	if _, err := k.Open(sealed, "device:2:ota_key"); err == nil {
		t.Fatal("opened with another aad")
	}
}

func TestJWS(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tok, err := jws.Sign(key, "cfg-1", "zir-config/1", map[string]any{"version": 7})
	if err != nil {
		t.Fatal(err)
	}
	keys := func(kid string) *ecdsa.PublicKey {
		if kid == "cfg-1" {
			return &key.PublicKey
		}
		return nil
	}
	var out struct{ Version int }
	h, err := jws.Verify(tok, keys, &out)
	if err != nil || out.Version != 7 || h.Typ != "zir-config/1" {
		t.Fatalf("verify: %v %+v", err, out)
	}
	if _, err := jws.Verify(tok, func(string) *ecdsa.PublicKey { return &other.PublicKey }, nil); err == nil {
		t.Fatal("verified with wrong key")
	}
	parts := strings.Split(tok, ".")
	forged := parts[0] + "." + "eyJ2ZXJzaW9uIjo5fQ" + "." + parts[2]
	if _, err := jws.Verify(forged, keys, nil); err == nil {
		t.Fatal("forged payload accepted")
	}
}

func TestECIES(t *testing.T) {
	priv, _ := ecdh.P256().GenerateKey(rand.Reader)
	box, err := ecies.Seal(priv.PublicKey(), ecies.InfoOTAKey, []byte("pem"), []byte("dev-1"))
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(box)
	var back ecies.Box
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if got, err := ecies.Open(priv, ecies.InfoOTAKey, back, []byte("dev-1")); err != nil || string(got) != "pem" {
		t.Fatalf("open: %v", err)
	}
	if _, err := ecies.Open(priv, ecies.InfoTelemetry, back, []byte("dev-1")); err == nil {
		t.Fatal("opened with another purpose")
	}
	if _, err := ecies.Open(priv, ecies.InfoOTAKey, back, []byte("dev-2")); err == nil {
		t.Fatal("opened with another aad")
	}
}

func TestAppDesc(t *testing.T) {
	body := bytes.Repeat([]byte{1, 2, 3}, 1000)
	a := appdesc.Build("1.4.0", "zir3m-full", 3, 0, body)
	d, err := appdesc.Parse(a)
	if err != nil {
		t.Fatal(err)
	}
	if d.Version != "1.4.0" || d.Profile != "zir3m-full" || d.WwwAPI != 3 || d.DevBuild() || !d.HasZir {
		t.Fatalf("parsed %+v", d)
	}
	b := appdesc.Build("1.5.0-beta.1", "zir3m-full", 3, 0, body)
	ha, _ := appdesc.ComparableHash(a)
	hb, _ := appdesc.ComparableHash(b)
	if ha != hb {
		t.Fatal("comparable hash differs for the same code")
	}
	c := appdesc.Build("1.5.0", "zir3m-full", 3, 0, append(body, 9))
	hc, _ := appdesc.ComparableHash(c)
	if ha == hc {
		t.Fatal("comparable hash equal for different code")
	}
	dev, _ := appdesc.Parse(appdesc.Build("1.5.0", "zir3m-full", 3, appdesc.FlagDevBuild, body))
	if !dev.DevBuild() {
		t.Fatal("dev flag not parsed")
	}
}
