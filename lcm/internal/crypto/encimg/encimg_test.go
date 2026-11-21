package encimg

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"os"
	"path/filepath"
	"testing"

	"zir/lcm/internal/testutil"
)

func genKey(t *testing.T) *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestRoundTrip(t *testing.T) {
	k := genKey(t)
	plain := make([]byte, 123457)
	rand.Read(plain)
	enc, err := Encrypt(plain, &k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decrypt(enc, k)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("round trip failed: %v", err)
	}

	other := genKey(t)
	if _, err := Decrypt(enc, other); err == nil {
		t.Fatal("image decrypted with another device's key")
	}
	enc[HeaderSize+10] ^= 1
	if _, err := Decrypt(enc, k); err == nil {
		t.Fatal("tampered image accepted")
	}
}

// encGenTool returns the path of esp_enc_img_gen.py from ZIR_ENC_IMG_GEN.
func encGenTool(t *testing.T) string {
	p := os.Getenv("ZIR_ENC_IMG_GEN")
	if p == "" {
		t.Skip("ZIR_ENC_IMG_GEN not set: skipping compatibility test with esp_enc_img_gen.py")
	}
	return p
}

func TestCompatEspEncImgGen(t *testing.T) {
	py := testutil.CompatPython(t)
	tool := encGenTool(t)
	k := genKey(t)
	keyPath := testutil.WriteRSAPrivatePEM(t, k)
	pubPath := testutil.WriteRSAPublicPEM(t, &k.PublicKey)
	tmp := t.TempDir()

	plain := make([]byte, 70000)
	rand.Read(plain)

	// Ours -> their decrypt.
	enc, _ := Encrypt(plain, &k.PublicKey)
	ours := filepath.Join(tmp, "ours.enc")
	os.WriteFile(ours, enc, 0o644)
	dec := filepath.Join(tmp, "ours.dec")
	testutil.Run(t, tmp, py, "-I", tool, "decrypt", ours, keyPath, dec)
	got, _ := os.ReadFile(dec)
	if !bytes.Equal(got, plain) {
		t.Fatal("esp_enc_img_gen.py decrypted something else")
	}

	// Their encrypt -> ours.
	in := filepath.Join(tmp, "plain.bin")
	theirs := filepath.Join(tmp, "theirs.enc")
	os.WriteFile(in, plain, 0o644)
	testutil.Run(t, tmp, py, "-I", tool, "encrypt", in, pubPath, theirs)
	theirEnc, _ := os.ReadFile(theirs)
	got, err := Decrypt(theirEnc, k)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("cannot decrypt esp_enc_img_gen.py output: %v", err)
	}
}
