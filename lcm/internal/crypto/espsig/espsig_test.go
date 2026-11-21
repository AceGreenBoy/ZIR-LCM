package espsig

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"zir/lcm/internal/testutil"
)

var (
	keyOnce sync.Once
	testKey *rsa.PrivateKey
)

func key(t *testing.T) *rsa.PrivateKey {
	keyOnce.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, KeyBits)
		if err != nil {
			t.Fatal(err)
		}
		testKey = k
	})
	return testKey
}

func image(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func TestSignVerify(t *testing.T) {
	k := key(t)
	for _, size := range []int{1, 4095, 4096, 100000} {
		img := image(size)
		signed, err := Sign(img, k)
		if err != nil {
			t.Fatal(err)
		}
		if len(signed)%SectorSize != 0 {
			t.Fatalf("size %d: signed length %d not sector aligned", size, len(signed))
		}
		contents, err := Verify(signed, &k.PublicKey)
		if err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		if !bytes.Equal(contents[:size], img) {
			t.Fatalf("size %d: contents changed", size)
		}
		if !HasSignature(signed) || HasSignature(pad(img)) {
			t.Fatalf("size %d: HasSignature wrong", size)
		}
		pub, err := PublicKey(signed)
		if err != nil || pub.N.Cmp(k.N) != 0 {
			t.Fatalf("size %d: embedded public key mismatch", size)
		}
	}
}

func TestVerifyRejectsTampering(t *testing.T) {
	k := key(t)
	signed, _ := Sign(image(10000), k)
	bad := bytes.Clone(signed)
	bad[100] ^= 1
	if _, err := Verify(bad, &k.PublicKey); err == nil {
		t.Fatal("tampered contents accepted")
	}
	other, _ := rsa.GenerateKey(rand.Reader, KeyBits)
	if _, err := Verify(signed, &other.PublicKey); err == nil {
		t.Fatal("wrong key accepted")
	}
}

// TestCompatEspsecure checks the block against espsecure.py both ways:
// it verifies our signature, and we verify its signature.
func TestCompatEspsecure(t *testing.T) {
	py := testutil.CompatPython(t)
	dir := testutil.EsptoolDir(t)
	k := key(t)
	keyPath := testutil.WriteRSAPrivatePEM(t, k)
	tmp := t.TempDir()

	img := image(70001)
	signed, err := Sign(img, k)
	if err != nil {
		t.Fatal(err)
	}
	ours := filepath.Join(tmp, "ours.bin")
	os.WriteFile(ours, signed, 0o644)
	out := testutil.Run(t, dir, py, "-m", "espsecure", "verify_signature", "--version", "2", "--keyfile", keyPath, ours)
	if !strings.Contains(out, "verification successful") {
		t.Fatalf("espsecure did not verify our signature:\n%s", out)
	}

	unsigned := filepath.Join(tmp, "unsigned.bin")
	theirs := filepath.Join(tmp, "theirs.bin")
	os.WriteFile(unsigned, img, 0o644)
	testutil.Run(t, dir, py, "-m", "espsecure", "sign_data", "--version", "2", "--keyfile", keyPath, "--output", theirs, unsigned)
	theirSigned, _ := os.ReadFile(theirs)
	if _, err := Verify(theirSigned, &k.PublicKey); err != nil {
		t.Fatalf("espsecure signature rejected: %v", err)
	}
	// PSS is randomized, but everything except the signature must match.
	if !bytes.Equal(theirSigned[:len(theirSigned)-SectorSize+812], signed[:len(signed)-SectorSize+812]) {
		t.Fatal("block header differs from espsecure")
	}
}
