// Package testutil holds helpers shared by tests.
package testutil

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// CompatPython returns a Python interpreter that has the `cryptography`
// package, from ZIR_COMPAT_PYTHON. Compatibility tests against Espressif's
// tools are skipped when it is not set.
func CompatPython(t *testing.T) string {
	t.Helper()
	py := os.Getenv("ZIR_COMPAT_PYTHON")
	if py == "" {
		t.Skip("ZIR_COMPAT_PYTHON not set: skipping compatibility test with Espressif tools")
	}
	return py
}

// EsptoolDir returns the directory containing the espsecure package, from
// ZIR_ESPTOOL_DIR (default: PlatformIO's tool-esptoolpy).
func EsptoolDir(t *testing.T) string {
	t.Helper()
	dir := os.Getenv("ZIR_ESPTOOL_DIR")
	if dir == "" {
		home, _ := os.UserHomeDir()
		dir = filepath.Join(home, ".platformio", "packages", "tool-esptoolpy")
	}
	if _, err := os.Stat(filepath.Join(dir, "espsecure")); err != nil {
		t.Skipf("espsecure not found in %s (set ZIR_ESPTOOL_DIR)", dir)
	}
	return dir
}

// Run runs a command and fails the test with its output on error.
func Run(t *testing.T, dir string, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
	return string(out)
}

// WriteRSAPrivatePEM writes key as a PKCS#1 PEM file and returns its path.
func WriteRSAPrivatePEM(t *testing.T, key *rsa.PrivateKey) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "key.pem")
	data := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// WriteRSAPublicPEM writes key as a PKIX PEM file and returns its path.
func WriteRSAPublicPEM(t *testing.T, key *rsa.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "pub.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}
