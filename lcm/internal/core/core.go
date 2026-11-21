// Package core holds the server's domain logic: profiles, registration,
// devices, configs, builds, releases and OTA. HTTP handlers (admin UI and
// device API) are thin wrappers around it.
package core

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"zir/lcm/internal/crypto/envelope"
	"zir/lcm/internal/crypto/jws"
	"zir/lcm/internal/signer"
)

type Core struct {
	Pool    *pgxpool.Pool
	Signer  *signer.Signer
	Env     *envelope.Key
	DataDir string
	Now     func() time.Time
}

func New(pool *pgxpool.Pool, s *signer.Signer, env *envelope.Key, dataDir string) *Core {
	return &Core{Pool: pool, Signer: s, Env: env, DataDir: dataDir, Now: time.Now}
}

// Error is a problem the caller can show to the user (Ukrainian text) or
// return to the device (Code).
type Error struct {
	Status int    // HTTP status for APIs
	Code   string // machine-readable, for devices
	Msg    string // for people
}

func (e *Error) Error() string { return e.Msg }

func userErr(status int, code, msg string, args ...any) error {
	return &Error{Status: status, Code: code, Msg: fmt.Sprintf(msg, args...)}
}

// AsError extracts a *Error.
func AsError(err error) (*Error, bool) {
	var e *Error
	ok := errors.As(err, &e)
	return e, ok
}

var b64 = base64.RawURLEncoding

// DecodeB64 accepts base64url or standard base64, with or without padding.
func DecodeB64(s string) ([]byte, error) {
	s = strings.TrimRight(s, "=")
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawStdEncoding.DecodeString(s)
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

// p256Point parses a 65-byte uncompressed P-256 point as both an ECDSA and
// an ECDH public key.
func p256Point(raw []byte) (*ecdsa.PublicKey, *ecdh.PublicKey, error) {
	ek, err := ecdh.P256().NewPublicKey(raw)
	if err != nil {
		return nil, nil, errors.New("bad P-256 public key")
	}
	pk, err := ecdsa.ParseUncompressedPublicKey(elliptic256(), raw)
	if err != nil {
		return nil, nil, errors.New("bad P-256 public key")
	}
	return pk, ek, nil
}

// DeviceSigMessage is what a device signs for every signed request:
// METHOD "\n" request-URI (path and query exactly as sent) "\n" body.
func DeviceSigMessage(method, requestURI string, body []byte) []byte {
	msg := make([]byte, 0, len(method)+len(requestURI)+2+len(body))
	msg = append(msg, method...)
	msg = append(msg, '\n')
	msg = append(msg, requestURI...)
	msg = append(msg, '\n')
	return append(msg, body...)
}

// VerifyDeviceSig checks the X-Zir-Sig header value (base64url r||s).
func VerifyDeviceSig(pubRaw []byte, method, requestURI string, body []byte, sigB64 string) bool {
	pk, _, err := p256Point(pubRaw)
	if err != nil {
		return false
	}
	sig, err := DecodeB64(sigB64)
	if err != nil {
		return false
	}
	return jws.VerifyRaw(pk, DeviceSigMessage(method, requestURI, body), sig)
}

func (c *Core) path(parts ...string) string {
	return filepath.Join(append([]string{c.DataDir}, parts...)...)
}

func writeFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
