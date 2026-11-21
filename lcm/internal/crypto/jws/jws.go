// Package jws implements JWS compact serialization with ES256 only
// (ECDSA P-256 + SHA-256, raw r||s signature), as used for manifests,
// configs and engineer tokens. The header always carries "kid" so the
// device can pick the right key from its key table during key rotation.
package jws

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

var b64 = base64.RawURLEncoding

type Header struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ,omitempty"`
}

// Sign serializes payload (any JSON-marshalable value) and signs it.
func Sign(key *ecdsa.PrivateKey, kid, typ string, payload any) (string, error) {
	hdr, err := json.Marshal(Header{Alg: "ES256", Kid: kid, Typ: typ})
	if err != nil {
		return "", err
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	input := b64.EncodeToString(hdr) + "." + b64.EncodeToString(body)
	sig, err := SignRaw(key, []byte(input))
	if err != nil {
		return "", err
	}
	return input + "." + b64.EncodeToString(sig), nil
}

// SignRaw returns the 64-byte r||s ES256 signature of msg.
func SignRaw(key *ecdsa.PrivateKey, msg []byte) ([]byte, error) {
	digest := sha256.Sum256(msg)
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return nil, err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return sig, nil
}

// VerifyRaw checks a 64-byte r||s ES256 signature.
func VerifyRaw(pub *ecdsa.PublicKey, msg, sig []byte) bool {
	if len(sig) != 64 {
		return false
	}
	digest := sha256.Sum256(msg)
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	return ecdsa.Verify(pub, digest[:], r, s)
}

// KeyFunc returns the public key for a kid, or nil if unknown.
type KeyFunc func(kid string) *ecdsa.PublicKey

// Verify checks the signature and decodes the payload into out.
// The signature is checked before the payload is parsed.
func Verify(token string, keys KeyFunc, out any) (Header, error) {
	var h Header
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return h, errors.New("jws: malformed token")
	}
	hdr, err := b64.DecodeString(parts[0])
	if err != nil {
		return h, errors.New("jws: bad header encoding")
	}
	if err := json.Unmarshal(hdr, &h); err != nil || h.Alg != "ES256" {
		return h, errors.New("jws: unsupported header")
	}
	pub := keys(h.Kid)
	if pub == nil {
		return h, fmt.Errorf("jws: unknown kid %q", h.Kid)
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil || !VerifyRaw(pub, []byte(parts[0]+"."+parts[1]), sig) {
		return h, errors.New("jws: bad signature")
	}
	body, err := b64.DecodeString(parts[1])
	if err != nil {
		return h, errors.New("jws: bad payload encoding")
	}
	if out != nil {
		if err := json.Unmarshal(body, out); err != nil {
			return h, fmt.Errorf("jws: payload: %w", err)
		}
	}
	return h, nil
}
