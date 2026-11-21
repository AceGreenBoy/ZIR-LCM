// Package ecies is the "zir box": P-256 ECDH with an ephemeral key,
// HKDF-SHA256 and AES-256-GCM. It carries secrets to a holder of a P-256
// private key: K_ota to the device (dev_kex), the web password and telemetry
// to the server (K_telemetry).
//
//	shared = ECDH(eph_priv, recipient_pub)
//	key    = HKDF-SHA256(ikm=shared, salt=empty, info=<purpose>, 32 bytes)
//	ct     = AES-256-GCM(key, iv (12 bytes), plaintext, aad)
//
// JSON form: {"epk": b64url(65-byte uncompressed point), "iv": b64url, "ct": b64url(ciphertext||tag)}.
package ecies

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
)

// Purposes (HKDF info). Each value is used for exactly one kind of payload.
const (
	InfoOTAKey      = "zir-otakey/1"
	InfoRegPassword = "zir-reg/1"
	InfoTelemetry   = "zir-tlm/1"
	InfoCoredump    = "zir-core/1"
	InfoWebPassword = "zir-pwd/1"
)

const ivSize = 12

type Box struct {
	EPK []byte `json:"epk"`
	IV  []byte `json:"iv"`
	CT  []byte `json:"ct"`
}

type boxJSON struct {
	EPK string `json:"epk"`
	IV  string `json:"iv"`
	CT  string `json:"ct"`
}

var b64 = base64.RawURLEncoding

func (b Box) MarshalJSON() ([]byte, error) {
	return json.Marshal(boxJSON{b64.EncodeToString(b.EPK), b64.EncodeToString(b.IV), b64.EncodeToString(b.CT)})
}

func (b *Box) UnmarshalJSON(data []byte) error {
	var j boxJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}
	var err error
	if b.EPK, err = b64.DecodeString(j.EPK); err != nil {
		return errors.New("ecies: bad epk")
	}
	if b.IV, err = b64.DecodeString(j.IV); err != nil {
		return errors.New("ecies: bad iv")
	}
	if b.CT, err = b64.DecodeString(j.CT); err != nil {
		return errors.New("ecies: bad ct")
	}
	return nil
}

func Seal(to *ecdh.PublicKey, info string, plain, aad []byte) (Box, error) {
	eph, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return Box{}, err
	}
	aead, err := deriveAEAD(eph, to, info)
	if err != nil {
		return Box{}, err
	}
	iv := make([]byte, ivSize)
	if _, err := rand.Read(iv); err != nil {
		return Box{}, err
	}
	return Box{EPK: eph.PublicKey().Bytes(), IV: iv, CT: aead.Seal(nil, iv, plain, aad)}, nil
}

func Open(priv *ecdh.PrivateKey, info string, box Box, aad []byte) ([]byte, error) {
	epk, err := ecdh.P256().NewPublicKey(box.EPK)
	if err != nil {
		return nil, errors.New("ecies: bad ephemeral key")
	}
	if len(box.IV) != ivSize {
		return nil, errors.New("ecies: bad iv")
	}
	aead, err := deriveAEAD(priv, epk, info)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, box.IV, box.CT, aad)
	if err != nil {
		return nil, errors.New("ecies: decryption failed")
	}
	return plain, nil
}

func deriveAEAD(priv *ecdh.PrivateKey, pub *ecdh.PublicKey, info string) (cipher.AEAD, error) {
	shared, err := priv.ECDH(pub)
	if err != nil {
		return nil, err
	}
	key, err := hkdf.Key(sha256.New, shared, nil, info, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
