// Package envelope encrypts secrets at rest with the master key
// (AES-256-GCM). Ciphertext: version byte 0x01 | 12-byte nonce | sealed data.
// The aad binds a ciphertext to its place (for example "device:<id>:ota_key"),
// so a value copied into another row does not decrypt.
package envelope

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
)

const version = 0x01

type Key struct{ aead cipher.AEAD }

// New takes a 32-byte master key.
func New(master []byte) (*Key, error) {
	if len(master) != 32 {
		return nil, errors.New("envelope: master key must be 32 bytes")
	}
	block, err := aes.NewCipher(master)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Key{aead: aead}, nil
}

func (k *Key) Seal(plain []byte, aad string) ([]byte, error) {
	nonce := make([]byte, k.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := append([]byte{version}, nonce...)
	return k.aead.Seal(out, nonce, plain, []byte(aad)), nil
}

func (k *Key) Open(sealed []byte, aad string) ([]byte, error) {
	ns := k.aead.NonceSize()
	if len(sealed) < 1+ns+k.aead.Overhead() || sealed[0] != version {
		return nil, errors.New("envelope: malformed ciphertext")
	}
	plain, err := k.aead.Open(nil, sealed[1:1+ns], sealed[1+ns:], []byte(aad))
	if err != nil {
		return nil, errors.New("envelope: decryption failed (wrong master key or aad)")
	}
	return plain, nil
}
