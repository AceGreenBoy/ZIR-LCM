// Package encimg produces pre-encrypted OTA images for the ESP-IDF
// esp_encrypted_img component (v2.x, RSA-3072 scheme), byte-compatible with
// its esp_enc_img_gen.py tool. The device decrypts them with its private
// K_ota key while downloading (esp_https_ota decrypt_cb).
//
// Format (512-byte header, then ciphertext):
//
//	u32 LE magic 0x0788b6cf
//	384     AES-256-GCM key encrypted with the device RSA-3072 public key (PKCS#1 v1.5)
//	16      GCM IV
//	u32 LE  plaintext size
//	16      GCM auth tag
//	88      zero
//	...     ciphertext (same length as plaintext)
//
// ESP32 classic has no HMAC peripheral, so the component's ECIES scheme is
// not available and only RSA-3072 is implemented here.
package encimg

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	Magic      = 0x0788b6cf
	HeaderSize = 512
	keySize    = 32
	ivSize     = 16
	tagSize    = 16
	encKeySize = 384
	offIV      = 4 + encKeySize
	offSize    = offIV + ivSize
	offTag     = offSize + 4
)

// Encrypt encrypts a (signed) app image for the device that owns pub.
func Encrypt(plain []byte, pub *rsa.PublicKey) ([]byte, error) {
	if pub.N.BitLen() != 3072 {
		return nil, errors.New("encimg: device key must be RSA-3072")
	}
	if uint64(len(plain)) > 0xFFFFFFFF {
		return nil, errors.New("encimg: image too large")
	}
	key := make([]byte, keySize)
	iv := make([]byte, ivSize)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	encKey, err := rsa.EncryptPKCS1v15(rand.Reader, pub, key) //nolint:staticcheck // format fixed by esp_encrypted_img
	if err != nil {
		return nil, fmt.Errorf("encimg: encrypt key: %w", err)
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	sealed := gcm.Seal(nil, iv, plain, nil)
	ct, tag := sealed[:len(plain)], sealed[len(plain):]

	out := make([]byte, HeaderSize, HeaderSize+len(ct))
	binary.LittleEndian.PutUint32(out[0:4], Magic)
	copy(out[4:offIV], encKey)
	copy(out[offIV:offSize], iv)
	binary.LittleEndian.PutUint32(out[offSize:offTag], uint32(len(plain)))
	copy(out[offTag:offTag+tagSize], tag)
	return append(out, ct...), nil
}

// Decrypt reverses Encrypt. The device does the same; the server and the
// device simulator use it in tests.
func Decrypt(enc []byte, priv *rsa.PrivateKey) ([]byte, error) {
	if len(enc) < HeaderSize || binary.LittleEndian.Uint32(enc[0:4]) != Magic {
		return nil, errors.New("encimg: bad magic")
	}
	key, err := rsa.DecryptPKCS1v15(rand.Reader, priv, enc[4:offIV]) //nolint:staticcheck // format fixed by esp_encrypted_img
	if err != nil || len(key) != keySize {
		return nil, errors.New("encimg: cannot decrypt key (image is for another device)")
	}
	size := binary.LittleEndian.Uint32(enc[offSize:offTag])
	if uint64(len(enc)-HeaderSize) != uint64(size) {
		return nil, fmt.Errorf("encimg: size field %d, ciphertext %d", size, len(enc)-HeaderSize)
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	sealed := make([]byte, 0, int(size)+tagSize)
	sealed = append(sealed, enc[HeaderSize:]...)
	sealed = append(sealed, enc[offTag:offTag+tagSize]...)
	plain, err := gcm.Open(nil, enc[offIV:offSize], sealed, nil)
	if err != nil {
		return nil, errors.New("encimg: authentication failed")
	}
	return plain, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithNonceSize(block, ivSize)
}
