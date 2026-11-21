// Package espsig signs ESP-IDF app and bootloader images with the Secure Boot V2
// RSA-3072 signature block, byte-compatible with
// `espsecure.py sign_data --version 2`.
//
// The ESP32 (ECO3) accepts a single signature block. On L0 the device runs
// "signed apps without hardware secure boot": an OTA image is verified against
// the public key embedded in the signature block of the running app.
//
// Signed image layout:
//
//	contents (padded with 0xFF to a 4 KB boundary) | signature sector (4 KB)
//
// Signature sector: one 1216-byte block, then 0xFF up to 4096 bytes. Block:
//
//	u8  magic 0xE7 | u8 version 0x02 | 2 zero bytes
//	32  SHA-256 of contents
//	384 RSA modulus n, little-endian
//	u32 public exponent e
//	384 rinv = 2^(2*3072) mod n, little-endian
//	u32 mdash = -n^-1 mod 2^32
//	384 RSA-PSS signature (SHA-256, salt 32), little-endian
//	u32 CRC32 of the 1196 bytes above
//	16  zero bytes
package espsig

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"math/big"
)

const (
	SectorSize   = 4096
	BlockSize    = 1216
	KeyBits      = 3072
	keyBytes     = KeyBits / 8
	blockMagic   = 0xE7
	blockVersion = 0x02
	crcOffset    = 1196
	saltLength   = 32
)

var (
	ErrNotSigned  = errors.New("espsig: image has no valid signature block")
	ErrBadKeySize = errors.New("espsig: RSA key must be 3072 bits")
)

// Sign pads image to a 4 KB boundary and appends a signature sector.
// The input must be an unsigned image (see HasSignature).
func Sign(image []byte, key *rsa.PrivateKey) ([]byte, error) {
	if key.N.BitLen() != KeyBits {
		return nil, ErrBadKeySize
	}
	contents := pad(image)
	digest := sha256.Sum256(contents)
	sig, err := rsa.SignPSS(rand.Reader, key, crypto.SHA256, digest[:],
		&rsa.PSSOptions{SaltLength: saltLength, Hash: crypto.SHA256})
	if err != nil {
		return nil, fmt.Errorf("espsig: sign: %w", err)
	}
	block, err := buildBlock(digest[:], &key.PublicKey, sig)
	if err != nil {
		return nil, err
	}
	sector := bytes.Repeat([]byte{0xFF}, SectorSize)
	copy(sector, block)

	out := make([]byte, 0, len(contents)+SectorSize)
	out = append(out, contents...)
	return append(out, sector...), nil
}

// Verify checks the signature sector of a signed image against pub and
// returns the signed contents (without the signature sector).
func Verify(signed []byte, pub *rsa.PublicKey) ([]byte, error) {
	contents, block, err := split(signed)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(contents)
	if subtle.ConstantTimeCompare(digest[:], block[4:36]) != 1 {
		return nil, errors.New("espsig: image digest mismatch")
	}
	n := new(big.Int).SetBytes(reverse(block[36 : 36+keyBytes]))
	if n.Cmp(pub.N) != 0 || int(binary.LittleEndian.Uint32(block[420:424])) != pub.E {
		return nil, errors.New("espsig: image signed with a different key")
	}
	sig := reverse(block[812 : 812+keyBytes])
	if err := rsa.VerifyPSS(pub, crypto.SHA256, digest[:], sig,
		&rsa.PSSOptions{SaltLength: saltLength, Hash: crypto.SHA256}); err != nil {
		return nil, fmt.Errorf("espsig: bad signature: %w", err)
	}
	return contents, nil
}

// PublicKey returns the public key embedded in the image's signature block.
func PublicKey(signed []byte) (*rsa.PublicKey, error) {
	_, block, err := split(signed)
	if err != nil {
		return nil, err
	}
	n := new(big.Int).SetBytes(reverse(block[36 : 36+keyBytes]))
	e := int(binary.LittleEndian.Uint32(block[420:424]))
	return &rsa.PublicKey{N: n, E: e}, nil
}

// HasSignature reports whether the image already ends with a structurally
// valid signature sector (magic, version and CRC). It does not verify the
// signature itself.
func HasSignature(image []byte) bool {
	_, _, err := split(image)
	return err == nil
}

func split(signed []byte) (contents, block []byte, err error) {
	if len(signed) < 2*SectorSize || len(signed)%SectorSize != 0 {
		return nil, nil, ErrNotSigned
	}
	contents = signed[:len(signed)-SectorSize]
	block = signed[len(contents) : len(contents)+BlockSize]
	if block[0] != blockMagic || block[1] != blockVersion {
		return nil, nil, ErrNotSigned
	}
	if crc32.ChecksumIEEE(block[:crcOffset]) != binary.LittleEndian.Uint32(block[crcOffset:crcOffset+4]) {
		return nil, nil, ErrNotSigned
	}
	return contents, block, nil
}

func buildBlock(digest []byte, pub *rsa.PublicKey, sig []byte) ([]byte, error) {
	if len(sig) != keyBytes {
		return nil, fmt.Errorf("espsig: signature is %d bytes, want %d", len(sig), keyBytes)
	}
	r := new(big.Int).Lsh(big.NewInt(1), 2*KeyBits)
	rinv := new(big.Int).Mod(r, pub.N)

	two32 := new(big.Int).Lsh(big.NewInt(1), 32)
	ninv := new(big.Int).ModInverse(new(big.Int).Mod(pub.N, two32), two32)
	if ninv == nil {
		return nil, errors.New("espsig: modulus is not invertible mod 2^32")
	}
	mdash := new(big.Int).Sub(two32, ninv) // -n^-1 mod 2^32
	mdash.Mod(mdash, two32)

	b := make([]byte, 0, BlockSize)
	b = append(b, blockMagic, blockVersion, 0, 0)
	b = append(b, digest...)
	b = append(b, leBytes(pub.N, keyBytes)...)
	b = binary.LittleEndian.AppendUint32(b, uint32(pub.E))
	b = append(b, leBytes(rinv, keyBytes)...)
	b = binary.LittleEndian.AppendUint32(b, uint32(mdash.Uint64()))
	b = append(b, reverse(sig)...)
	b = binary.LittleEndian.AppendUint32(b, crc32.ChecksumIEEE(b))
	b = append(b, make([]byte, 16)...)
	if len(b) != BlockSize {
		return nil, fmt.Errorf("espsig: block is %d bytes", len(b))
	}
	return b, nil
}

func pad(image []byte) []byte {
	out := make([]byte, len(image), len(image)+SectorSize)
	copy(out, image)
	if rem := len(out) % SectorSize; rem != 0 {
		out = append(out, bytes.Repeat([]byte{0xFF}, SectorSize-rem)...)
	}
	return out
}

// leBytes returns x as a little-endian byte slice of exactly size bytes.
func leBytes(x *big.Int, size int) []byte {
	return reverse(x.FillBytes(make([]byte, size)))
}

func reverse(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[len(b)-1-i] = b[i]
	}
	return out
}
