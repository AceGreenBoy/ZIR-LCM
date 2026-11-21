// Package appdesc reads the ESP-IDF application description (esp_app_desc_t)
// and the ZIR custom description (zir_custom_desc_t, FIRMWARE_REQUIREMENTS 6.4)
// from an app image, and computes the "comparable hash" used to tell whether
// a profile's code changed between builds.
package appdesc

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	imageMagic   = 0xE9
	imageHdrSize = 24
	segHdrSize   = 8
	descOffset   = imageHdrSize + segHdrSize // esp_app_desc_t starts the first (DROM) segment
	descSize     = 256
	descMagic    = 0xABCD5432
	zirOffset    = descOffset + descSize // .rodata_custom_desc follows .rodata_desc
	zirSize      = 128
	ZirMagic     = 0x5A495244 // 'ZIRD'

	FlagDevBuild = 1 << 0
)

// esp_app_desc_t field offsets (relative to the description).
const (
	offVersion  = 16
	offProject  = 48
	offTime     = 80
	offDate     = 96
	offIDF      = 112
	offElfSHA   = 144
	lenVersion  = 32
	lenProject  = 32
	lenTime     = 16
	lenDate     = 16
	lenIDF      = 32
	lenElfSHA   = 32
	zOffMagic   = 0
	zOffDescVer = 4
	zOffWwwAPI  = 6
	zOffProfile = 8
	zOffVersion = 40
	zOffFlags   = 72
)

type Desc struct {
	Version      string
	Project      string
	Time         string
	Date         string
	IDF          string
	ElfSHA256    []byte
	ChipID       uint16
	HashAppended bool

	HasZir     bool
	ZirDescVer uint16
	WwwAPI     uint16
	Profile    string
	ZirVersion string
	Flags      uint32
}

func (d Desc) DevBuild() bool { return d.Flags&FlagDevBuild != 0 }

// Parse reads the descriptions from an unsigned or signed app image.
func Parse(img []byte) (Desc, error) {
	var d Desc
	if len(img) < zirOffset+zirSize || img[0] != imageMagic {
		return d, errors.New("appdesc: not an ESP app image")
	}
	d.ChipID = binary.LittleEndian.Uint16(img[12:14])
	d.HashAppended = img[23] == 1
	desc := img[descOffset : descOffset+descSize]
	if binary.LittleEndian.Uint32(desc[0:4]) != descMagic {
		return d, errors.New("appdesc: esp_app_desc_t not found (bootloader or not an app?)")
	}
	d.Version = cstr(desc[offVersion : offVersion+lenVersion])
	d.Project = cstr(desc[offProject : offProject+lenProject])
	d.Time = cstr(desc[offTime : offTime+lenTime])
	d.Date = cstr(desc[offDate : offDate+lenDate])
	d.IDF = cstr(desc[offIDF : offIDF+lenIDF])
	d.ElfSHA256 = bytes.Clone(desc[offElfSHA : offElfSHA+lenElfSHA])

	z := img[zirOffset : zirOffset+zirSize]
	if binary.LittleEndian.Uint32(z[zOffMagic:]) == ZirMagic {
		d.HasZir = true
		d.ZirDescVer = binary.LittleEndian.Uint16(z[zOffDescVer:])
		d.WwwAPI = binary.LittleEndian.Uint16(z[zOffWwwAPI:])
		d.Profile = cstr(z[zOffProfile : zOffProfile+32])
		d.ZirVersion = cstr(z[zOffVersion : zOffVersion+32])
		d.Flags = binary.LittleEndian.Uint32(z[zOffFlags:])
	}
	return d, nil
}

// ComparableHash hashes an unsigned image with everything that changes on a
// rebuild of the same code blanked out: version, build time and date, ELF
// hash, the ZIR version string, the image checksum byte and the appended
// SHA-256. Requires CONFIG_APP_REPRODUCIBLE_BUILD in the firmware.
func ComparableHash(img []byte) ([32]byte, error) {
	d, err := Parse(img)
	if err != nil {
		return [32]byte{}, err
	}
	b := bytes.Clone(img)
	zero := func(off, n int) { clear(b[off : off+n]) }
	zero(descOffset+offVersion, lenVersion)
	zero(descOffset+offTime, lenTime)
	zero(descOffset+offDate, lenDate)
	zero(descOffset+offElfSHA, lenElfSHA)
	if d.HasZir {
		zero(zirOffset+zOffVersion, 32)
	}
	end := len(b)
	if d.HashAppended {
		end -= 32
	}
	if end < 1 {
		return [32]byte{}, errors.New("appdesc: image too short")
	}
	end-- // checksum byte
	return sha256.Sum256(b[:end]), nil
}

func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

// Build creates a minimal fake app image for tests and the device simulator.
func Build(version, profile string, wwwAPI uint16, flags uint32, body []byte) []byte {
	img := make([]byte, zirOffset+zirSize)
	img[0] = imageMagic
	img[1] = 1
	img[23] = 1
	binary.LittleEndian.PutUint32(img[imageHdrSize+4:], uint32(descSize+zirSize+len(body)))
	desc := img[descOffset:]
	binary.LittleEndian.PutUint32(desc[0:], descMagic)
	copy(desc[offVersion:offVersion+lenVersion], version)
	copy(desc[offProject:offProject+lenProject], "ZIR_3M")
	copy(desc[offTime:offTime+lenTime], "12:00:00")
	copy(desc[offDate:offDate+lenDate], "Nov  8 2026")
	copy(desc[offIDF:offIDF+lenIDF], "v6.0.1")
	z := img[zirOffset:]
	binary.LittleEndian.PutUint32(z[zOffMagic:], ZirMagic)
	binary.LittleEndian.PutUint16(z[zOffDescVer:], 1)
	binary.LittleEndian.PutUint16(z[zOffWwwAPI:], wwwAPI)
	copy(z[zOffProfile:zOffProfile+32], profile)
	copy(z[zOffVersion:zOffVersion+32], version)
	binary.LittleEndian.PutUint32(z[zOffFlags:], flags)
	img = append(img, body...)
	img = append(img, 0xAA) // checksum
	h := sha256.Sum256(img) // simple hash
	return append(img, h[:]...)
}

func (d Desc) String() string {
	return fmt.Sprintf("%s %s profile=%q www_api=%d flags=%#x", d.Project, d.Version, d.Profile, d.WwwAPI, d.Flags)
}
