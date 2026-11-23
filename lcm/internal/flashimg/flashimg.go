// Package flashimg reads a merged ESP32 flash image written at 0x0 (the
// bootstrap image made by ZIR_3M/bootstrap/merged_image.py): bootloader at
// 0x1000, partition table at 0x8000 and the app in ota_0.
package flashimg

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"zir/lcm/internal/crypto/appdesc"
)

const (
	BootloaderOffset = 0x1000
	PartTableOffset  = 0x8000
	partEntrySize    = 32
	partMagic        = 0x50AA // bytes AA 50
	partMD5Magic     = 0xEBEB
	maxPartEntries   = 95 // 0xC00 bytes of table
	imageMagic       = 0xE9

	TypeApp       = 0x00
	SubtypeFactor = 0x00
	SubtypeOTA0   = 0x10
)

type Partition struct {
	Label   string
	Type    byte
	Subtype byte
	Offset  uint32
	Size    uint32
}

type Info struct {
	FlashSize  string // from the bootloader header: "4MB"
	FlashMode  string
	Partitions []Partition
	App        Partition // ota_0 (or factory) the image boots
	Desc       appdesc.Desc
}

var flashSizes = map[byte]string{0: "1MB", 1: "2MB", 2: "4MB", 3: "8MB", 4: "16MB"}
var flashModes = map[byte]string{0: "QIO", 1: "QOUT", 2: "DIO", 3: "DOUT"}

// Parse checks the layout of an image meant to be written at 0x0.
func Parse(img []byte) (Info, error) {
	var in Info
	if len(img) < PartTableOffset+partEntrySize {
		return in, errors.New("образ закороткий: це не об'єднаний образ з адреси 0x0")
	}
	bl := img[BootloaderOffset:]
	if bl[0] != imageMagic {
		if img[0] == imageMagic {
			return in, errors.New("це образ застосунку, а не об'єднаний образ з адреси 0x0 (zir3m-bootstrap-<версія>.bin)")
		}
		return in, errors.New("за адресою 0x1000 немає завантажувача: це не об'єднаний образ з адреси 0x0")
	}
	if chip := binary.LittleEndian.Uint16(bl[12:14]); chip != 0 {
		return in, fmt.Errorf("завантажувач не для ESP32 (chip_id %d)", chip)
	}
	in.FlashMode = flashModes[bl[2]]
	in.FlashSize = flashSizes[bl[3]>>4]
	if in.FlashSize == "" {
		in.FlashSize = fmt.Sprintf("код %d", bl[3]>>4)
	}

	for i := 0; i < maxPartEntries; i++ {
		off := PartTableOffset + i*partEntrySize
		if off+partEntrySize > len(img) {
			break
		}
		e := img[off : off+partEntrySize]
		m := binary.LittleEndian.Uint16(e[0:2])
		if m == partMD5Magic || m == 0xFFFF {
			break
		}
		if m != partMagic {
			return in, fmt.Errorf("пошкоджена таблиця розділів (запис %d)", i)
		}
		label := e[12:28]
		if j := bytes.IndexByte(label, 0); j >= 0 {
			label = label[:j]
		}
		in.Partitions = append(in.Partitions, Partition{Label: string(label), Type: e[2], Subtype: e[3],
			Offset: binary.LittleEndian.Uint32(e[4:8]), Size: binary.LittleEndian.Uint32(e[8:12])})
	}
	if len(in.Partitions) == 0 {
		return in, errors.New("за адресою 0x8000 немає таблиці розділів")
	}
	found := false
	for _, p := range in.Partitions {
		if p.Type == TypeApp && p.Subtype == SubtypeOTA0 {
			in.App, found = p, true
			break
		}
	}
	if !found {
		for _, p := range in.Partitions {
			if p.Type == TypeApp && p.Subtype == SubtypeFactor {
				in.App, found = p, true
			}
		}
	}
	if !found {
		return in, errors.New("у таблиці розділів немає ota_0")
	}
	if int(in.App.Offset) >= len(img) {
		return in, fmt.Errorf("в образі немає застосунку в %s (0x%x)", in.App.Label, in.App.Offset)
	}
	if uint64(len(img)) > uint64(in.App.Offset)+uint64(in.App.Size) {
		return in, fmt.Errorf("образ довший за кінець розділу %s: він зачепить розділи після нього", in.App.Label)
	}
	d, err := appdesc.Parse(img[in.App.Offset:])
	if err != nil {
		return in, fmt.Errorf("застосунок у %s: %v", in.App.Label, err)
	}
	if d.ChipID != 0 {
		return in, fmt.Errorf("застосунок не для ESP32 (chip_id %d)", d.ChipID)
	}
	in.Desc = d
	return in, nil
}

// Build makes a minimal merged image for tests: bootloader stub, a partition
// table like ZIR_3M/partitions.csv and an app in ota_0 with extra bytes
// (embedded keys) at its end.
func Build(project, version string, extra []byte) []byte {
	const ota0 = 0x10000
	img := bytes.Repeat([]byte{0xFF}, ota0)
	bl := img[BootloaderOffset:]
	bl[0], bl[1], bl[2], bl[3] = imageMagic, 1, 2, 0x20
	clear(bl[4:24])
	parts := []Partition{{"nvs", 1, 2, 0x9000, 0x5000}, {"otadata", 1, 0, 0xe000, 0x2000},
		{"ota_0", 0, 0x10, ota0, 0x180000}, {"ota_1", 0, 0x11, 0x190000, 0x180000}}
	for i, p := range parts {
		e := img[PartTableOffset+i*partEntrySize:]
		binary.LittleEndian.PutUint16(e[0:], partMagic)
		e[2], e[3] = p.Type, p.Subtype
		binary.LittleEndian.PutUint32(e[4:], p.Offset)
		binary.LittleEndian.PutUint32(e[8:], p.Size)
		copy(e[12:28], append([]byte(p.Label), make([]byte, 16-len(p.Label))...))
		clear(e[28:32])
	}
	app := appdesc.Build(version, "", 0, 0, nil)
	copy(app[32+48:32+80], append([]byte(project), make([]byte, 32-len(project))...))
	app = append(app, bytes.Repeat([]byte{0x5A}, 4096)...)
	return append(append(img, app...), extra...)
}
