package hardening

import (
	"debug/pe"
	"encoding/binary"
	"io"
)

// loadConfig captures the fields of IMAGE_LOAD_CONFIG_DIRECTORY that are
// relevant to hardening checks. A nil pointer means the field is not present
// (either the directory is missing, or it is too small to contain the field).
type loadConfig struct {
	securityCookie *uint64
	seHandlerTable *uint64
	seHandlerCount *uint64
	guardFlags     *uint32
	actualSize     uint32
	directorySize  uint32
}

// rvaToOffset converts a relative virtual address to a file offset using the
// section table. It returns false when the address does not fall within any
// section.
func rvaToOffset(f *pe.File, rva uint32) (uint32, bool) {
	for _, section := range f.Sections {
		base := section.VirtualAddress
		end := base + maxUint32(section.VirtualSize, section.Size)
		if rva >= base && rva < end {
			return rva - base + section.Offset, true
		}
	}
	return 0, false
}

func maxUint32(a, b uint32) uint32 {
	if a > b {
		return a
	}
	return b
}

func readLoadConfig(f *pe.File, r io.ReaderAt) *loadConfig {
	var directory pe.DataDirectory
	switch header := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		if int(pe.IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG) >= len(header.DataDirectory) {
			return nil
		}
		directory = header.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG]
	case *pe.OptionalHeader64:
		if int(pe.IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG) >= len(header.DataDirectory) {
			return nil
		}
		directory = header.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG]
	default:
		return nil
	}

	if directory.VirtualAddress == 0 || directory.Size == 0 {
		return nil
	}

	offset, ok := rvaToOffset(f, directory.VirtualAddress)
	if !ok {
		return nil
	}

	// The first field of IMAGE_LOAD_CONFIG_DIRECTORY is its own size, which
	// allows parsers to cope with entries from newer toolchain versions.
	header := make([]byte, 4)
	if _, err := r.ReadAt(header, int64(offset)); err != nil {
		return nil
	}
	actualSize := binary.LittleEndian.Uint32(header)

	readSize := directory.Size
	if actualSize != 0 && actualSize < readSize {
		readSize = actualSize
	}

	data := make([]byte, readSize)
	if _, err := r.ReadAt(data, int64(offset)); err != nil {
		return nil
	}

	config := &loadConfig{
		actualSize:    actualSize,
		directorySize: directory.Size,
	}

	is64bit := false
	switch f.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		is64bit = true
	}

	// Field offsets within IMAGE_LOAD_CONFIG_DIRECTORY. The pointer-sized fields
	// use 4 byte slots in PE32 and 8 byte slots in PE32+.
	var cookieOffset, seTableOffset, seCountOffset, guardFlagsOffset uint32
	if is64bit {
		cookieOffset = 0x58
		seTableOffset = 0x60
		seCountOffset = 0x68
		guardFlagsOffset = 0x88
	} else {
		cookieOffset = 0x3c
		seTableOffset = 0x40
		seCountOffset = 0x44
		guardFlagsOffset = 0x58
	}

	config.securityCookie = readPointerField(data, cookieOffset, is64bit)
	config.seHandlerTable = readPointerField(data, seTableOffset, is64bit)
	config.seHandlerCount = readPointerField(data, seCountOffset, is64bit)
	if guardFlagsOffset+4 <= uint32(len(data)) {
		value := binary.LittleEndian.Uint32(data[guardFlagsOffset:])
		config.guardFlags = &value
	}

	return config
}

func readPointerField(data []byte, offset uint32, is64bit bool) *uint64 {
	if is64bit {
		if offset+8 > uint32(len(data)) {
			return nil
		}
		value := binary.LittleEndian.Uint64(data[offset:])
		return &value
	}
	if offset+4 > uint32(len(data)) {
		return nil
	}
	value := uint64(binary.LittleEndian.Uint32(data[offset:]))
	return &value
}
