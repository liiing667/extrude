package pe

import (
	"encoding/binary"
)

// peOptions controls the minimal PE32+ images assembled by buildPE. The images
// are intentionally small but valid, containing a .text section, an .rdata
// section (holding the load configuration) and, optionally, a COFF symbol
// table carrying the /GS stack cookie symbol.
type peOptions struct {
	dllCharacteristics uint16
	securityCookie     bool
	guardFlags         uint32
	noSEH              bool
	safeSEHHandlers    uint64
	loadConfig         bool
}

const (
	fileAlignment    = 0x200
	sectionAlignment = 0x1000
	pe32PlusMagic    = 0x20b

	imageDllCharacteristicsDynamicBase = 0x0040
	imageDllCharacteristicsNXCompat    = 0x0100
	imageDllCharacteristicsNoSEH       = 0x0400
	imageDllCharacteristicsGuardCF     = 0x4000

	imageScnMemExecute = 0x20000000
	imageScnMemRead    = 0x40000000
	imageScnMemWrite   = 0x80000000
	imageScnCntCode    = 0x00000020
	imageScnCntInit    = 0x00000040

	imageSymClassExternal = 2
)

func buildPE(options peOptions) []byte {
	const (
		headersSize   = 0x200
		textRVA       = sectionAlignment
		rdataRVA      = sectionAlignment * 2
		textFileOff   = headersSize
		rdataFileOff  = headersSize + fileAlignment
		sectionCount  = 2
		optionalSize  = 240
		sectionTable  = 0x98 + optionalSize
		loadConfigRVA = rdataRVA
		loadConfigLen = 0xd0
	)

	image := make([]byte, rdataFileOff+fileAlignment)

	// DOS header: MZ signature and PE header offset at 0x3c.
	image[0] = 'M'
	image[1] = 'Z'
	binary.LittleEndian.PutUint32(image[0x3c:], 0x80)

	// PE signature.
	copy(image[0x80:], []byte{'P', 'E', 0, 0})

	coff := 0x84
	opt := 0x98
	binary.LittleEndian.PutUint16(image[coff+0:], 0x8664) // IMAGE_FILE_MACHINE_AMD64
	binary.LittleEndian.PutUint16(image[coff+2:], sectionCount)
	binary.LittleEndian.PutUint32(image[coff+4:], 0) // TimeDateStamp
	binary.LittleEndian.PutUint32(image[coff+16:], optionalSize)
	binary.LittleEndian.PutUint16(image[coff+18:], 0x0022) // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

	binary.LittleEndian.PutUint16(image[opt+0:], pe32PlusMagic)
	image[opt+2] = 14                                          // MajorLinkerVersion
	image[opt+3] = 0                                           // MinorLinkerVersion
	binary.LittleEndian.PutUint32(image[opt+4:], 0x200)        // SizeOfCode
	binary.LittleEndian.PutUint32(image[opt+16:], 0x1000)      // AddressOfEntryPoint
	binary.LittleEndian.PutUint32(image[opt+20:], textRVA)     // BaseOfCode
	binary.LittleEndian.PutUint64(image[opt+24:], 0x140000000) // ImageBase
	binary.LittleEndian.PutUint32(image[opt+32:], sectionAlignment)
	binary.LittleEndian.PutUint32(image[opt+36:], fileAlignment)
	binary.LittleEndian.PutUint16(image[opt+40:], 6)                          // MajorOperatingSystemVersion
	binary.LittleEndian.PutUint16(image[opt+48:], 0)                          // MajorImageVersion
	binary.LittleEndian.PutUint16(image[opt+56:], 6)                          // MajorSubsystemVersion
	binary.LittleEndian.PutUint32(image[opt+60:], sectionAlignment*3)         // SizeOfImage
	binary.LittleEndian.PutUint32(image[opt+64:], headersSize)                // SizeOfHeaders
	binary.LittleEndian.PutUint16(image[opt+68:], 3)                          // Subsystem (Windows CUI)
	binary.LittleEndian.PutUint16(image[opt+70:], options.dllCharacteristics) // DllCharacteristics
	binary.LittleEndian.PutUint32(image[opt+108:], 16)                        // NumberOfRvaAndSizes

	// Load configuration data directory (index 10).
	dataDir := opt + 112 + 10*8
	if options.loadConfig {
		binary.LittleEndian.PutUint32(image[dataDir:], loadConfigRVA)
		binary.LittleEndian.PutUint32(image[dataDir+4:], loadConfigLen)
	}

	// Section headers.
	textHeader := sectionTable
	writeSectionHeader(image[textHeader:], ".text", fileAlignment, textRVA, textFileOff,
		imageScnCntCode|imageScnMemExecute|imageScnMemRead)
	rdataHeader := sectionTable + 40
	writeSectionHeader(image[rdataHeader:], ".rdata", loadConfigLen, rdataRVA, rdataFileOff,
		imageScnCntInit|imageScnMemRead)

	// .text payload (a single int3 halt instruction).
	image[textFileOff] = 0xf4

	if options.loadConfig {
		loadConfigFileOffset := rdataFileOff + (loadConfigRVA - rdataRVA)
		loadConfig := image[loadConfigFileOffset : loadConfigFileOffset+loadConfigLen]
		binary.LittleEndian.PutUint32(loadConfig[0:], loadConfigLen) // Size
		if options.securityCookie {
			binary.LittleEndian.PutUint64(loadConfig[0x58:], 0x140002000) // SecurityCookie VA
		}
		if options.noSEH {
			binary.LittleEndian.PutUint64(loadConfig[0x60:], 0) // SEHandlerTable
			binary.LittleEndian.PutUint64(loadConfig[0x68:], 0) // SEHandlerCount
		} else if options.safeSEHHandlers > 0 {
			binary.LittleEndian.PutUint64(loadConfig[0x60:], 0x140002100)
			binary.LittleEndian.PutUint64(loadConfig[0x68:], options.safeSEHHandlers)
		}
		if options.guardFlags != 0 {
			binary.LittleEndian.PutUint32(loadConfig[0x88:], options.guardFlags)
		}
	}

	if options.securityCookie {
		// A COFF symbol table with "__security_cookie", followed by a string
		// table holding the long symbol name.
		name := "__security_cookie"
		symbolOffset := uint32(len(image))
		image = append(image, make([]byte, 18)...)
		symbol := image[symbolOffset : symbolOffset+18]
		binary.LittleEndian.PutUint32(symbol[0:], 0)  // name lives in the string table
		binary.LittleEndian.PutUint32(symbol[4:], 4)  // string table offset
		binary.LittleEndian.PutUint16(symbol[12:], 1) // SectionNumber (.text)
		symbol[16] = imageSymClassExternal

		binary.LittleEndian.PutUint32(image[coff+8:], symbolOffset) // PointerToSymbolTable
		binary.LittleEndian.PutUint32(image[coff+12:], 1)           // NumberOfSymbols

		stringTableOffset := symbolOffset + 18
		stringTableSize := uint32(4 + len(name) + 1)
		image = append(image, make([]byte, stringTableSize)...)
		binary.LittleEndian.PutUint32(image[stringTableOffset:], stringTableSize)
		copy(image[stringTableOffset+4:], name)
		image[stringTableOffset+4+uint32(len(name))] = 0
	}

	return image
}

func writeSectionHeader(buffer []byte, name string, virtualSize, virtualAddress, rawOffset uint32, characteristics uint32) {
	copy(buffer[0:8], name)
	binary.LittleEndian.PutUint32(buffer[8:], virtualSize)
	binary.LittleEndian.PutUint32(buffer[12:], virtualAddress)
	binary.LittleEndian.PutUint32(buffer[16:], fileAlignment) // SizeOfRawData
	binary.LittleEndian.PutUint32(buffer[20:], rawOffset)
	binary.LittleEndian.PutUint32(buffer[36:], characteristics)
}
