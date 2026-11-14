package hardening

import (
	"debug/pe"
	"io"
)

// Check describes the state of a single hardening feature and the evidence
// that was used to derive that state.
type Check struct {
	Enabled  bool
	Evidence string
}

type Attributes struct {
	// AddressSpaceLayoutRandomization reflects the IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
	// (ASLR) flag in the optional header.
	AddressSpaceLayoutRandomization Check
	// DataExecutionPrevention reflects the IMAGE_DLLCHARACTERISTICS_NX_COMPAT
	// (DEP) flag in the optional header.
	DataExecutionPrevention Check
	// ControlFlowGuard reflects the IMAGE_DLLCHARACTERISTICS_GUARD_CF flag and
	// the associated load configuration.
	ControlFlowGuard Check
	// StackBufferOverrunDetection reflects the /GS stack cookie emitted by the
	// compiler.
	StackBufferOverrunDetection Check
	// StructuredExceptionHandlerProtection reflects SafeSEH (32-bit) or the
	// absence of IMAGE_DLLCHARACTERISTICS_NO_SEH.
	StructuredExceptionHandlerProtection Check
}

// IdentifyAttributes inspects the PE file and derives the state of each
// supported hardening feature. The reader is used to access data outside of
// the headers (e.g. the load configuration directory).
func IdentifyAttributes(f *pe.File, r io.ReaderAt) Attributes {
	config := readLoadConfig(f, r)
	return Attributes{
		AddressSpaceLayoutRandomization:      checkASLR(f),
		DataExecutionPrevention:              checkDEP(f),
		ControlFlowGuard:                     checkCFG(f, config),
		StackBufferOverrunDetection:          checkGS(f, config),
		StructuredExceptionHandlerProtection: checkSEH(f, config),
	}
}

func dllCharacteristics(f *pe.File) uint16 {
	switch header := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		return header.DllCharacteristics
	case *pe.OptionalHeader64:
		return header.DllCharacteristics
	default:
		return 0
	}
}
