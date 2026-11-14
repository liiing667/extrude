package hardening

import (
	"debug/pe"
	"fmt"
)

func checkASLR(f *pe.File) Check {
	characteristics := dllCharacteristics(f)
	if characteristics&pe.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE != 0 {
		return Check{
			Enabled:  true,
			Evidence: fmt.Sprintf("DllCharacteristics bit 0x%04x (DYNAMIC_BASE) is set in the optional header", pe.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE),
		}
	}
	return Check{
		Enabled:  false,
		Evidence: fmt.Sprintf("DllCharacteristics bit 0x%04x (DYNAMIC_BASE) is not set in the optional header", pe.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE),
	}
}
