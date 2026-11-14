package hardening

import (
	"debug/pe"
	"fmt"
)

func checkDEP(f *pe.File) Check {
	characteristics := dllCharacteristics(f)
	if characteristics&pe.IMAGE_DLLCHARACTERISTICS_NX_COMPAT != 0 {
		return Check{
			Enabled:  true,
			Evidence: fmt.Sprintf("DllCharacteristics bit 0x%04x (NX_COMPAT) is set in the optional header", pe.IMAGE_DLLCHARACTERISTICS_NX_COMPAT),
		}
	}
	return Check{
		Enabled:  false,
		Evidence: fmt.Sprintf("DllCharacteristics bit 0x%04x (NX_COMPAT) is not set in the optional header", pe.IMAGE_DLLCHARACTERISTICS_NX_COMPAT),
	}
}
