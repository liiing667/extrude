package hardening

import (
	"debug/pe"
	"fmt"
)

func checkCFG(f *pe.File, config *loadConfig) Check {
	characteristics := dllCharacteristics(f)
	flagSet := characteristics&pe.IMAGE_DLLCHARACTERISTICS_GUARD_CF != 0

	switch {
	case flagSet && config != nil && config.guardFlags != nil:
		return Check{
			Enabled:  true,
			Evidence: fmt.Sprintf("DllCharacteristics bit 0x%04x (GUARD_CF) is set and the load configuration GuardFlags field is 0x%08x", pe.IMAGE_DLLCHARACTERISTICS_GUARD_CF, *config.guardFlags),
		}
	case flagSet:
		return Check{
			Enabled:  true,
			Evidence: fmt.Sprintf("DllCharacteristics bit 0x%04x (GUARD_CF) is set, but no load configuration GuardFlags field is present", pe.IMAGE_DLLCHARACTERISTICS_GUARD_CF),
		}
	default:
		return Check{
			Enabled:  false,
			Evidence: fmt.Sprintf("DllCharacteristics bit 0x%04x (GUARD_CF) is not set in the optional header", pe.IMAGE_DLLCHARACTERISTICS_GUARD_CF),
		}
	}
}
