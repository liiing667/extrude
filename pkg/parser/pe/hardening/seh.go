package hardening

import (
	"debug/pe"
	"fmt"
)

func checkSEH(f *pe.File, config *loadConfig) Check {
	characteristics := dllCharacteristics(f)
	if characteristics&pe.IMAGE_DLLCHARACTERISTICS_NO_SEH != 0 {
		return Check{
			Enabled:  true,
			Evidence: fmt.Sprintf("DllCharacteristics bit 0x%04x (NO_SEH) is set, so the image contains no structured exception handlers", pe.IMAGE_DLLCHARACTERISTICS_NO_SEH),
		}
	}

	// On 32-bit images SafeSEH is expressed through a registered exception
	// handler table in the load configuration.
	if _, is32bit := f.OptionalHeader.(*pe.OptionalHeader32); is32bit {
		if config != nil && config.seHandlerTable != nil && *config.seHandlerTable != 0 &&
			config.seHandlerCount != nil && *config.seHandlerCount > 0 {
			return Check{
				Enabled:  true,
				Evidence: fmt.Sprintf("load configuration lists %d SafeSEH exception handler(s) via SEHandlerTable", *config.seHandlerCount),
			}
		}
		return Check{
			Enabled:  false,
			Evidence: "DllCharacteristics NO_SEH is not set and the load configuration has no SafeSEH handler table",
		}
	}

	return Check{
		Enabled:  false,
		Evidence: fmt.Sprintf("DllCharacteristics bit 0x%04x (NO_SEH) is not set, so exception handlers remain available without SafeSEH protection", pe.IMAGE_DLLCHARACTERISTICS_NO_SEH),
	}
}
