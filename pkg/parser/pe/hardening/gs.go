package hardening

import "debug/pe"

const securityCookieSymbol = "__security_cookie"

func checkGS(f *pe.File, config *loadConfig) Check {
	for _, symbol := range f.Symbols {
		if symbol.Name == securityCookieSymbol {
			return Check{
				Enabled:  true,
				Evidence: "COFF symbol table contains the \"" + securityCookieSymbol + "\" stack cookie symbol",
			}
		}
	}

	if config != nil && config.securityCookie != nil && *config.securityCookie != 0 {
		return Check{
			Enabled:  true,
			Evidence: "load configuration directory references a non-zero SecurityCookie virtual address",
		}
	}

	switch {
	case len(f.Symbols) > 0:
		return Check{
			Enabled:  false,
			Evidence: "no \"" + securityCookieSymbol + "\" symbol is present in the COFF symbol table and the load configuration has no SecurityCookie",
		}
	case config != nil:
		return Check{
			Enabled:  false,
			Evidence: "the COFF symbol table is stripped and the load configuration has no SecurityCookie",
		}
	default:
		return Check{
			Enabled:  false,
			Evidence: "no COFF symbol table and no load configuration directory were found",
		}
	}
}
