package pe

import (
	"debug/pe"

	"github.com/liamg/extrude/pkg/parser/pe/hardening"
	"github.com/liamg/extrude/pkg/report"
)

func (m *Metadata) CreateReport() (report.Report, error) {
	rep := report.New()

	overview := report.NewSection("Overview")
	overview.AddKeyValue("File", m.File.Path)
	overview.AddKeyValue("Format", m.File.Format.String())
	overview.AddKeyValue("Architecture", machineName(m.pe.Machine))
	overview.AddKeyValue("Class", m.optionalHeaderClass())
	overview.AddKeyValue("Subsystem", subsystemName(m.subsystem()))
	overview.AddKeyValue("Type", m.imageType())
	rep.AddSection(overview)

	security := report.NewSection("Security Features")

	security.AddTest(
		"Address Space Layout Randomization",
		boolToResult(m.Hardening.AddressSpaceLayoutRandomization.Enabled),
		`ASLR loads the image and its dependencies at random virtual memory addresses, making return oriented programming (ROP) and other memory corruption attacks significantly less reliable. `+
			evidence(m.Hardening.AddressSpaceLayoutRandomization),
	)

	security.AddTest(
		"Data Execution Prevention",
		boolToResult(m.Hardening.DataExecutionPrevention.Enabled),
		`DEP marks data pages such as the stack and heap as non-executable, preventing injected shellcode from being run directly from writable memory. `+
			evidence(m.Hardening.DataExecutionPrevention),
	)

	security.AddTest(
		"Control Flow Guard",
		boolToResult(m.Hardening.ControlFlowGuard.Enabled),
		`CFG restricts indirect calls to valid function targets identified at compile time, preventing an attacker from redirecting execution through hijacked function pointers. `+
			evidence(m.Hardening.ControlFlowGuard),
	)

	security.AddTest(
		"Stack Buffer Overrun Detection",
		boolToResult(m.Hardening.StackBufferOverrunDetection.Enabled),
		`Compiled with /GS, a "canary" value is stored between local variables and the return address; the program aborts when the canary is overwritten, which catches most stack based buffer overflows. `+
			evidence(m.Hardening.StackBufferOverrunDetection),
	)

	security.AddTest(
		"Structured Exception Handler Protection",
		boolToResult(m.Hardening.StructuredExceptionHandlerProtection.Enabled),
		`SafeSEH validates structured exception handlers before they are invoked, and the NO_SEH characteristic removes exception handlers entirely. This stops exception handler overwrites being used to hijack control flow. `+
			evidence(m.Hardening.StructuredExceptionHandlerProtection),
	)

	rep.AddSection(security)

	return rep, nil
}

func evidence(check hardening.Check) string {
	return "Evidence: " + check.Evidence + "."
}

func boolToResult(in bool) report.Result {
	if in {
		return report.Pass
	}
	return report.Fail
}

func (m *Metadata) optionalHeaderClass() string {
	switch m.pe.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		return "64-bit"
	case *pe.OptionalHeader32:
		return "32-bit"
	default:
		return "unknown"
	}
}

func (m *Metadata) subsystem() uint16 {
	switch header := m.pe.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		return header.Subsystem
	case *pe.OptionalHeader32:
		return header.Subsystem
	default:
		return 0
	}
}

func subsystemName(subsystem uint16) string {
	switch subsystem {
	case pe.IMAGE_SUBSYSTEM_NATIVE:
		return "Native"
	case pe.IMAGE_SUBSYSTEM_WINDOWS_GUI:
		return "Windows GUI"
	case pe.IMAGE_SUBSYSTEM_WINDOWS_CUI:
		return "Windows CUI"
	case pe.IMAGE_SUBSYSTEM_OS2_CUI:
		return "OS/2 CUI"
	case pe.IMAGE_SUBSYSTEM_POSIX_CUI:
		return "POSIX CUI"
	case pe.IMAGE_SUBSYSTEM_NATIVE_WINDOWS:
		return "Native Windows"
	case pe.IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:
		return "Windows CE GUI"
	case pe.IMAGE_SUBSYSTEM_EFI_APPLICATION:
		return "EFI Application"
	case pe.IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
		return "EFI Boot Service Driver"
	case pe.IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
		return "EFI Runtime Driver"
	case pe.IMAGE_SUBSYSTEM_EFI_ROM:
		return "EFI ROM"
	case pe.IMAGE_SUBSYSTEM_XBOX:
		return "Xbox"
	case pe.IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION:
		return "Windows Boot Application"
	default:
		return "Unknown"
	}
}

func machineName(machine uint16) string {
	switch machine {
	case pe.IMAGE_FILE_MACHINE_I386:
		return "i386"
	case pe.IMAGE_FILE_MACHINE_AMD64:
		return "AMD64"
	case pe.IMAGE_FILE_MACHINE_ARM:
		return "ARM"
	case pe.IMAGE_FILE_MACHINE_ARMNT:
		return "ARM Thumb-2"
	case pe.IMAGE_FILE_MACHINE_ARM64:
		return "ARM64"
	case pe.IMAGE_FILE_MACHINE_IA64:
		return "IA-64"
	case pe.IMAGE_FILE_MACHINE_RISCV32:
		return "RISC-V 32"
	case pe.IMAGE_FILE_MACHINE_RISCV64:
		return "RISC-V 64"
	case pe.IMAGE_FILE_MACHINE_RISCV128:
		return "RISC-V 128"
	case pe.IMAGE_FILE_MACHINE_UNKNOWN:
		return "Unknown"
	default:
		return "Unknown"
	}
}

func (m *Metadata) imageType() string {
	if m.pe.Characteristics&pe.IMAGE_FILE_DLL != 0 {
		return "DLL"
	}
	return "Executable"
}
