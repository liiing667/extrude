# extrude

Analyse binaries for missing security features, information disclosure and more.

Extrude is in the early stages of development, and currently supports ELF, MachO and PE/COFF binaries.

![Screenshot](screenshot.png)

## Usage

```
Usage:
  extrude [flags] [file]

Flags:
  -a, --all               Show details of all tests, not just those which failed.
  -w, --fail-on-warning   Exit with a non-zero status even if only warnings are discovered.
  -h, --help              help for extrude

```

## Docker

You can optionally run extrude with docker via:

```
docker run -v `pwd`:/blah -it ghcr.io/liamg/extrude /blah/targetfile
```

## Supported Checks

### ELF

- PIE
- RELRO
- BIND NOW
- Fortified Source
- Stack Canary
- NX Stack

### MachO

- PIE
- Stack Canary
- NX Stack
- NX Heap
- ARC

### Windows

- ASLR (DYNAMIC_BASE)
- DEP (NX_COMPAT)
- Control Flow Guard (GUARD_CF)
- Stack Buffer Overrun Detection (/GS)
- Structured Exception Handler Protection (SafeSEH / NO_SEH)

## TODO

- Add secret scanning
- Detect packers
