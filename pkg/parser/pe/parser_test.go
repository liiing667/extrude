package pe

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/liamg/extrude/pkg/format"
	"github.com/liamg/extrude/pkg/report"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var updateFixtures = flag.Bool("update", false, "regenerate PE test fixtures")

const (
	hardenedFixture = "hardened.exe"
	weakFixture     = "weak.exe"
	corruptFixture  = "corrupt.exe"
)

func hardenedOptions() peOptions {
	return peOptions{
		dllCharacteristics: imageDllCharacteristicsDynamicBase |
			imageDllCharacteristicsNXCompat |
			imageDllCharacteristicsNoSEH |
			imageDllCharacteristicsGuardCF,
		securityCookie: true,
		noSEH:          true,
		guardFlags:     0x1000,
		loadConfig:     true,
	}
}

func TestHardenedImage(t *testing.T) {
	metadata := parseTestImage(t, hardenedOptions())

	checks := map[string]bool{
		"Address Space Layout Randomization":      metadata.Hardening.AddressSpaceLayoutRandomization.Enabled,
		"Data Execution Prevention":               metadata.Hardening.DataExecutionPrevention.Enabled,
		"Control Flow Guard":                      metadata.Hardening.ControlFlowGuard.Enabled,
		"Stack Buffer Overrun Detection":          metadata.Hardening.StackBufferOverrunDetection.Enabled,
		"Structured Exception Handler Protection": metadata.Hardening.StructuredExceptionHandlerProtection.Enabled,
	}
	for name, enabled := range checks {
		assert.True(t, enabled, "%s should be enabled", name)
	}

	assert.Contains(t, metadata.Hardening.AddressSpaceLayoutRandomization.Evidence, "DYNAMIC_BASE")
	assert.Contains(t, metadata.Hardening.DataExecutionPrevention.Evidence, "NX_COMPAT")
	assert.Contains(t, metadata.Hardening.ControlFlowGuard.Evidence, "GUARD_CF")
	assert.Contains(t, metadata.Hardening.StackBufferOverrunDetection.Evidence, "security_cookie")
	assert.Contains(t, metadata.Hardening.StructuredExceptionHandlerProtection.Evidence, "NO_SEH")
}

func TestWeakImage(t *testing.T) {
	metadata := parseTestImage(t, peOptions{})

	assert.False(t, metadata.Hardening.AddressSpaceLayoutRandomization.Enabled)
	assert.False(t, metadata.Hardening.DataExecutionPrevention.Enabled)
	assert.False(t, metadata.Hardening.ControlFlowGuard.Enabled)
	assert.False(t, metadata.Hardening.StackBufferOverrunDetection.Enabled)
	assert.False(t, metadata.Hardening.StructuredExceptionHandlerProtection.Enabled)

	assert.Contains(t, metadata.Hardening.AddressSpaceLayoutRandomization.Evidence, "not set")
	assert.Contains(t, metadata.Hardening.StackBufferOverrunDetection.Evidence, "no COFF symbol table")
}

func TestSafeSEHOn32BitStyleLoadConfig(t *testing.T) {
	options := peOptions{
		loadConfig:      true,
		safeSEHHandlers: 2,
	}
	metadata := parseTestImage(t, options)
	assert.False(t, metadata.Hardening.StructuredExceptionHandlerProtection.Enabled,
		"SafeSEH handler table only applies to 32-bit images, the PE32+ fixture must still fail")
	assert.Contains(t, metadata.Hardening.StructuredExceptionHandlerProtection.Evidence, "NO_SEH")
}

func TestCorruptImageFails(t *testing.T) {
	corrupt := buildPE(hardenedOptions())
	// Truncate the image inside the section payload so the structure is broken.
	corrupt = corrupt[:len(corrupt)-512]

	_, err := New().Parse(bytes.NewReader(corrupt), corruptFixture, format.PE)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "PE/COFF")
}

func TestInvalidPESignatureFails(t *testing.T) {
	corrupt := buildPE(hardenedOptions())
	// Wipe the PE\0\0 signature while retaining the MZ DOS header.
	corrupt[0x80] = 'X'
	corrupt[0x81] = 'X'

	_, err := New().Parse(bytes.NewReader(corrupt), corruptFixture, format.PE)
	require.Error(t, err)
}

type panickingReader struct{}

func (panickingReader) ReadAt([]byte, int64) (int, error) {
	panic("simulated malformed input panic")
}

func TestMalformedInputDoesNotPanic(t *testing.T) {
	reporter, err := New().Parse(panickingReader{}, "panic.exe", format.PE)
	require.Error(t, err)
	assert.Nil(t, reporter)
	assert.Contains(t, err.Error(), "malformed PE/COFF file")
}

func TestReportChainIncludesAllChecksWithEvidence(t *testing.T) {
	metadata := parseTestImage(t, hardenedOptions())
	rep, err := metadata.CreateReport()
	require.NoError(t, err)

	var sections []string
	var testNames []string
	for _, section := range rep.Sections() {
		sections = append(sections, section.Heading())
		for _, test := range section.Tests() {
			testNames = append(testNames, test.Name)
			assert.Contains(t, test.Description, "Evidence:")
		}
	}

	assert.Contains(t, sections, "Overview")
	assert.Contains(t, sections, "Security Features")
	assert.ElementsMatch(t, []string{
		"Address Space Layout Randomization",
		"Data Execution Prevention",
		"Control Flow Guard",
		"Stack Buffer Overrun Detection",
		"Structured Exception Handler Protection",
	}, testNames)
	assert.Equal(t, report.Pass, rep.Status())
}

func TestWeakReportFails(t *testing.T) {
	metadata := parseTestImage(t, peOptions{})
	rep, err := metadata.CreateReport()
	require.NoError(t, err)
	assert.Equal(t, report.Fail, rep.Status())
}

func TestFixturesOnDisk(t *testing.T) {
	for _, name := range []string{hardenedFixture, weakFixture, corruptFixture} {
		path := filepath.Join("_testdata", name)
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(path)
			require.NoError(t, err)

			reporter, err := New().Parse(bytes.NewReader(data), path, format.PE)
			switch name {
			case corruptFixture:
				require.Error(t, err)
			default:
				require.NoError(t, err)
				rep, err := reporter.CreateReport()
				require.NoError(t, err)
				assert.NotEmpty(t, rep.Sections())
			}
		})
	}
}

func parseTestImage(t *testing.T, options peOptions) *Metadata {
	t.Helper()
	reporter, err := New().Parse(bytes.NewReader(buildPE(options)), "test.exe", format.PE)
	require.NoError(t, err)
	metadata, ok := reporter.(*Metadata)
	require.True(t, ok)
	return metadata
}

func TestMain(m *testing.M) {
	flag.Parse()
	if *updateFixtures {
		writeFixture(tHelperPath(hardenedFixture), buildPE(hardenedOptions()))
		writeFixture(tHelperPath(weakFixture), buildPE(peOptions{}))

		corrupt := buildPE(hardenedOptions())
		writeFixture(tHelperPath(corruptFixture), corrupt[:0x200])
	}
	os.Exit(m.Run())
}

func tHelperPath(name string) string {
	return filepath.Join("_testdata", name)
}

func writeFixture(path string, data []byte) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		panic(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		panic(err)
	}
}
