package parser

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseFileRoutesPEIntoReportChain(t *testing.T) {
	rep, err := ParseFile(filepath.Join("pe", "_testdata", "hardened.exe"))
	require.NoError(t, err)

	var testNames []string
	for _, section := range rep.Sections() {
		if section.Heading() == "Security Features" {
			for _, test := range section.Tests() {
				testNames = append(testNames, test.Name)
				assert.NotEmpty(t, test.Description)
			}
		}
	}

	assert.ElementsMatch(t, []string{
		"Address Space Layout Randomization",
		"Data Execution Prevention",
		"Control Flow Guard",
		"Stack Buffer Overrun Detection",
		"Structured Exception Handler Protection",
	}, testNames)
}

func TestParseFileFailsOnCorruptPE(t *testing.T) {
	_, err := ParseFile(filepath.Join("pe", "_testdata", "corrupt.exe"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "PE/COFF")
}

func TestParseFileRejectsUnknownFormat(t *testing.T) {
	path := filepath.Join(t.TempDir(), "unknown.bin")
	require.NoError(t, os.WriteFile(path, []byte{0x00, 0x00, 0x00, 0x00}, 0o644))

	_, err := ParseFile(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not supported")
}
