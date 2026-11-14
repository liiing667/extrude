package pe

import (
	"debug/pe"
	"errors"
	"fmt"
	"io"
	"path/filepath"

	"github.com/liamg/extrude/pkg/format"
	"github.com/liamg/extrude/pkg/parser/pe/hardening"
	"github.com/liamg/extrude/pkg/report"
)

type parser struct{}

func New() *parser {
	return &parser{}
}

func (p *parser) Parse(r io.ReaderAt, path string, fileFormat format.Format) (reporter report.Reporter, err error) {

	var metadata Metadata
	metadata.File.Path = path
	metadata.File.Name = filepath.Base(path)
	metadata.File.Format = fileFormat
	metadata.reader = r

	// debug/pe performs only basic validation and can panic on malformed
	// inputs, so recover and surface the failure as an explicit error.
	defer func() {
		if recovered := recover(); recovered != nil {
			reporter = nil
			err = fmt.Errorf("malformed PE/COFF file: %v", recovered)
		}
	}()

	file, err := pe.NewFile(r)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PE/COFF file: %w", err)
	}
	metadata.pe = file

	if err := metadata.analyse(); err != nil {
		return nil, err
	}

	return &metadata, nil
}

func (m *Metadata) analyse() error {
	if m.pe == nil {
		return errors.New("no PE/COFF image was parsed")
	}
	m.Hardening = hardening.IdentifyAttributes(m.pe, m.reader)
	return nil
}
