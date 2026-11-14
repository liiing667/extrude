package pe

import (
	"debug/pe"
	"io"

	"github.com/liamg/extrude/pkg/format"
	"github.com/liamg/extrude/pkg/parser/pe/hardening"
)

type Metadata struct {
	File struct {
		Path   string
		Name   string
		Format format.Format
	}
	Hardening hardening.Attributes
	pe        *pe.File
	reader    io.ReaderAt
}
