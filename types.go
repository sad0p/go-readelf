package main

import (
	"debug/elf"
	"encoding/binary"
	"os"
)

type EnumIdent struct {
	Endianness binary.ByteOrder
	Arch       elf.Class
	Machine    elf.Machine
}

type SHDRTable struct {
	Section     interface{}
	SectionName []string
}

type SYMTable struct {
	Symbol     interface{}
	SymbolName []string
}

type ELFFile struct {
	Fh          *os.File
	Ident       [16]byte
	FileHdr     EnumIdent
	Hdr         interface{}
	err         error
	ElfSections SHDRTable
	ElfSymbols  SYMTable
	Size        int64

	Symbols        map[uint32]interface{}
	SymbolsName    map[uint32]string
	DynSymbols     map[uint32]interface{}
	DynSymbolsName map[uint32]string
	Rels           map[uint32]interface{} // relocation entries are mapped to section index

}

const (
	DynSym int = 0xa
	Sym    int = 0xb
)
