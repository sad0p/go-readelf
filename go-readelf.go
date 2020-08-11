package main

import (
	"fmt"
	"io"
	"encoding/binary"
	"bytes"
	"debug/elf"
	"os"
	"unsafe"
	)

// Goals
// [1] Determine if file is elf binary (abort process if it isn't)
// [2] Determine architecture of elf binary if it is 32bit or 64bit
// [3] Abstract away architectural differences from the perspective of main function
// [4] Create functionality to print elfheader
// [5] Create functionality to print imported symbols
// [6] Create functionality to print exported symbols
// [7] Create functionality to print all symbols
// [8] Create functionality to print relocation entries
// [9] Create functionality to print shared library dependencies
// [10] Create functionality to locate a specific symbol

type ElfBiner interface{
	Header(amb_elf_arch interface{})
}

type EnumIdent struct{
	Endianness binary.ByteOrder
	Arch elf.Class
}

type ShdrTble struct{
	Section interface{}
	SectionName interface{}
}

type SymTab struct{
	Symbol interface{}
	SymbolName interface{}
}

type ElfFile struct{
	Fh *os.File
	Ident [16]byte
	FileHdr EnumIdent
	Hdr interface{}
	Err error
	ElfSections ShdrTble
	ElfSymbols SymTab
	Size int64
}

const (
	SUCCESS int = 0
	ERROR   int = 1
)

func (elfFs *ElfFile) Header(amb_elf_arch interface{}){
	switch v := amb_elf_arch.(type) {
		case *elf.Header32:
			fmt.Printf("Elf32 detected: %v\n", v)
		case *elf.Header64:
			fmt.Println("Elf64 detected: %v\n", v)
		default:
			fmt.Println("Invalid Type detected: %v\n", v)
	}
}

func (elfFs *ElfFile) SetArch() {
	switch elf.Class(elfFs.Ident[elf.EI_CLASS]) {
		case elf.ELFCLASS64:
			elfFs.Hdr = new(elf.Header64)
			elfFs.FileHdr.Arch = elf.ELFCLASS64

		case elf.ELFCLASS32:
			elfFs.Hdr = new(elf.Header32)
			elfFs.FileHdr.Arch = elf.ELFCLASS32
		default:
			fmt.Println("Elf Arch Class Invalid !\n")
			os.Exit(1)
	}
}

func (elfFs *ElfFile) MapHeader() {

	switch elf.Data(elfFs.Ident[elf.EI_DATA]) {
		case elf.ELFDATA2LSB:
			elfFs.FileHdr.Endianness = binary.LittleEndian
		case elf.ELFDATA2MSB:
			elfFs.FileHdr.Endianness = binary.BigEndian
		default:
			fmt.Println("Possible Corruption, Endianness unknown\n")
	}

	elfFs.Fh.Seek(0, io.SeekStart)
	err := binary.Read(elfFs.Fh, elfFs.FileHdr.Endianness, elfFs.Hdr)
	checkError(err)
}


func (elfFs *ElfFile) findSectionByName(name string) {
	return
}

//Section Header Table Offset = Shoff
//Number of Section Header Table Entries = Shnum
//Size per entry in Section Header Table = Shentsize
//Calculate the size of Section Header Table = Shnum * Shentsize


func (elfFs *ElfFile) getSections() {

	if h, ok := elfFs.Hdr.(*elf.Header64); ok {
		shdrTableSize := h.Shentsize * h.Shnum

		elfFs.ElfSections.Section = make([]elf.Section64, h.Shnum)
		elfFs.ElfSections.SectionName = make([]string, h.Shnum)

		sr := io.NewSectionReader(elfFs.Fh, int64(h.Shoff), int64(shdrTableSize))
		err := binary.Read(sr, elfFs.FileHdr.Endianness, elfFs.ElfSections.Section.([]elf.Section64))
		checkError(err)

		shstrtab := make([]byte, elfFs.ElfSections.Section.([]elf.Section64)[h.Shstrndx].Size)
		shstrtabOff := elfFs.ElfSections.Section.([]elf.Section64)[h.Shstrndx].Off
		shstrtabSize := elfFs.ElfSections.Section.([]elf.Section64)[h.Shstrndx].Size

		shstrtabSec := io.NewSectionReader(elfFs.Fh, int64(shstrtabOff), int64(shstrtabSize) + int64(shstrtabOff))
		err = binary.Read(shstrtabSec, elfFs.FileHdr.Endianness, shstrtab)
		checkError(err)

		for i := 0; i < int(h.Shnum); i++ {
			sIndex := elfFs.ElfSections.Section.([]elf.Section64)[i].Name
			elfFs.ElfSections.SectionName.([]string)[i] = getSectionName(sIndex, shstrtab)
		}
	}

	if h, ok := elfFs.Hdr.(*elf.Header32); ok {
		shdrTableSize := h.Shentsize * h.Shnum

		elfFs.ElfSections.Section = make([]elf.Section32, h.Shnum)
		elfFs.ElfSections.SectionName = make([]string, h.Shnum)

		sr := io.NewSectionReader(elfFs.Fh, int64(h.Shoff), int64(shdrTableSize))
		err := binary.Read(sr, elfFs.FileHdr.Endianness, elfFs.ElfSections.Section.([]elf.Section32))
		checkError(err)

		shstrtab := make([]byte, elfFs.ElfSections.Section.([]elf.Section32)[h.Shstrndx].Size)
		shstrtabOff := elfFs.ElfSections.Section.([]elf.Section32)[h.Shstrndx].Off
		shstrtabSize := elfFs.ElfSections.Section.([]elf.Section32)[h.Shstrndx].Size
		shstrTableEnd := shstrtabOff + shstrtabSize

		shstrtabSec := io.NewSectionReader(elfFs.Fh, int64(shstrtabOff), int64(shstrTableEnd))
		err = binary.Read(shstrtabSec, elfFs.FileHdr.Endianness, shstrtab)
		checkError(err)

		for i := 0; i < int(h.Shnum); i++ {
			sIndex := elfFs.ElfSections.Section.([]elf.Section32)[i].Name
			elfFs.ElfSections.SectionName.([]string)[i] = getSectionName(sIndex, shstrtab)
		}
	}
}
func (elfFs *ElfFile) getSymbols() {
    
	var dsymtabNdx uint32
	if dsymtabNdx = getSectionNdx(".dynsym", elfFs); dsymtabNdx != 0 {
		var  dynstrNdx uint32
		dynstrNdx  = getSectionNdx(".dynstr", elfFs)
		elfFs.loadSymbols(dsymtabNdx, dynstrNdx)

		fmt.Printf("%d entries found in .dynsym\n", len(elfFs.ElfSymbols.SymbolName.([]string)))
		printSymbols(elfFs)
	} else {
		fmt.Println("No Dynamic symbols found - .dynsym missing from target")
	}

	var symtabNdx uint32
	var symstrNdx  uint32
	if symtabNdx  = getSectionNdx(".symtab", elfFs); symtabNdx != 0 {
		symstrNdx  = getSectionNdx(".strtab", elfFs)
		elfFs.loadSymbols(symtabNdx, symstrNdx)

		fmt.Printf("%d entries found in .symtab\n", len(elfFs.ElfSymbols.SymbolName.([]string)))
		printSymbols(elfFs)
	} else {
		fmt.Println("Section .symtab mising -- Binary is stripped no exported symbols available !")
	}
}

func (elfFs *ElfFile) loadSymbols(sectionNdx uint32, symstrNdx uint32) {
	switch elfFs.FileHdr.Arch {
	
	case elf.ELFCLASS32:
		s := elfFs.ElfSections.Section.([]elf.Section32)[sectionNdx].Size
		numSymbols := s / uint32(unsafe.Sizeof(elfFs.ElfSymbols.Symbol.(elf.Sym32)))
		elfFs.ElfSymbols.Symbol = make([]elf.Sym32, numSymbols)

		off := elfFs.ElfSections.Section.([]elf.Section32)[sectionNdx].Off
		size := elfFs.ElfSections.Section.([]elf.Section32)[sectionNdx].Size

			sr := io.NewSectionReader(elfFs.Fh, int64(off), int64(size))
			err := binary.Read(sr, elfFs.FileHdr.Endianness, elfFs.ElfSymbols.Symbol.([]elf.Sym32))
			checkError(err)
			

			strtab := make([]byte, elfFs.ElfSections.Section.([]elf.Section32)[symstrNdx].Size)
			elfFs.ElfSymbols.SymbolName = make([]string, numSymbols)

			strtabOff := elfFs.ElfSections.Section.([]elf.Section32)[symstrNdx].Off
			strtabSize := elfFs.ElfSections.Section.([]elf.Section32)[symstrNdx].Size
			shstrtabSec := io.NewSectionReader(elfFs.Fh, int64(strtabOff), int64(strtabSize))

			err = binary.Read(shstrtabSec, elfFs.FileHdr.Endianness, strtab)
			checkError(err)
			
			for i := uint32(0); i < numSymbols; i++ {
				symIndex := elfFs.ElfSymbols.Symbol.([]elf.Sym32)[i].Name
				elfFs.ElfSymbols.SymbolName.([]string)[i] = getSymbolName(symIndex, strtab)
			}
	
	case elf.ELFCLASS64:
		s := elfFs.ElfSections.Section.([]elf.Section64)[sectionNdx].Size
		numSymbols := s / uint64(unsafe.Sizeof(elfFs.ElfSymbols.Symbol.(elf.Sym64)))
		elfFs.ElfSymbols.Symbol = make([]elf.Sym64, numSymbols)

		off := elfFs.ElfSections.Section.([]elf.Section64)[sectionNdx].Off
		size := elfFs.ElfSections.Section.([]elf.Section64)[sectionNdx].Size

		sr := io.NewSectionReader(elfFs.Fh, int64(off), int64(size))
		err := binary.Read(sr, elfFs.FileHdr.Endianness, elfFs.ElfSymbols.Symbol.([]elf.Sym64))
		checkError(err)
			

		strtab := make([]byte, elfFs.ElfSections.Section.([]elf.Section64)[symstrNdx].Size)
		elfFs.ElfSymbols.SymbolName = make([]string, numSymbols)

		strtabOff := elfFs.ElfSections.Section.([]elf.Section64)[symstrNdx].Off
		strtabSize := elfFs.ElfSections.Section.([]elf.Section64)[symstrNdx].Size
		shstrtabSec := io.NewSectionReader(elfFs.Fh, int64(strtabOff), int64(strtabSize))

		err = binary.Read(shstrtabSec, elfFs.FileHdr.Endianness, strtab)
		checkError(err)
			
		for i := uint64(0); i < numSymbols; i++ {
			symIndex := elfFs.ElfSymbols.Symbol.([]elf.Sym64)[i].Name
			elfFs.ElfSymbols.SymbolName.([]string)[i] = getSymbolName(symIndex, strtab)
		}		
	}
}

func getSymbolName(symIndex uint32, sectionStrtab []byte) string {
	return getSectionName(symIndex, sectionStrtab)
}

func getSectionNdx(name string, elfFs *ElfFile) uint32 {
	var ndx uint32
	for ndx = 0; ndx < uint32(len(elfFs.ElfSections.SectionName.([]string))); ndx++ {
		if elfFs.ElfSections.SectionName.([]string)[ndx] == name {
				return ndx
		}
	}
	return uint32(0)
}

func getSectionName(sIndex uint32, sectionShstrTab []byte) string {
	end := sIndex
	for end < uint32(len(sectionShstrTab)) {
		if sectionShstrTab[end] == 0x0 {
			break;
		}
		end++
	}

	var name bytes.Buffer
	name.Write(sectionShstrTab[sIndex:end])
	return name.String()
}

func (elfFs *ElfFile) getRelocations() {


	if s, ok := elfFs.ElfSections.Section.([]elf.Section32); ok {
		for sNdx := 0; sNdx < len(s); sNdx++ {
			switch elf.SectionType(s[sNdx].Type) {
				case elf.SHT_REL:
					fmt.Println("Got a rel")
			
			}
		}
	}
}


func printSymbols(elfFs *ElfFile) {

	//ndx := getSectionNdx(".dynsym", elfFs)
	nsym := len(elfFs.ElfSymbols.SymbolName.([]string))
	//fmt.Printf("%d Symbol entries found in .dynsym\n\n", nsym)

	switch elfFs.FileHdr.Arch{
		case elf.ELFCLASS32:
			for i := 0; i < nsym; i++ {
				fmt.Printf("Entry: #%d\n", i)
				fmt.Printf("Value: 0x%x\n",elfFs.ElfSymbols.Symbol.([]elf.Sym32)[i].Value)
				fmt.Printf("Size: %d\n", elfFs.ElfSymbols.Symbol.([]elf.Sym32)[i].Size)
				fmt.Printf("Type: %s\n", elf.ST_TYPE(elfFs.ElfSymbols.Symbol.([]elf.Sym32)[i].Info))
				fmt.Printf("Bind: %s\n", elf.ST_BIND(elfFs.ElfSymbols.Symbol.([]elf.Sym32)[i].Info))
			//	fmt.Printf("Info: %s\n", elf.ST_INFO(elfFs.ElfSymbols.Symbol.([]elf.Sym32)[i].Info))
				fmt.Printf("Visibility: %s\n", elf.ST_VISIBILITY(elfFs.ElfSymbols.Symbol.([]elf.Sym32)[i].Other))
				fmt.Printf("Section: %d\n", elfFs.ElfSymbols.Symbol.([]elf.Sym32)[i].Shndx)
				fmt.Printf("Name: %s\n", elfFs.ElfSymbols.SymbolName.([]string)[i])
				fmt.Printf("\n\n\n\n")
			}

		case elf.ELFCLASS64:
			for i := 0; i < nsym; i++ {
				fmt.Printf("Entry: #%d\n", i)
				fmt.Printf("Value: 0x%x\n",elfFs.ElfSymbols.Symbol.([]elf.Sym64)[i].Value)
				fmt.Printf("Size: %d\n", elfFs.ElfSymbols.Symbol.([]elf.Sym64)[i].Size)
				fmt.Printf("Type: %s\n", elf.ST_TYPE(elfFs.ElfSymbols.Symbol.([]elf.Sym64)[i].Info))
				fmt.Printf("Bind: %s\n", elf.ST_BIND(elfFs.ElfSymbols.Symbol.([]elf.Sym64)[i].Info))
			//	fmt.Printf("Info: %s\n", elf.ST_INFO(elfFs.ElfSymbols.Symbol.([]elf.Sym32)[i].Info))
				fmt.Printf("Visibility: %s\n", elf.ST_VISIBILITY(elfFs.ElfSymbols.Symbol.([]elf.Sym64)[i].Other))
				fmt.Printf("Section: %d\n", elfFs.ElfSymbols.Symbol.([]elf.Sym64)[i].Shndx)
				fmt.Printf("Name: %s\n", elfFs.ElfSymbols.SymbolName.([]string)[i])
				fmt.Printf("\n\n\n\n")
			}
	}

}

func printSections(ElfSections ShdrTble, numSec uint16, secOff interface{}) {
	
	fmt.Printf("------------------------------------------\n\n\n")
	switch secOff.(type) {
		case uint32:
		fmt.Printf("%d Sections @ Offset 0x%x\n", numSec, secOff.(uint32))

		case uint64:
		fmt.Printf("%d Sections @ Offset 0x%x\n", numSec, secOff.(uint64))
	}

	if section, ok := ElfSections.Section.([]elf.Section32); ok {
		for i := uint16(0); i < numSec; i++ {
			fmt.Printf("Section Number: %d\n", i)
			fmt.Printf("Name: %s\n", ElfSections.SectionName.([]string)[i])
			fmt.Printf("Type: %s\n", elf.SectionType(section[i].Type))
			fmt.Printf("Flags: %s\n", elf.SectionFlag(section[i].Flags))
			fmt.Printf("Address: 0x%x\n", section[i].Addr)
			fmt.Printf("Offset: 0x%x\n", section[i].Off)
			fmt.Printf("Size: 0x%x\n", section[i].Size)
			fmt.Printf("Link: 0x%x\n", section[i].Link)
			fmt.Printf("Info: 0x%x\n", section[i].Info)
			fmt.Printf("Alignment: 0x%x\n", section[i].Addralign)
			fmt.Printf("Entry Size: 0x%x\n", section[i].Entsize)
		}
	}

	if section, ok := ElfSections.Section.([]elf.Section64); ok {
		for i := uint16(0); i < numSec; i++ {
			fmt.Printf("------------------------------------------\n\n\n")
			fmt.Printf("Section Number: %d\n", i)
			fmt.Printf("Name: %s\n", ElfSections.SectionName.([]string)[i])
			fmt.Printf("Type: %s\n", elf.SectionType(section[i].Type))
			fmt.Printf("Flags: %s\n", elf.SectionFlag(section[i].Flags))
			fmt.Printf("Address: 0x%x\n", section[i].Addr)
			fmt.Printf("Offset: 0x%x\n", section[i].Off)
			fmt.Printf("Size: 0x%x\n", section[i].Size)
			fmt.Printf("Link: 0x%x\n", section[i].Link)
			fmt.Printf("Info: 0x%x\n", section[i].Info)
			fmt.Printf("Alignment: 0x%x\n", section[i].Addralign)
			fmt.Printf("Entry Size: 0x%x\n", section[i].Entsize)
		}
	}
	return
}

func printHeader(hdr interface{}) {
        if h, ok := hdr.(*elf.Header64); ok{
                fmt.Printf("-------------------------- Elf Header ------------------------\n")
                fmt.Printf("Magic: % x\n", h.Ident)
                fmt.Printf("Elf Type: %s\n", elf.Type(h.Type))
                fmt.Printf("Machine: %s\n", elf.Machine(h.Machine))
                fmt.Printf("Version: %s\n", elf.Version(h.Version))
                fmt.Printf("Entry: 0x%x\n", h.Entry)
                fmt.Printf("Program Header Offset: 0x%x\n", h.Phoff)
                fmt.Printf("Section Header Offset: 0x%x\n", h.Shoff)
                fmt.Printf("Flags: 0x%x\n", h.Flags)
                fmt.Printf("Elf Header Size (bytes): %d\n", h.Ehsize)
                fmt.Printf("Program Header Entry Size (bytes): %d\n", h.Phentsize)
                fmt.Printf("Number of Program Header Entries: %d\n", h.Phnum)
                fmt.Printf("Size of Section Header Entry: %d\n", h.Shentsize)
                fmt.Printf("Number of Section Header Entries: %d\n", h.Shnum)
                fmt.Printf("Index In Section Header Table For String Section: %d\n", h.Shstrndx)
	}

        if h, ok := hdr.(*elf.Header32); ok{
                fmt.Printf("-------------------------- Elf Header ------------------------\n")
                fmt.Printf("Magic: % x\n", h.Ident)
                fmt.Printf("Elf Type: %s\n", elf.Type(h.Type))
                fmt.Printf("Machine: %s\n", elf.Machine(h.Machine))
                fmt.Printf("Version: %s\n", elf.Version(h.Version))
                fmt.Printf("Entry: 0x%x\n", h.Entry)
                fmt.Printf("Program Header Offset: 0x%x\n", h.Phoff)
                fmt.Printf("Section Header Offset: 0x%x\n", h.Shoff)
                fmt.Printf("Flags: 0x%x\n", h.Flags)
                fmt.Printf("Elf Header Size (bytes): %d\n", h.Ehsize)
                fmt.Printf("Program Header Entry Size (bytes): %d\n", h.Phentsize)
                fmt.Printf("Number of Program Header Entries: %d\n", h.Phnum)
                fmt.Printf("Size of Section Header Entry: %d\n", h.Shentsize)
                fmt.Printf("Number of Section Header Entries: %d\n", h.Shnum)
                fmt.Printf("Index In Section Header Table For String Section: %d\n", h.Shstrndx)
	}
	return
}

func main() {

	if len(os.Args) < 3{
		usage()
		os.Exit(ERROR)

	}

	var target ElfFile;

	bin := os.Args[2]
	target.Fh, target.Err = os.Open(bin)
	checkError(target.Err)

	target.Fh.Read(target.Ident[:16])

	if isElf(target.Ident[:4]) == false {
		fmt.Println("This is not an Elf binary\n")
		os.Exit(1)
	}
	target.SetArch()
	target.MapHeader()


	options := os.Args[1]
	if options[0] != '-' {
		usage()
		os.Exit(ERROR)
	}

	var optHeader, optSections, optSymbols, optRelocations bool
	for i := 1; i < len(options) ; i++ {
		switch {
			case options[i] == 'h':
				optHeader = true
			case options[i] == 'S':
				optSections = true
			case options[i] == 's':
				optSymbols = true
			case options[i] == 'r':
				optRelocations = true
			default:
				fmt.Println("Unrecognizable parameters");
				os.Exit(ERROR)
		}
	}

	if optHeader {
		printHeader(target.Hdr)
	}

	if optSections {
		target.getSections()
		switch target.FileHdr.Arch {
			case elf.ELFCLASS32:
				printSections(target.ElfSections, target.Hdr.(*elf.Header32).Shnum, target.Hdr.(*elf.Header32).Shoff)
			case elf.ELFCLASS64:
				printSections(target.ElfSections, target.Hdr.(*elf.Header64).Shnum, target.Hdr.(*elf.Header64).Shoff)
		}
	}

	if optSymbols {
		if optSections == false {
			target.getSections()
		}
		target.getSymbols()
	}

	if optRelocations {
		if optSections == false {
			target.getSections()
		}
		target.getRelocations()
	}
}

func usage() {
	fmt.Println("Usage information")
}

func checkError(checkError error){
	if checkError != nil{
		panic(checkError)
	}
}

func isElf(magic []byte) bool {
	return !(magic[0] != '\x7f' || magic[1] != 'E' || magic [2] != 'L' || magic[3] != 'F')
}
