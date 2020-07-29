package main

import (
	"fmt"
	"io"
	"encoding/binary"
	"bytes"
	"debug/elf"
	"os"
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

type ElfFile struct{
	Fh *os.File
	Ident [16]byte
	FileHdr EnumIdent
	Hdr interface{}
	Err error
	ElfSections ShdrTble
	Size int64
}

const (
	SUCCESS int = 0
	ERROR   int = 1
)

func (elf_fs *ElfFile) SetArch() {
	switch elf.Class(elf_fs.Ident[elf.EI_CLASS]) {
		case elf.ELFCLASS64:
			elf_fs.Hdr = new(elf.Header64)
			elf_fs.FileHdr.Arch = elf.ELFCLASS64

		case elf.ELFCLASS32:
			elf_fs.Hdr = new(elf.Header32)
			elf_fs.FileHdr.Arch = elf.ELFCLASS32
		default:
			fmt.Println("Elf Arch Class Invalid !\n")
			os.Exit(1)
	}
}

func (elf_fs *ElfFile) MapHeader() {

	switch elf.Data(elf_fs.Ident[elf.EI_DATA]) {
		case elf.ELFDATA2LSB:
			elf_fs.FileHdr.Endianness = binary.LittleEndian
		case elf.ELFDATA2MSB:
			elf_fs.FileHdr.Endianness = binary.BigEndian
		default:
			fmt.Println("Possible Corruption, Endianness unknown\n")
	}

	elf_fs.Fh.Seek(0, io.SeekStart)
	err := binary.Read(elf_fs.Fh, elf_fs.FileHdr.Endianness, elf_fs.Hdr)
	checkError(err)
}


func (elf_fs *ElfFile) findSectionByName(name string) {
	return
}

//Section Header Table Offset = Shoff
//Number of Section Header Table Entries = Shnum
//Size per entry in Section Header Table = Shentsize
//Calculate the size of Section Header Table = Shnum * Shentsize


func (elf_fs *ElfFile) getSections() {

	if h, ok := elf_fs.Hdr.(*elf.Header64); ok {
		shdrTableSize := h.Shentsize * h.Shnum

		elf_fs.ElfSections.Section = make([]elf.Section64, h.Shnum)
		elf_fs.ElfSections.SectionName = make([]string, h.Shnum)

		sr := io.NewSectionReader(elf_fs.Fh, int64(h.Shoff), int64(shdrTableSize))
		err := binary.Read(sr, elf_fs.FileHdr.Endianness, elf_fs.ElfSections.Section.([]elf.Section64))
		checkError(err)

		strTable := make([]byte, elf_fs.ElfSections.Section.([]elf.Section64)[h.Shstrndx].Size)
		strTableOff := elf_fs.ElfSections.Section.([]elf.Section64)[h.Shstrndx].Off
		strTableSize := elf_fs.ElfSections.Section.([]elf.Section64)[h.Shstrndx].Size

		strTabSec := io.NewSectionReader(elf_fs.Fh, int64(strTableOff), int64(strTableSize) + int64(strTableOff))
		err = binary.Read(strTabSec, elf_fs.FileHdr.Endianness, strTable)
		checkError(err)

		for i := 0; i < int(h.Shnum); i++ {
			strIndex := elf_fs.ElfSections.Section.([]elf.Section64)[i].Name
			elf_fs.ElfSections.SectionName.([]string)[i] = getSectionName(strIndex, strTable)
		}
	}

	if h, ok := elf_fs.Hdr.(*elf.Header32); ok {
		shdrTableSize := h.Shentsize * h.Shnum

		elf_fs.ElfSections.Section = make([]elf.Section32, h.Shnum)
		elf_fs.ElfSections.SectionName = make([]string, h.Shnum)

		sr := io.NewSectionReader(elf_fs.Fh, int64(h.Shoff), int64(shdrTableSize))
		err := binary.Read(sr, elf_fs.FileHdr.Endianness, elf_fs.ElfSections.Section.([]elf.Section32))
		checkError(err)

		strTable := make([]byte, elf_fs.ElfSections.Section.([]elf.Section32)[h.Shstrndx].Size)
		strTableOff := elf_fs.ElfSections.Section.([]elf.Section32)[h.Shstrndx].Off
		strTableSize := elf_fs.ElfSections.Section.([]elf.Section32)[h.Shstrndx].Size
		StrTableEnd := strTableOff + strTableSize

		strTabSec := io.NewSectionReader(elf_fs.Fh, int64(strTableOff), int64(StrTableEnd))
		err = binary.Read(strTabSec, elf_fs.FileHdr.Endianness, strTable)
		checkError(err)

		for i := 0; i < int(h.Shnum); i++ {
			strIndex := elf_fs.ElfSections.Section.([]elf.Section32)[i].Name
			elf_fs.ElfSections.SectionName.([]string)[i] = getSectionName(strIndex, strTable)
		}
	}
}

func getSectionName(strIndex uint32, sectionStrTab []byte) string {
	end := strIndex
	for end < uint32(len(sectionStrTab)) {
		if sectionStrTab[end] == 0x0 {
			break;
		}
		end++
	}

	var name bytes.Buffer
	name.Write(sectionStrTab[strIndex:end])
	return name.String()
}

func printSections(ElfSections ShdrTble, numSec uint16, secOff interface{}) {
	
	switch secOff.(type) {
		case uint32:
		fmt.Printf("%d Sections @ Offset 0x%x\n", numSec, secOff.(uint32))

		case uint64:
		fmt.Printf("%d Sections @ Offset 0x%x\n", numSec, secOff.(uint64))
	}

	if section, ok := ElfSections.Section.([]elf.Section32); ok {
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
	var target ElfFile;

	if len(os.Args) < 3{
		usage()
		os.Exit(ERROR)

	}

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


	var optheader, optsections bool
	options := os.Args[1]
	if options[0] != '-' {
		usage()
		os.Exit(ERROR)
	}

	for i := 1; i < len(options) ; i++ {
		switch {
			case options[i] == 'h':
				fmt.Println("h flag present")
				optheader = true
			case options[i] == 'S':
				fmt.Println("S flag present")
				optsections = true
			default:
				fmt.Println("Unrecognizable parameters");
				os.Exit(ERROR)
		}
	}

	if optheader {
		printHeader(target.Hdr)
	}

	if optsections {
		target.getSections()
		//fmt.Printf("%s\n", target.ElfSections.SectionName.([]string)[1])
		//fmt.Printf("%x\n", target.ElfSections.Section.([]elf.Section64)[1].Size)
		switch target.FileHdr.Arch {
			case elf.ELFCLASS32:
			printSections(target.ElfSections, target.Hdr.(*elf.Header32).Shnum, target.Hdr.(*elf.Header32).Shoff)
			case elf.ELFCLASS64:
			printSections(target.ElfSections, target.Hdr.(*elf.Header64).Shnum, target.Hdr.(*elf.Header64).Shoff)
		}
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
