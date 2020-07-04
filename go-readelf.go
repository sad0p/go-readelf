package main

import (
	"fmt"
	"io"
	"encoding/binary"
	"bytes"
	"debug/elf"
	"flag"
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

type elfbin interface{
	Header(amb_elf_arch interface{})
}

type enum_Ident struct{
	Endianness binary.ByteOrder
	Arch elf.Class
}

type ShdrTble struct{
	Section interface{}
	SectionName interface{}
}

type elf_File struct{
	Fh *os.File
	Ident [16]byte
	FileHdr enum_Ident
	Hdr interface{}
	Err error
	ElfSections ShdrTble
	Size int64
}

func (elf_fs *elf_File) Header(amb_elf_arch interface{}){
	switch v := amb_elf_arch.(type) {
		case *elf.Header32:
			fmt.Printf("Elf32 detected: %v\n", v)
		case *elf.Header64:
			fmt.Println("Elf64 detected: %v\n", v)
		default:
			fmt.Println("Invalid Type detected: %v\n", v)
	}
}

func (elf_fs *elf_File) SetArch() {
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

func (elf_fs *elf_File) MapHeader() {

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
	checkerror(err)
}


func (elf_fs *elf_File) FindSectionByName(name string) {
	return
}

//Section Header Table Offset = Shoff
//Number of Section Header Table Entries = Shnum
//Size per entry in Section Header Table = Shentsize
//Calculate the size of Section Header Table = Shnum * Shentsize


func (elf_fs *elf_File) GetSections() {

	var StrTabBuf bytes.Buffer

	if h, ok := elf_fs.Hdr.(*elf.Header64); ok {
		Shentsize_ := h.Shentsize
		Shnum_ := h.Shnum
		ShdrTableSize := Shentsize_ * Shnum_

		elf_fs.ElfSections.Section = make([]elf.Section64, Shnum_)
		elf_fs.ElfSections.SectionName = make([]string, Shnum_)

		sr := io.NewSectionReader(elf_fs.Fh, int64(h.Shoff), int64(ShdrTableSize))
		err := binary.Read(sr, elf_fs.FileHdr.Endianness, elf_fs.ElfSections.Section.([]elf.Section64))
		checkerror(err)

		StrTable := make([]byte, elf_fs.ElfSections.Section.([]elf.Section64)[h.Shstrndx].Size)
		StrTableOff := elf_fs.ElfSections.Section.([]elf.Section64)[h.Shstrndx].Off
		StrTableSize := elf_fs.ElfSections.Section.([]elf.Section64)[h.Shstrndx].Size

		StrTabSec := io.NewSectionReader(elf_fs.Fh, int64(StrTableOff), int64(StrTableSize) + int64(StrTableOff))
		err = binary.Read(StrTabSec, elf_fs.FileHdr.Endianness, StrTable)
		checkerror(err)

		var SecStrEnd uint64
		for i := 0; i < int(Shnum_); i++ {
			SecStrStart := elf_fs.ElfSections.Section.([]elf.Section64)[i].Name
			for SecStrEnd = uint64(SecStrStart); SecStrEnd < uint64(len(StrTable)); SecStrEnd++ {
				if StrTable[SecStrEnd] == 0x0 {
					break;
				}
			}

			StrTabBuf.Write(StrTable[SecStrStart:SecStrEnd])
			elf_fs.ElfSections.SectionName.([]string)[i] = StrTabBuf.String()
			StrTabBuf.Reset()
		}
	}

	if h, ok := elf_fs.Hdr.(*elf.Header32); ok {
		Shentsize_ := h.Shentsize
		Shnum_ := h.Shnum
		ShdrTableSize := Shentsize_ * Shnum_

		elf_fs.ElfSections.Section = make([]elf.Section32, Shnum_)
		elf_fs.ElfSections.SectionName = make([]string, Shnum_)

		sr := io.NewSectionReader(elf_fs.Fh, int64(h.Shoff), int64(ShdrTableSize))
		err := binary.Read(sr, elf_fs.FileHdr.Endianness, elf_fs.ElfSections.Section.([]elf.Section32))
		checkerror(err)

		StrTable := make([]byte, elf_fs.ElfSections.Section.([]elf.Section32)[h.Shstrndx].Size)
		StrTableOff := elf_fs.ElfSections.Section.([]elf.Section32)[h.Shstrndx].Off
		StrTableSize := elf_fs.ElfSections.Section.([]elf.Section32)[h.Shstrndx].Size
		StrTableEnd := StrTableOff + StrTableSize

		StrTabSec := io.NewSectionReader(elf_fs.Fh, int64(StrTableOff), int64(StrTableEnd))
		err = binary.Read(StrTabSec, elf_fs.FileHdr.Endianness, StrTable)
		checkerror(err)

		var SecStrEnd uint64
		for i := 0; i < int(Shnum_); i++ {
			SecStrStart := elf_fs.ElfSections.Section.([]elf.Section32)[i].Name
			for SecStrEnd = uint64(SecStrStart); SecStrEnd < uint64(len(StrTable)); SecStrEnd++ {
				if StrTable[SecStrEnd] == 0x0 {
					break;
				}
			}

			StrTabBuf.Write(StrTable[SecStrStart:SecStrEnd])
			elf_fs.ElfSections.SectionName.([]string)[i] = StrTabBuf.String()
			StrTabBuf.Reset()
		}
	}
}
func print_sections() {
	return
}

func print_header(hdr interface{}) {
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
	var target elf_File;
	readheader := flag.String("-h", "", "Print out elf header of binary")
	readsections := flag.String("-S", "", "Print out section headers")
	flag.Parse()

	bin := os.Args[3]
	target.Fh, target.Err = os.Open(bin)
	checkerror(target.Err)

	target.Fh.Read(target.Ident[:16])

	if is_elf(target.Ident[:4]) == false {
		fmt.Println("This is not an Elf binary\n")
		os.Exit(1)
	}
	target.SetArch()
	target.MapHeader()

	switch os.Args[1]{
	case "-h":
		



	}
	target.GetSections()
	fmt.Printf("%s\n", target.ElfSections.SectionName.([]string)[1])
	fmt.Printf("%x\n", target.ElfSections.Section.([]elf.Section32)[1].Size)
}

func checkerror(e error){
	if e != nil{
		panic(e)
	}
}

func is_elf(magic []byte) bool {
	return !(magic[0] != '\x7f' || magic[1] != 'E' || magic [2] != 'L' || magic[3] != 'F')
}
