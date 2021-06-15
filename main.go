package main

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"
	"unsafe"
)

func (elfFs *ELFFile) setArch() {
	switch elf.Class(elfFs.Ident[elf.EI_CLASS]) {
	case elf.ELFCLASS64:
		elfFs.Hdr = new(elf.Header64)
		elfFs.FileHdr.Arch = elf.ELFCLASS64

	case elf.ELFCLASS32:
		elfFs.Hdr = new(elf.Header32)
		elfFs.FileHdr.Arch = elf.ELFCLASS32
	default:
		fmt.Println("Elf Arch Class Invalid !")
		os.Exit(1)
	}
}

func (elfFs *ELFFile) mapHeader() {

	switch elf.Data(elfFs.Ident[elf.EI_DATA]) {
	case elf.ELFDATA2LSB:
		elfFs.FileHdr.Endianness = binary.LittleEndian
	case elf.ELFDATA2MSB:
		elfFs.FileHdr.Endianness = binary.BigEndian
	default:
		fmt.Println("Possible Corruption, Endianness unknown")
	}

	elfFs.Fh.Seek(0, io.SeekStart)
	err := binary.Read(elfFs.Fh, elfFs.FileHdr.Endianness, elfFs.Hdr)
	checkError(err)

	switch h := elfFs.Hdr.(type) {
	case *elf.Header32:
		elfFs.FileHdr.Machine = elf.Machine(h.Machine)
	case *elf.Header64:
		elfFs.FileHdr.Machine = elf.Machine(h.Machine)
	}
}

//Section Header Table Offset = Shoff
//Number of Section Header Table Entries = Shnum
//Size per entry in Section Header Table = Shentsize
//Calculate the size of Section Header Table = Shnum * Shentsize

func (elfFs *ELFFile) getSections() {

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

		shstrtabSec := io.NewSectionReader(elfFs.Fh, int64(shstrtabOff), int64(shstrtabSize)+int64(shstrtabOff))
		err = binary.Read(shstrtabSec, elfFs.FileHdr.Endianness, shstrtab)
		checkError(err)

		for i := 0; i < int(h.Shnum); i++ {
			sIndex := elfFs.ElfSections.Section.([]elf.Section64)[i].Name
			elfFs.ElfSections.SectionName[i] = getSectionName(sIndex, shstrtab)
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
			elfFs.ElfSections.SectionName[i] = getSectionName(sIndex, shstrtab)
		}
	}
}

func (elfFs *ELFFile) getSymbols() {
	var dsymtabNdx uint32
	if dsymtabNdx = getSectionNdx(".dynsym", elfFs); dsymtabNdx != 0 {
		var dynstrNdx uint32
		dynstrNdx = getSectionNdx(".dynstr", elfFs)
		elfFs.loadSymbols(dsymtabNdx, dynstrNdx, DynSym)

		fmt.Printf("%d entries found in .dynsym\n", len(elfFs.DynSymbols))
		printSymbols(elfFs)
	} else {
		fmt.Println("No Dynamic symbols found - .dynsym missing from target")
	}

	var symtabNdx uint32
	var symstrNdx uint32
	if symtabNdx = getSectionNdx(".symtab", elfFs); symtabNdx != 0 {
		symstrNdx = getSectionNdx(".strtab", elfFs)
		elfFs.loadSymbols(symtabNdx, symstrNdx, Sym)
		fmt.Printf("%d entries found in .symtab\n", len(elfFs.Symbols))
		printSymbols(elfFs)
	} else {
		fmt.Println("Section .symtab mising -- Binary is stripped no exported symbols available !")
	}
}

func (elfFs *ELFFile) loadSymbols(sectionNdx uint32, symstrNdx uint32, symType int) {
	switch elfFs.FileHdr.Arch {
	case elf.ELFCLASS32:
		var sym32 elf.Sym32
		symSize := uint32(unsafe.Sizeof(sym32))
		symtabSize := elfFs.ElfSections.Section.([]elf.Section32)[sectionNdx].Size
		numSymbols := symtabSize / symSize
		off := elfFs.ElfSections.Section.([]elf.Section32)[sectionNdx].Off

		/* strtab can be either .dynstr or .strtab depending on the symbol table*/
		strtab := make([]byte, elfFs.ElfSections.Section.([]elf.Section32)[symstrNdx].Size)
		strtabOff := elfFs.ElfSections.Section.([]elf.Section32)[symstrNdx].Off
		strtabSize := elfFs.ElfSections.Section.([]elf.Section32)[symstrNdx].Size

		n := int64(strtabOff + strtabSize)
		shstrtabSec := io.NewSectionReader(elfFs.Fh, int64(strtabOff), n)

		err := binary.Read(shstrtabSec, elfFs.FileHdr.Endianness, strtab)
		checkError(err)

		if symType == Sym {
			elfFs.Symbols = make(map[uint32]interface{})
			elfFs.SymbolsName = make(map[uint32]string)
			n := int64(off + symtabSize)
			sr := io.NewSectionReader(elfFs.Fh, int64(off), n)

			for symNdx := uint32(0); symNdx < numSymbols; symNdx++ {
				elfFs.Symbols[symNdx] = new(elf.Sym32)
				err := binary.Read(sr, elfFs.FileHdr.Endianness, elfFs.Symbols[symNdx])
				checkError(err)
				symEntry := elfFs.Symbols[symNdx]
				elfFs.SymbolsName[symEntry.(*elf.Sym32).Name] = getSymbolName(symEntry.(*elf.Sym32).Name, strtab)
			}
		}

		if symType == DynSym {
			elfFs.DynSymbols = make(map[uint32]interface{})
			elfFs.DynSymbolsName = make(map[uint32]string)
			n := int64(off + symtabSize)
			sr := io.NewSectionReader(elfFs.Fh, int64(off), n)

			for symNdx := uint32(0); symNdx < numSymbols; symNdx++ {
				elfFs.DynSymbols[symNdx] = new(elf.Sym32)
				err := binary.Read(sr, elfFs.FileHdr.Endianness, elfFs.DynSymbols[symNdx])
				checkError(err)
				symEntry := elfFs.DynSymbols[symNdx]
				elfFs.DynSymbolsName[symEntry.(*elf.Sym32).Name] = getSymbolName(symEntry.(*elf.Sym32).Name, strtab)
			}
		}

	case elf.ELFCLASS64:
		var sym64 elf.Sym64
		symSize := uint32(unsafe.Sizeof(sym64))
		symtabSize := elfFs.ElfSections.Section.([]elf.Section64)[sectionNdx].Size
		numSymbols := symtabSize / uint64(symSize)
		off := elfFs.ElfSections.Section.([]elf.Section64)[sectionNdx].Off

		/* strtab can be either .dynstr or .strtab depending on the symbol table*/
		strtab := make([]byte, elfFs.ElfSections.Section.([]elf.Section64)[symstrNdx].Size)
		strtabOff := elfFs.ElfSections.Section.([]elf.Section64)[symstrNdx].Off
		strtabSize := elfFs.ElfSections.Section.([]elf.Section64)[symstrNdx].Size
		n := int64(strtabOff + strtabSize)

		shstrtabSec := io.NewSectionReader(elfFs.Fh, int64(strtabOff), n)

		err := binary.Read(shstrtabSec, elfFs.FileHdr.Endianness, strtab)
		checkError(err)

		if symType == Sym {
			elfFs.Symbols = make(map[uint32]interface{})
			elfFs.SymbolsName = make(map[uint32]string)
			n := int64(off + symtabSize)
			sr := io.NewSectionReader(elfFs.Fh, int64(off), n)

			for symNdx := uint32(0); uint64(symNdx) < numSymbols; symNdx++ {
				elfFs.Symbols[symNdx] = new(elf.Sym64)
				err := binary.Read(sr, elfFs.FileHdr.Endianness, elfFs.Symbols[symNdx])
				checkError(err)
				symEntry := elfFs.Symbols[symNdx]
				elfFs.SymbolsName[symEntry.(*elf.Sym64).Name] = getSymbolName(symEntry.(*elf.Sym64).Name, strtab)
			}
		}

		if symType == DynSym {
			elfFs.DynSymbols = make(map[uint32]interface{})
			elfFs.DynSymbolsName = make(map[uint32]string)
			n := int64(off + symtabSize)
			sr := io.NewSectionReader(elfFs.Fh, int64(off), n)

			for symNdx := uint32(0); uint64(symNdx) < numSymbols; symNdx++ {
				elfFs.DynSymbols[symNdx] = new(elf.Sym64)
				err := binary.Read(sr, elfFs.FileHdr.Endianness, elfFs.DynSymbols[symNdx])
				checkError(err)
				symEntry := elfFs.DynSymbols[symNdx]
				elfFs.DynSymbolsName[symEntry.(*elf.Sym64).Name] = getSymbolName(symEntry.(*elf.Sym64).Name, strtab)
			}
		}
	}
}

func getSymbolName(symIndex uint32, sectionStrtab []byte) string {
	return getSectionName(symIndex, sectionStrtab)
}

func getSectionNdx(name string, elfFs *ELFFile) uint32 {
	var ndx uint32
	for ndx = 0; ndx < uint32(len(elfFs.ElfSections.SectionName)); ndx++ {
		if elfFs.ElfSections.SectionName[ndx] == name {
			return ndx
		}
	}
	return uint32(0)
}

func getSectionName(sIndex uint32, sectionShstrTab []byte) string {
	end := sIndex
	for end < uint32(len(sectionShstrTab)) {
		if sectionShstrTab[end] == 0x0 {
			break
		}
		end++
	}

	var name bytes.Buffer
	name.Write(sectionShstrTab[sIndex:end])
	return name.String()
}

func getSectionByType(t elf.SectionType, elfFs *ELFFile) []uint32 {

	var indexList []uint32

	if s, ok := elfFs.ElfSections.Section.([]elf.Section32); ok {
		for sNdx := uint32(0); sNdx < uint32(len(s)); sNdx++ {
			if t == elf.SectionType(s[sNdx].Type) {
				indexList = append(indexList, sNdx)
			}
		}
	}

	if s, ok := elfFs.ElfSections.Section.([]elf.Section64); ok {
		for sNdx := uint32(0); sNdx < uint32(len(s)); sNdx++ {
			if t == elf.SectionType(s[sNdx].Type) {
				indexList = append(indexList, sNdx)
			}
		}
	}

	return indexList
}

func (elfFs *ELFFile) getProgHeaders() {
	fmt.Printf("%d program header entries\n", elfFs.Hdr.(*elf.Header64).Phnum)
	fmt.Printf("  \t\t\t\t\tAddress\t\t\t\tSize\n")
	fmt.Printf("  Num:\tType\tFlags\t\tOffset\tVirtual\t\tPhysical\tFile\tMemory\tAlign\n")

	switch elfFs.FileHdr.Arch {
	case elf.ELFCLASS32:
		header, ok := elfFs.Hdr.(*elf.Header32)
		if !ok {
			return
		}

		buffer := make([]byte, header.Phnum*header.Phentsize)
		_, err := elfFs.Fh.Seek(int64(header.Phoff), 0)
		if err != nil {
			fmt.Println(err)
			return
		}

		_, err = io.ReadFull(elfFs.Fh, buffer)
		if err != nil {
			fmt.Println(err)
			return
		}

		for i := 0; i < int(header.Phnum); i++ {
			buf := bytes.NewBuffer(buffer[i*int(header.Phentsize) : (i+1)*int(header.Phentsize)])
			entry := &elf.Prog32{}
			err = binary.Read(buf, elfFs.FileHdr.Endianness, entry)
			if err != nil {
				fmt.Println(err)
				return
			}
			flag := elf.ProgFlag(entry.Flags).String()
			fmt.Printf("  %d\t%d\t%-16s0x%-4s\t0x%-8s\t0x%-8s\t%-4d\t%-4d\t%-4d\n", i, entry.Type, flag, fmt.Sprintf("%X", entry.Off), fmt.Sprintf("%X", entry.Vaddr), fmt.Sprintf("%X", entry.Paddr), entry.Filesz, entry.Memsz, entry.Align)
		}
		break
	case elf.ELFCLASS64:
		header, ok := elfFs.Hdr.(*elf.Header64)
		if !ok {
			return
		}

		buffer := make([]byte, header.Phnum*header.Phentsize)
		_, err := elfFs.Fh.Seek(int64(header.Phoff), 0)
		if err != nil {
			fmt.Println(err)
			return
		}

		_, err = io.ReadFull(elfFs.Fh, buffer)
		if err != nil {
			fmt.Println(err)
			return
		}

		for i := 0; i < int(header.Phnum); i++ {
			buf := bytes.NewBuffer(buffer[i*int(header.Phentsize) : (i+1)*int(header.Phentsize)])
			entry := &elf.Prog64{}
			err = binary.Read(buf, elfFs.FileHdr.Endianness, entry)
			if err != nil {
				fmt.Println(err)
				return
			}
			flag := elf.ProgFlag(entry.Flags).String()
			fmt.Printf("  %d\t%d\t%-16s0x%-4s\t0x%-8s\t0x%-8s\t%-4d\t%-4d\t%-4d\n", i, entry.Type, flag, fmt.Sprintf("%X", entry.Off), fmt.Sprintf("%X", entry.Vaddr), fmt.Sprintf("%X", entry.Paddr), entry.Filesz, entry.Memsz, entry.Align)
		}
		break
	}

}

func (elfFs *ELFFile) getRelocations() {
	elfFs.Rels = make(map[uint32]interface{})
	if s, ok := elfFs.ElfSections.Section.([]elf.Section32); ok {
		for sNdx := uint32(0); sNdx < uint32(len(s)); sNdx++ {
			switch elf.SectionType(s[sNdx].Type) {
			case elf.SHT_REL:
				var rel elf.Rel32
				sr := io.NewSectionReader(elfFs.Fh, int64(s[sNdx].Off), int64(s[sNdx].Size))
				numRels := s[sNdx].Size / uint32(unsafe.Sizeof(rel))
				elfFs.Rels[sNdx] = make([]elf.Rel32, numRels)
				err := binary.Read(sr, elfFs.FileHdr.Endianness, elfFs.Rels[sNdx])
				checkError(err)

			case elf.SHT_RELA:
				var rel elf.Rela32
				sr := io.NewSectionReader(elfFs.Fh, int64(s[sNdx].Off), int64(s[sNdx].Size))
				numRels := s[sNdx].Size / uint32(unsafe.Sizeof(rel))
				elfFs.Rels[sNdx] = make([]elf.Rela32, numRels)
				err := binary.Read(sr, elfFs.FileHdr.Endianness, elfFs.Rels[sNdx])
				checkError(err)

			}
		}
	}

	if s, ok := elfFs.ElfSections.Section.([]elf.Section64); ok {
		for sNdx := uint32(0); sNdx < uint32(len(s)); sNdx++ {
			switch elf.SectionType(s[sNdx].Type) {
			case elf.SHT_REL:
				var rel elf.Rel64
				n := int64(s[sNdx].Off) + int64(s[sNdx].Size)
				sr := io.NewSectionReader(elfFs.Fh, int64(s[sNdx].Off), n)
				numRels := s[sNdx].Size / uint64(unsafe.Sizeof(rel))
				elfFs.Rels[sNdx] = make([]elf.Rel64, numRels)
				err := binary.Read(sr, elfFs.FileHdr.Endianness, elfFs.Rels[sNdx])
				checkError(err)

			case elf.SHT_RELA:
				var rel elf.Rela64
				n := int64(s[sNdx].Off) + int64(s[sNdx].Size)
				sr := io.NewSectionReader(elfFs.Fh, int64(s[sNdx].Off), n)
				numRels := s[sNdx].Size / uint64(unsafe.Sizeof(rel))
				elfFs.Rels[sNdx] = make([]elf.Rela64, numRels)
				err := binary.Read(sr, elfFs.FileHdr.Endianness, elfFs.Rels[sNdx])
				checkError(err)

			}
		}
	}
}

func resolveRelocType(rType uint32, mType elf.Machine) string {
	switch mType {
	case elf.EM_X86_64:
		return fmt.Sprintf("%s", elf.R_X86_64(rType))
	case elf.EM_386:
		return fmt.Sprintf("%s", elf.R_386(rType))
	case elf.EM_ARM:
		return fmt.Sprintf("%s", elf.R_ARM(rType))
	case elf.EM_AARCH64:
		return fmt.Sprintf("%s", elf.R_AARCH64(rType))
	case elf.EM_PPC:
		return fmt.Sprintf("%s", elf.R_PPC(rType))
	case elf.EM_PPC64:
		return fmt.Sprintf("%s", elf.R_PPC64(rType))
	case elf.EM_MIPS:
		return fmt.Sprintf("%s", elf.R_MIPS(rType))
	case elf.EM_RISCV:
		return fmt.Sprintf("%s", elf.R_RISCV(rType))
	case elf.EM_S390:
		return fmt.Sprintf("%s", elf.R_390(rType))
	case elf.EM_SPARCV9:
		return fmt.Sprintf("%s", elf.R_SPARC(rType))
	default:
		return "R_UNKNOWN"
	}
}

func printRelocations(elfFs *ELFFile) {
	if _, ok := elfFs.ElfSections.Section.([]elf.Section32); ok {
		for k, v := range elfFs.Rels {
			sName := elfFs.ElfSections.SectionName[k]
			switch r := v.(type) {
			case []elf.Rel32:
				l := len(r)
				fmt.Printf("\nSection %s has %d relocation entries\n\n", sName, l)
				fmt.Println("Offset\t\t\tInfo\t\t\t\tType\t\t\tSym.Value\t\t\tSym.Name")

				for rNdx := 0; rNdx < l; rNdx++ {
					o := r[rNdx].Off
					t := elf.R_TYPE32(r[rNdx].Info)
					s := elf.R_SYM32(r[rNdx].Info)
					i := elf.R_INFO(s, t)

					relName := resolveRelocType(t, elfFs.FileHdr.Machine)

					var symName string
					var symValue uint32
					var symbol interface{}

					secNdx := elfFs.ElfSections.Section.([]elf.Section32)[k].Link
					switch elfFs.ElfSections.SectionName[secNdx] {
					case ".dynsym":
						symbol = elfFs.DynSymbols[s]
						symName = elfFs.DynSymbolsName[symbol.(*elf.Sym32).Name]
					case ".symtab":
						symbol = elfFs.Symbols[s]
						symName = elfFs.SymbolsName[symbol.(*elf.Sym32).Name]
					default:
						fmt.Printf("f when locating symbol tables in printRelocations()")
						os.Exit(1)
					}
					symValue = symbol.(*elf.Sym32).Value
					fmt.Printf("%016x\t%016x\t%s\t%016x\t\t%s\n", o, i, relName, symValue, symName)
				}
			case []elf.Rela32:
				l := len(r)
				fmt.Printf("\nSection %s has %d relocation entries\n\n", sName, l)
				for rNdx := 0; rNdx < l; rNdx++ {
					o := r[rNdx].Off
					a := r[rNdx].Addend
					t := elf.R_TYPE32(r[rNdx].Info)
					s := elf.R_SYM32(r[rNdx].Info)
					i := elf.R_INFO(s, t)

					relName := resolveRelocType(t, elfFs.FileHdr.Machine)

					var symName string
					var symValue uint32
					var symbol interface{}

					secNdx := elfFs.ElfSections.Section.([]elf.Section32)[k].Link
					switch elfFs.ElfSections.SectionName[secNdx] {
					case ".dynsym":
						symbol = elfFs.DynSymbols[s]
						symName = elfFs.DynSymbolsName[symbol.(*elf.Sym32).Name]
					case ".symtab":
						symbol = elfFs.Symbols[s]
						symName = elfFs.SymbolsName[symbol.(*elf.Sym32).Name]
					default:
						fmt.Printf("f when locating symbol tables in printRelocations()")
						os.Exit(1)
					}
					symValue = symbol.(*elf.Sym32).Value
					if s != uint32(elf.SHN_UNDEF) {
						symName += " + "
					}
					fmt.Printf("%016x\t%016x\t%s\t%016x\t\t%s%d\n", o, i, relName, symValue, symName, a)
				}
			}
		}
	}

	if _, ok := elfFs.ElfSections.Section.([]elf.Section64); ok {
		for k, v := range elfFs.Rels {
			sName := elfFs.ElfSections.SectionName[k]
			switch r := v.(type) {
			case []elf.Rel64:
				l := len(r)
				fmt.Printf("\nSection %s has %d relocation entries\n\n", sName, l)
				fmt.Println("Offset\t\t\tInfo\t\t\t\tType\t\t\tSym.Value\t\t\tSym.Name")

				for rNdx := 0; rNdx < l; rNdx++ {
					o := r[rNdx].Off
					t := elf.R_TYPE64(r[rNdx].Info)
					s := elf.R_SYM64(r[rNdx].Info)
					i := elf.R_INFO(s, t)

					relName := resolveRelocType(t, elfFs.FileHdr.Machine)

					var symName string
					var symValue uint64
					var symbol interface{}

					secNdx := elfFs.ElfSections.Section.([]elf.Section64)[k].Link
					switch elfFs.ElfSections.SectionName[secNdx] {
					case ".dynsym":
						symbol = elfFs.DynSymbols[s]
						symName = elfFs.DynSymbolsName[symbol.(*elf.Sym64).Name]
					case ".symtab":
						symbol = elfFs.Symbols[s]
						symName = elfFs.SymbolsName[symbol.(*elf.Sym64).Name]
					default:
						fmt.Printf("f when locating symbol tables in printRelocations()")
						os.Exit(1)
					}
					symValue = symbol.(*elf.Sym64).Value
					fmt.Printf("%016x\t%016x\t%s\t%016x\t\t%s\n", o, i, relName, symValue, symName)
				}
			case []elf.Rela64:
				l := len(r)
				fmt.Printf("\nSection %s has %d relocation entries\n\n", sName, l)
				fmt.Println("Offset\t\t\tInfo\t\t\t\tType\t\t\tSym.Value\t\t\tSym.Name + Addend")

				for rNdx := 0; rNdx < l; rNdx++ {
					o := r[rNdx].Off
					a := r[rNdx].Addend
					t := elf.R_TYPE64(r[rNdx].Info)
					s := elf.R_SYM64(r[rNdx].Info)
					i := elf.R_INFO(s, t)

					relName := resolveRelocType(t, elfFs.FileHdr.Machine)

					var symName string
					var symValue uint64
					var symbol interface{}

					secNdx := elfFs.ElfSections.Section.([]elf.Section64)[k].Link
					switch elfFs.ElfSections.SectionName[secNdx] {
					case ".dynsym":
						symbol = elfFs.DynSymbols[s]
						symName = elfFs.DynSymbolsName[symbol.(*elf.Sym64).Name]
					case ".symtab":
						symbol = elfFs.Symbols[s]
						symName = elfFs.SymbolsName[symbol.(*elf.Sym64).Name]
					default:
						fmt.Printf("Error when locating symbol tables in printRelocations()")
						os.Exit(1)
					}
					symValue = symbol.(*elf.Sym64).Value
					if s != uint32(elf.SHN_UNDEF) {
						symName += " + "
					}
					fmt.Printf("%016x\t%016x\t%s\t%016x\t\t%s%d\n", o, i, relName, symValue, symName, a)
				}
			}
		}
	}
}

func printSymbols(elfFs *ELFFile) {
	var symPresent, dsymPresent bool
	var ndsym, nsym int

	if ndsym = len(elfFs.DynSymbols); ndsym > 0 {
		dsymPresent = true
	}
	if nsym = len(elfFs.Symbols); nsym > 0 {
		symPresent = true
	}

	switch elfFs.FileHdr.Arch {
	case elf.ELFCLASS32:
		fmt.Printf("  Num:\tValue\t\tSize \tType\t\tBind\t\tVis\t\tNdx\t\tName\n")
		if dsymPresent {
			for sNdx := uint32(0); sNdx < uint32(ndsym); sNdx++ {
				sym := elfFs.DynSymbols[sNdx]
				v := sym.(*elf.Sym32).Value
				s := sym.(*elf.Sym32).Size
				t := elf.ST_TYPE(sym.(*elf.Sym32).Info)
				b := elf.ST_BIND(sym.(*elf.Sym32).Info)
				vis := elf.ST_VISIBILITY(sym.(*elf.Sym32).Info)
				sec := sym.(*elf.Sym32).Shndx
				nm := elfFs.DynSymbolsName[sym.(*elf.Sym32).Name]
				fmt.Printf("  %-5d %08x\t%d\t%s\t%s\t%s\t%d\t%s\n", sNdx, v, s, t, b, vis, sec, nm)
			}
		}

		if symPresent {
			for sNdx := uint32(0); sNdx < uint32(nsym); sNdx++ {
				sym := elfFs.Symbols[sNdx]
				v := sym.(*elf.Sym32).Value
				s := sym.(*elf.Sym32).Size
				t := elf.ST_TYPE(sym.(*elf.Sym32).Info)
				b := elf.ST_BIND(sym.(*elf.Sym32).Info)
				vis := elf.ST_VISIBILITY(sym.(*elf.Sym32).Info)
				sec := sym.(*elf.Sym32).Shndx
				nm := elfFs.SymbolsName[sym.(*elf.Sym32).Name]
				fmt.Printf("  %-5d %08x\t%d\t%s\t%s\t%s\t%d\t%s\n", sNdx, v, s, t, b, vis, sec, nm)
			}
		}
	case elf.ELFCLASS64:
		fmt.Printf("  Num:\tValue\t\tSize \tType\t\tBind\t\tVis\t\tNdx\t\tName\n")
		if dsymPresent {
			for sNdx := uint32(0); sNdx < uint32(ndsym); sNdx++ {
				sym := elfFs.DynSymbols[sNdx]
				v := sym.(*elf.Sym64).Value
				s := sym.(*elf.Sym64).Size
				t := elf.ST_TYPE(sym.(*elf.Sym64).Info)
				b := elf.ST_BIND(sym.(*elf.Sym64).Info)
				vis := elf.ST_VISIBILITY(sym.(*elf.Sym64).Info)
				sec := sym.(*elf.Sym64).Shndx
				nm := elfFs.DynSymbolsName[sym.(*elf.Sym64).Name]
				fmt.Printf("  %-5d %08x\t%d\t%s\t%s\t%s\t%d\t%s\n", sNdx, v, s, t, b, vis, sec, nm)
			}
		}

		if symPresent {
			for sNdx := uint32(0); sNdx < uint32(nsym); sNdx++ {
				sym := elfFs.Symbols[sNdx]
				v := sym.(*elf.Sym64).Value
				s := sym.(*elf.Sym64).Size
				t := elf.ST_TYPE(sym.(*elf.Sym64).Info)
				b := elf.ST_BIND(sym.(*elf.Sym64).Info)
				vis := elf.ST_VISIBILITY(sym.(*elf.Sym64).Info)
				sec := sym.(*elf.Sym64).Shndx
				nm := elfFs.SymbolsName[sym.(*elf.Sym64).Name]
				fmt.Printf("  %-5d %08x\t%d\t%s\t%s\t%s\t%d\t%s\n", sNdx, v, s, t, b, vis, sec, nm)
			}
		}
	}

}

func printSections(ElfSections SHDRTable, numSec uint16, secOff interface{}) {
	switch v := secOff.(type) {
	case uint32:
		fmt.Printf("%d Sections @ Offset 0x%x\n", numSec, v)

	case uint64:
		fmt.Printf("%d Sections @ Offset 0x%x\n", numSec, v)
	}

	if section, ok := ElfSections.Section.([]elf.Section32); ok {
		fmt.Println("[NR]  Name\t\t\tType\t\tAddress\t\t\tOffsets")
		fmt.Println("      Size\t\t\tEntSize\t\tFlags Link Info\t\tAlign")
		for i := uint16(0); i < numSec; i++ {
			a := section[i].Addr
			o := section[i].Off
			s := section[i].Size
			e := section[i].Entsize
			l := section[i].Link
			f := flagToKey(fmt.Sprintf("%s", elf.SectionFlag(section[i].Flags)))
			info := section[i].Info
			align := section[i].Addralign
			nm := ElfSections.SectionName[i]

			/* SHT_REL string throws off alignment, this is a hack to maintain alignment for display purposes */
			t := fmt.Sprintf("%s", elf.SectionType(section[i].Type))
			if t == "SHT_REL" {
				t += " "
			}

			fmt.Printf("[%-2d]  %-20s\t%s\t%08x\t\t%08x\n", i, nm, t, a, o)
			fmt.Printf("      %08x\t\t\t%08x\t  %-5s%-5d%d\t\t%5d\n", s, e, f, l, info, align)
		}
	}

	if section, ok := ElfSections.Section.([]elf.Section64); ok {
		fmt.Println("[NR]  Name\t\t\tType\t\tAddress\t\t\tOffsets")
		fmt.Println("      Size\t\t\tEntSize\t\tFlags Link Info\t\tAlign")
		for i := uint16(0); i < numSec; i++ {
			t := elf.SectionType(section[i].Type)
			a := section[i].Addr
			o := section[i].Off
			s := section[i].Size
			e := section[i].Entsize
			l := section[i].Link
			f := flagToKey(fmt.Sprintf("%s", elf.SectionFlag(section[i].Flags)))
			info := section[i].Info
			align := section[i].Addralign
			nm := ElfSections.SectionName[i]
			fmt.Printf("[%-2d]  %-20s\t%s\t%016x\t%08x\n", i, nm, t, a, o)
			fmt.Printf("      %016x\t\t%016x  %-5s%-5d%d\t\t%5d\n", s, e, f, l, info, align)
		}
	}

	fmt.Println("Key to Flags:")
	fmt.Println("W (write), A (alloc), X (executable), M (merge), S (strings), I (info)")
	fmt.Println("L (link order), O (extra os processing required), G (group), T (TLS)")
	fmt.Println("C (compressed), p (processor specific)")
}

func flagToKey(flag string) (key string) {
	if strings.Contains(flag, "SHF_WRITE") {
		key += "W"
	}

	if strings.Contains(flag, "SHF_ALLOC") {
		key += "A"
	}

	if strings.Contains(flag, "SHF_EXECINSTR") {
		key += "X"
	}

	if strings.Contains(flag, "SHF_MERGE") {
		key += "M"
	}

	if strings.Contains(flag, "SHF_STRINGS") {
		key += "S"
	}

	if strings.Contains(flag, "SHF_INFO_LINK") {
		key += "I"
	}

	if strings.Contains(flag, "SHF_LINK_ORDER") {
		key += "L"
	}

	if strings.Contains(flag, "SHF_OS_NONCONFORMING") {
		key += "O"
	}

	if strings.Contains(flag, "SHF_GROUP") {
		key += "G"
	}

	if strings.Contains(flag, "SHF_TLS") {
		key += "T"
	}

	if strings.Contains(flag, "SHF_COMPRESSED") {
		key += "C"
	}

	if strings.Contains(flag, "SHF_MASKOS") {
		key += "o"
	}

	if strings.Contains(flag, "SHF_MASKPROC") {
		key += "P"
	}
	return
}

func printHeader(hdr interface{}) {
	if h, ok := hdr.(*elf.Header64); ok {
		fmt.Printf("-------------------------- Elf Header ------------------------\n")
		fmt.Printf("Magic: % x\n", h.Ident)
		fmt.Printf("Class: %s\n", elf.Class(h.Ident[elf.EI_CLASS]))
		fmt.Printf("Data: %s\n", elf.Data(h.Ident[elf.EI_DATA]))
		fmt.Printf("Version: %s\n", elf.Version(h.Version))
		fmt.Printf("OS/ABI: %s\n", elf.OSABI(h.Ident[elf.EI_OSABI]))
		fmt.Printf("ABI Version: %d\n", h.Ident[elf.EI_ABIVERSION])
		fmt.Printf("Elf Type: %s\n", elf.Type(h.Type))
		fmt.Printf("Machine: %s\n", elf.Machine(h.Machine))
		fmt.Printf("Entry: 0x%x\n", h.Entry)
		fmt.Printf("Program Header Offset: 0x%x\n", h.Phoff)
		fmt.Printf("Section Header Offset: 0x%x\n", h.Shoff)
		fmt.Printf("Flags: 0x%x\n", h.Flags)
		fmt.Printf("Elf Header Size (bytes): %d\n", h.Ehsize)
		fmt.Printf("Program Header Entry Size (bytes): %d\n", h.Phentsize)
		fmt.Printf("Number of Program Header Entries: %d\n", h.Phnum)
		fmt.Printf("Size of Section Header Entry: %d\n", h.Shentsize)
		fmt.Printf("Number of Section Header Entries: %d\n", h.Shnum)
		fmt.Printf("Index of section header string table: %d\n", h.Shstrndx)
	}

	if h, ok := hdr.(*elf.Header32); ok {
		fmt.Printf("-------------------------- Elf Header ------------------------\n")
		fmt.Printf("Magic: % x\n", h.Ident)
		fmt.Printf("Class: %s\n", elf.Class(h.Ident[elf.EI_CLASS]))
		fmt.Printf("Data: %s\n", elf.Data(h.Ident[elf.EI_DATA]))
		fmt.Printf("Version: %s\n", elf.Version(h.Version))
		fmt.Printf("OS/ABI: %s\n", elf.OSABI(h.Ident[elf.EI_OSABI]))
		fmt.Printf("ABI Version: %d\n", h.Ident[elf.EI_ABIVERSION])
		fmt.Printf("Elf Type: %s\n", elf.Type(h.Type))
		fmt.Printf("Machine: %s\n", elf.Machine(h.Machine))
		fmt.Printf("Entry: 0x%x\n", h.Entry)
		fmt.Printf("Program Header Offset: 0x%x\n", h.Phoff)
		fmt.Printf("Section Header Offset: 0x%x\n", h.Shoff)
		fmt.Printf("Flags: 0x%x\n", h.Flags)
		fmt.Printf("Elf Header Size (bytes): %d\n", h.Ehsize)
		fmt.Printf("Program Header Entry Size (bytes): %d\n", h.Phentsize)
		fmt.Printf("Number of Program Header Entries: %d\n", h.Phnum)
		fmt.Printf("Size of Section Header Entry: %d\n", h.Shentsize)
		fmt.Printf("Number of Section Header Entries: %d\n", h.Shnum)
		fmt.Printf("Index of section header string table: %d\n", h.Shstrndx)
	}
	return
}

func main() {
	if len(os.Args) < 3 {
		usage()
		os.Exit(1)

	}

	var target ELFFile

	bin := os.Args[2]
	target.Fh, target.err = os.Open(bin)
	checkError(target.err)
	defer target.Fh.Close()

	target.Fh.Read(target.Ident[:16])

	if isElf(target.Ident[:4]) == false {
		fmt.Println("This is not an Elf binary")
		os.Exit(1)
	}
	target.setArch()
	target.mapHeader()

	options := os.Args[1]
	if options[0] != '-' {
		usage()
		os.Exit(1)
	}

	var optHeader, optSections, optSymbols, optRelocations, optProgHeaders bool
	for i := 1; i < len(options); i++ {
		switch {
		case options[i] == 'h':
			optHeader = true
		case options[i] == 'S':
			optSections = true
		case options[i] == 's':
			optSymbols = true
		case options[i] == 'r':
			optRelocations = true
		case options[i] == 'l':
			optProgHeaders = true
		default:
			fmt.Println("Unrecognizable parameters")
			os.Exit(1)
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

		if optSymbols == false {
			target.getSymbols()
		}
		target.getRelocations()
		printRelocations(&target)

	}

	if optProgHeaders {
		target.getProgHeaders()
	}
}

func usage() {
	fmt.Printf("Usage: %s [-hrsS] <target-binary>\n", os.Args[0])
	fmt.Println("\t-h: View Elf header")
	fmt.Println("\t-r: View relocation entries")
	fmt.Println("\t-s: View symbols")
	fmt.Println("\t-S: View Sections")
	fmt.Println("\t-l: View program headers")
}

func checkError(e error) {
	if e != nil {
		panic(e)
	}
}

func isElf(magic []byte) bool {
	return !(magic[0] != '\x7f' || magic[1] != 'E' || magic[2] != 'L' || magic[3] != 'F')
}
