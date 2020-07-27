package main

import (
	"os"
	"fmt"
//	"strings"
)

const (
	SUCCESS int = 0
	ERROR   int = 1
)
func main() {

	if len(os.Args) < 3{
		usage()
		os.Exit(ERROR)

	}
	var optheader, optsections bool
	options := os.Args[1]
	if options[0] != '-' {
		usage()
		os.Exit(ERROR)
	}

	for i := 0; i < len(options) ; i++ {
		switch {
		case options[i] == 'h':
			fmt.Println("h flag present")
			optheader = true
		case options[i] == 'S':
			fmt.Println("S flag present")
			optsections = true
		default:
			fmt.Println("not recognizing")
		}
	}

}

func usage() {
	fmt.Println("Usage information")

}
