What is it ?

go-readelf is a small elf binary parser currently capable of printing relocation entries, elf header, sections and Symbols.
It utilizes Go's elf package for typing and structure information while performing the mechanics for 
parsing elf binaries independently. It supports both 32 and 64-bit elf binaries and was tested/built on x86_64 Linux (Arch).

What about binutils readelf ?

This is a pet project really meant to culuminate/expand what I am currently studying out of a book called 
Linux Binary Analysis (chapter-2). Readelf is about 16k lines of C code, so this is in no way a replacement (it would be a meme to claim it is).
If you would like to see what elf parsing looks like in Golang then this utility source code certainly helps, maybe for some reason you need a lightweight elf parser.
I'd also suggest
the elf package in Golang.

Installation:
<pre>
[terminal]$ git clone https://github.com/sad0p/go-readelf.git
[terminal]$ cd go-readelf
[terminal]$ go build go-readelf.go
[terminal]$ ./go-readelf
Usage: ./go-readelf [-hrsS] <target_binary>
        -h: View elf header
        -r: View relocation entries
        -s: View symbols
        -S: View Sections
        -l: View program headers
[terminal]$ 
</pre>
Source code quality:
I'm fairly new to Go, as a matter of fact this is the first application I've written in the language, refactoring
along the lines of the Effective Go guidelines are welcomed if I missed anything.

Needed improvements:
I purposely didn't implement the ability to print program headers, hopefully someone takes up the task before I'm
no longer bored and push code to do just that.

Future work related to this project:

I'm definitely looking forward to writing a parser that is resistant to anti-reverse engineering techniques that corrupt
Elf meta data to the point it stops analysis tools like this, but binary is still interpreted and executes correctly.
