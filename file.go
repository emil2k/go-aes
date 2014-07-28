package main

import (
	"fmt"
	"io"
	"os"
)

// writeToFile writes the data bytes to given file, panics if error.
func writeToFile(f *os.File, data ...byte) {
	if _, err := f.Write(data); err != nil {
		panic(err)
	}
}

// readFromFile reads data from given file into a byte slice, panics if error.
// Maximum size 20KB
func readFromFile(f *os.File) []byte {
	var fsize int64
	if finfo, err := f.Stat(); err != nil {
		panic(err)
		return nil
	} else if fsize = finfo.Size(); fsize > 20*1024 {
		panic(fmt.Sprintf("file is to large to read, file size : %d bytes", fsize))
		return nil
	}
	data := make([]byte, fsize)
	if n, err := f.Read(data); err != nil {
		if err == io.EOF {
			debugLog.Println("read to eof", f.Name())
			return data
		}
		panic(fmt.Sprintf("Error reading from file : %s", err))
		return nil
	} else if args.verbose {
		debugLog.Println(n, "bytes read from", f.Name())
	}
	return data
}

// getFileSize returns the files size, panics if error.
func getFileSize(name string) int64 {
	if finfo, err := os.Stat(name); err != nil {
		panic(err)
	} else {
		return finfo.Size()
	}
}

// createFile creates a file, truncates an existing file, panics if error.
func createFile(name string) *os.File {
	if f, err := os.Create(name); err != nil {
		panic(err)
		return nil
	} else {
		if args.verbose {
			debugLog.Println("created file", f.Name())
		}
		return f
	}
}

// openFile opens a file, panics if error.
func openFile(name string) *os.File {
	if f, err := os.Open(name); err != nil {
		panic(err)
		return nil
	} else {
		if args.verbose {
			debugLog.Println("opened file", f.Name())
		}
		return f
	}
}

// closeFile closes a file, panics if error.
func closeFile(f *os.File) {
	if err := f.Close(); err != nil {
		panic(err)
	}
	if args.verbose {
		debugLog.Println("closed file", f.Name())
	}
}
