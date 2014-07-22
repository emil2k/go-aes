package main

import (
	"io"
	"os"
)

// writeToFile writes the data bytes to given file outputting any errors
// to the error log
func writeToFile(f *os.File, data ...byte) {
	if _, err := f.Write(data); err != nil {
		errorLog.Fatalln(err)
	}
}

// readFromFile reads data from given file into a byte slice
// outputs any errors to the error log maximum size 20KB
func readFromFile(f *os.File) []byte {
	var fsize int64
	if finfo, err := f.Stat(); err != nil {
		errorLog.Fatalln(err)
		return nil
	} else if fsize = finfo.Size(); fsize > 20*1024 {
		errorLog.Fatalln("file is to large to read, file size :", fsize)
		return nil
	}
	data := make([]byte, fsize)
	if n, err := f.Read(data); err != nil {
		if err == io.EOF {
			debugLog.Println("read to eof", f.Name())
			return data
		}
		errorLog.Fatalln("Error reading from file :", err)
		return nil
	} else if verbose {
		debugLog.Println(n, "bytes read from", f.Name())
	}
	return data
}

// createFile creates a file, truncates an existing file outputs errors
// to the error log
func createFile(name string) *os.File {
	if f, err := os.Create(name); err != nil {
		errorLog.Fatalln(err)
		return nil
	} else {
		if verbose {
			debugLog.Println("created file", f.Name())
		}
		return f
	}
}

// openFile opens a file outputs errors to the the error log
func openFile(name string) *os.File {
	if f, err := os.Open(name); err != nil {
		errorLog.Fatalln(err)
		return nil
	} else {
		if verbose {
			debugLog.Println("opened file", f.Name())
		}
		return f
	}
}

// closeFile closes a file outputting any errors to the error log
func closeFile(f *os.File) {
	if err := f.Close(); err != nil {
		errorLog.Fatalln(err)
	}
	if verbose {
		debugLog.Println("closed file", f.Name())
	}
}
