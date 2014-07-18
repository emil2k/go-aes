package main

import (
	crand "crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/emil2k/go-aes/cipher"
	"github.com/emil2k/go-aes/modes/ctr"
)

const help string = `
Encrypt and decrypt files using an AES block cipher.

%s [ -d | -v | -vv ] [-mode mode] key_file input_file output_file

`

// Logs
var errorLog *log.Logger = log.New(os.Stderr, "errror : ", 0)
var infoLog *log.Logger = log.New(os.Stdout, "info : ", 0)
var debugLog *log.Logger = log.New(os.Stdout, "debug : ", 0)

// Command line arguments
var verbose bool
var veryVerbose bool
var isDecrypt bool
var mode string
var args []string
var key string
var input string
var output string

func init() {
	flag.Usage = func() {
		command := os.Args[0]
		fmt.Fprintf(os.Stderr, help, command)
		flag.PrintDefaults()
		fmt.Fprintln(os.Stderr, "\n~~ by Emil ~~\n")
	}
}

func main() {
	// Parse command flags
	flag.BoolVar(&verbose, "v", false, "verbose output, debugging from block cipher mode")
	flag.BoolVar(&veryVerbose, "vv", false, "very verbose output, includes debugging from block cipher")
	flag.BoolVar(&isDecrypt, "d", false, "whether in encryption mode")
	flag.StringVar(&mode, "mode", "ctr", "block cipher mode, `ctr` for counter mode")
	flag.Parse()
	if veryVerbose {
		verbose = true
	}
	args = flag.Args()
	if len(args) < 3 {
		errorLog.Fatalln("must specify the key, input, output paths for both encryption and decrytption")
	}
	key, input, output = args[0], args[1], args[2]
	if verbose {
		debugLog.Println("verbose : ", verbose)
		debugLog.Println("very verbose : ", veryVerbose)
		debugLog.Println("mode : ", mode)
		debugLog.Println("is decryption? : ", isDecrypt)
		debugLog.Println("key : ", key)
		debugLog.Println("output : ", output)
		debugLog.Println("input : ", input)
		debugLog.Println("args : ", args)
	}
	// Setup file handlers
	var kfile, ifile, ofile *os.File
	if isDecrypt {
		kfile, ifile, ofile = openFile(key), openFile(input), createFile(output)
	} else {
		kfile, ifile, ofile = createFile(key), openFile(input), createFile(output)
	}
	defer closeFile(kfile)
	defer closeFile(ifile)
	defer closeFile(ofile)
	// Initiate data
	var ck, in, nonce []byte
	if isDecrypt {
		ck = readFromFile(kfile)
		nonce, in = inputFromFile(ifile)
	} else {
		// Generate random cipher key
		ck = getRand(16)
		in = readFromFile(ifile)
		nonce, _ = ctr.NewNonce()
	}
	if verbose {
		debugLog.Println(hex.EncodeToString(ck), "cipher key")
		debugLog.Println(hex.EncodeToString(nonce), "nonce")
	}
	// Setup cipher factory
	cf := func() *cipher.Cipher {
		c := cipher.NewCipher(4, 10)
		c.ErrorLog = errorLog
		if verbose {
			c.InfoLog = infoLog
			if veryVerbose {
				c.DebugLog = debugLog
			}
		}
		return c
	}
	// Setup and run the appropriate block cipher mode
	switch mode {
	case "ctr", "cm", "icm", "sic":
		infoLog.Println("counter mode chosen")
		ctrMode := ctr.NewCounter(cf)
		ctrMode.ErrorLog = errorLog
		ctrMode.InfoLog = infoLog
		if verbose {
			ctrMode.DebugLog = debugLog
		}
		if isDecrypt {
			out := ctrMode.Decrypt(in, ck, nonce)
			writeToFile(ofile, out...)
			infoLog.Println("decryption stored in", ofile.Name())
		} else {
			outputToFile(ofile, nonce, ctrMode.Encrypt(in, ck, nonce))
			infoLog.Println("encryption stored in", ofile.Name())
			// Output cipher key
			writeToFile(kfile, ck...)
			infoLog.Println("cipher key stored in", kfile.Name())
		}
	default:
		errorLog.Fatalln("unknown mode chosen")
	}
}

// outputToFile outputs the encrypted data into a custom AES file format
//  1 Octet - length of nonce or IV in bytes
// nn Octet - nonce or IV
// nn Octet - encrypted message
func outputToFile(f *os.File, iv []byte, data []byte) {
	writeToFile(f, byte(len(iv)))
	writeToFile(f, iv...)
	writeToFile(f, data...)
}

// inputFromFile parses the custom AES file format returning the nonce and
// encrypted message
func inputFromFile(f *os.File) ([]byte, []byte) {
	data := readFromFile(f)
	ivl := int(data[0])
	return data[1 : 1+ivl], data[1+ivl:]
}

// writeToFile writes the data bytes to given file outputting any errors
// to the error log
func writeToFile(f *os.File, data ...byte) {
	if _, err := f.Write(data); err != nil {
		errorLog.Panicln(err)
	}
}

// readFromFile reads data from given file into a byte slice
// outputs any errors to the error log maximum size 1024 bytes
func readFromFile(f *os.File) []byte {
	var fsize int64
	if finfo, err := f.Stat(); err != nil {
		errorLog.Panicln(err)
		return nil
	} else if fsize = finfo.Size(); fsize > 1024 {
		errorLog.Panicln("file is to large to read, file size :", fsize)
		return nil
	}
	data := make([]byte, fsize)
	if n, err := f.Read(data); err != nil {
		errorLog.Panicln(err)
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
		errorLog.Panicln(err)
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
		errorLog.Panicln(err)
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
		errorLog.Panicln(err)
	}
	if verbose {
		debugLog.Println("closed file", f.Name())
	}
}

// getRand provides a n-byte slice of random data
// uses a "cryptographically secure pseudorandom number generator"
func getRand(n int) []byte {
	r := make([]byte, n)
	if _, err := crand.Read(r); err != nil {
		log.Panicln(err)
		return nil
	}
	return r
}
