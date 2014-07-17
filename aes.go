package main

import (
	crand "crypto/rand"
	"encoding/hex"
	"flag"
	"log"
	mrand "math/rand"
	"os"
	"time"

	"github.com/emil2k/go-aes/cipher"
	"github.com/emil2k/go-aes/modes/ctr"
	"github.com/emil2k/go-aes/state"
)

// Logs
var errorLog *log.Logger = log.New(os.Stderr, "errror : ", 0)
var infoLog *log.Logger = log.New(os.Stdout, "info : ", 0)
var debugLog *log.Logger = log.New(os.Stdout, "debug : ", 0)

// Command line arguments
var verbose bool
var veryVerbose bool
var mode string
var output string
var keyOutput string

func main() {
	// Parse command flags
	flag.BoolVar(&verbose, "v", false, "verbose output, debugging from block cipher mode")
	flag.BoolVar(&veryVerbose, "vv", false, "very verbose output, includes debugging from block cipher")
	flag.StringVar(&mode, "mode", "ctr", "block cipher mode, `ctr` for counter mode")
	flag.StringVar(&output, "o", "output.aes", "output file for the encrypted file")
	flag.StringVar(&keyOutput, "k", "output.key.aes", "output file for the encryption key")
	flag.Parse()
	if veryVerbose {
		verbose = true
	}
	if verbose {
		debugLog.Println("verbose : ", verbose)
		debugLog.Println("very verbose : ", veryVerbose)
		debugLog.Println("mode : ", mode)
		debugLog.Println("args : ", flag.Args())
	}
	// Open up output files
	ofile := createFile(output)
	defer closeFile(ofile)
	ofileKey := createFile(keyOutput)
	defer closeFile(ofileKey)
	// Setup cipher
	c := cipher.NewCipher(4, 10)
	c.ErrorLog = errorLog
	if verbose {
		c.InfoLog = infoLog
		if veryVerbose {
			c.DebugLog = debugLog
		}
	}
	// Generate random input data
	mrand.Seed(time.Now().UnixNano())
	in := getRand(mrand.Intn(1000)) // random length input
	c.DebugLog.Println(len(in), "bytes in input")
	// Generate random cipher key
	ck := getRand(16)
	c.DebugLog.Println(state.State(ck), "cipher key")
	// Setup and run the appropriate block cipher mode
	switch mode {
	case "ctr", "cm", "icm", "sic":
		infoLog.Println("counter mode chosen")
		ctrMode := ctr.NewCounter(c)
		ctrMode.ErrorLog = errorLog
		ctrMode.InfoLog = infoLog
		if verbose {
			ctrMode.DebugLog = debugLog
		}
		nonce, _ := ctr.NewNonce()
		ct := ctrMode.Encrypt(in, ck, nonce)
		if verbose {
			debugLog.Printf("cipher text after counter mode encryption\n%s\n", hex.Dump(ct))
		}
		outputToFile(ofile, nonce, ct)
		infoLog.Println("encryption stored in", ofile.Name())
	default:
		errorLog.Fatalln("unknown mode chosen")
	}
	// Output cipher key
	writeToFile(ofileKey, ck...)
	infoLog.Println("cipher key stored in", ofileKey.Name())
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

// writeToFile writes the data bytes to given file outputting any errors
// to the error log
func writeToFile(f *os.File, data ...byte) {
	if _, err := f.Write(data); err != nil {
		errorLog.Panicln(err)
	}
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
