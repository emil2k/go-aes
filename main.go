package main

import (
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

%s [ -d | -v | -vv ] [-mode mode] [-size size] key_file input_file output_file

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
var keySize int
var key string
var input string
var output string
var args []string

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
	flag.IntVar(&keySize, "size", 128, "cipher key size in bits, for encryption only")
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
		debugLog.Println("key size : ", keySize)
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
		keySize = len(ck)
	} else {
		in = readFromFile(ifile)
		nonce, _ = ctr.NewNonce()
	}
	if verbose {
		debugLog.Println(hex.EncodeToString(ck), "cipher key")
		debugLog.Println(hex.EncodeToString(nonce), "nonce")
	}
	// Setup and run the appropriate block cipher mode
	switch mode {
	case "ctr", "cm", "icm", "sic":
		infoLog.Println("counter mode chosen")
		// Check cipher key size
		switch cipher.CipherKeySize(keySize) {
		case cipher.CK128, cipher.CK192, cipher.CK256:
			if !isDecrypt {
				ck = getRand(keySize) // generate random cipher key
			}
		default:
			errorLog.Fatalln("invalid cipher key size", keySize)
		}
		// Setup cipher factory
		cf := func() *cipher.Cipher {
			c := cipher.NewCipher(cipher.CipherKeySize(keySize))
			c.ErrorLog = errorLog
			if verbose {
				c.InfoLog = infoLog
				if veryVerbose {
					c.DebugLog = debugLog
				}
			}
			return c
		}
		// Setup counter state
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
