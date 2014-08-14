package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"

	"github.com/emil2k/go-aes/cipher"
	"github.com/emil2k/go-aes/modes"
	"github.com/emil2k/go-aes/modes/cbc"
	"github.com/emil2k/go-aes/modes/ctr"
	"github.com/emil2k/go-aes/util/rand"
)

// help is displayed with the usage info for the command.
const help string = `
Encrypt and decrypt files using an AES block cipher.

%s [ -d | -v | -vv ] [-mode mode] [-size size] key_file input_file output_file

`

var errorLog *log.Logger = log.New(os.Stderr, "error : ", 0) // log for errors
var standardLog *log.Logger = log.New(os.Stdout, "", 0)      // log for regular output, non-verbose
var verboseLog *log.Logger                                   // log for verbose output
var veryVerboseLog *log.Logger                               // log for very verbose output

var args CommandArguments // holds the command parameters for the current execution

// CommandArguments holds the parameters to run the command.
type CommandArguments struct {
	verbose     bool   // whether to log verbose output
	veryVerbose bool   // whether to log very verbose ouput, including info from block cipher
	isDecrypt   bool   // whether decrypting
	mode        string // string identifier for the block cipher mode
	keySize     uint64 // cipher key size in bits
	key         string // the file path for the cipher key, encryption will generate a cipher key at the location
	input       string // the file path for the input
	output      string // the file path for the output
}

// init setups the command flags.
func init() {
	defer fatalPanic()
	prepareFlags()
}

// main executes the main branch of the command.
func main() {
	defer fatalPanic()
	// Parse and validate the command flags
	flag.Parse()
	if args.veryVerbose {
		args.verbose = true
	}
	prepareLogs() // instantiates any verbose logs
	if len(flag.Args()) < 3 {
		panic("must specify the key, input, output paths for both encryption and decrytption")
	}
	args.key, args.input, args.output = flag.Args()[0], flag.Args()[1], flag.Args()[2]
	verboseLog.Println("verbose : ", args.verbose)
	verboseLog.Println("very verbose : ", args.veryVerbose)
	verboseLog.Println("mode : ", args.mode)
	verboseLog.Println("key size : ", args.keySize)
	verboseLog.Println("is decryption? : ", args.isDecrypt)
	verboseLog.Println("key : ", args.key)
	verboseLog.Println("output : ", args.output)
	verboseLog.Println("input : ", args.input)
	// Execute encryption or decryption
	if args.isDecrypt {
		decrypt()
	} else {
		encrypt()
	}
}

// prepareFlags prepares the command flags.
func prepareFlags() {
	// Set the usage string, displayed when help is run
	flag.Usage = func() {
		command := os.Args[0]
		fmt.Fprintf(os.Stderr, help, command)
		flag.PrintDefaults()
		fmt.Fprintln(os.Stderr, "\n~~ by Emil ~~\n")
	}
	// Setup the command flags
	flag.BoolVar(&args.verbose, "v", false, "verbose output, debugging from block cipher mode")
	flag.BoolVar(&args.veryVerbose, "vv", false, "very verbose output, includes debugging from block cipher")
	flag.BoolVar(&args.isDecrypt, "d", false, "whether in encryption mode")
	flag.StringVar(&args.mode, "mode", "ctr", "block cipher mode, `ctr` for counter or `cbc` for chain-block chaining")
	flag.Uint64Var(&args.keySize, "size", 128, "cipher key size in bits, for encryption only")
}

// prepareLogs initiates the different logs based on the verbose parameters.
func prepareLogs() {
	if args.verbose {
		verboseLog = log.New(os.Stdout, "debug : ", 0)
	} else {
		verboseLog = log.New(ioutil.Discard, "", 0)
	}
	if args.veryVerbose {
		veryVerboseLog = log.New(os.Stdout, "debug : ", 0)
	} else {
		veryVerboseLog = log.New(ioutil.Discard, "", 0)
	}
}

// encrypt executes the encrypting branch of the command.
func encrypt() {
	checkKeySize(args.keySize)
	kfile, ifile, ofile := createFile(args.key), openFile(args.input), createFile(args.output)
	defer closeFile(kfile)
	defer closeFile(ifile)
	defer closeFile(ofile)
	// Initiate data
	ck := rand.GetRand(int(args.keySize / 8)) // generate random cipher key
	// Setup and run the appropriate block cipher mode
	var nonce []byte
	var mode modes.ModeInterface
	switch args.mode {
	case "ctr", "cm", "icm", "sic":
		verboseLog.Println("counter mode chosen")
		nonce = rand.GetRand(8)
		mode = ctr.NewCounter(getCipherFactory())
	case "cbc":
		verboseLog.Println("chain-block chaining mode chosen")
		nonce = rand.GetRand(16)
		mode = cbc.NewChain(getCipherFactory())
	default:
		panic("unknown mode chosen")
	}
	prepareMode(mode)
	prepareOutput(ofile, nonce)
	// Run the encryption
	mode.Encrypt(uint64(len(nonce)+1), uint64(getFileSize(args.input)), ifile, ofile, ck, nonce)
	standardLog.Println("encryption stored in", ofile.Name())
	writeToFile(kfile, ck...)
	standardLog.Println("cipher key stored in", kfile.Name())
}

// decrypt executes the decrypting branch of the command.
func decrypt() {
	// Check cipher key size
	kfile := openFile(args.key)
	defer closeFile(kfile)
	if info, err := kfile.Stat(); err != nil {
		panic(err)
	} else if !info.Mode().IsRegular() {
		panic("key file is not a regular file")
	} else {
		args.keySize = uint64(info.Size()) * 8
		checkKeySize(args.keySize)
	}
	ifile, ofile := openFile(args.input), createFile(args.output)
	defer closeFile(ifile)
	defer closeFile(ofile)
	// Initiate data
	ck := readFromFile(kfile)
	nonce := processInput(ifile)
	// Setup and run the appropriate block cipher mode
	var mode modes.ModeInterface
	switch args.mode {
	case "ctr", "cm", "icm", "sic":
		verboseLog.Println("counter mode chosen")
		mode = ctr.NewCounter(getCipherFactory())
	case "cbc":
		verboseLog.Println("chain-block chaining mode chosen")
		mode = cbc.NewChain(getCipherFactory())
	default:
		panic("unknown mode chosen")
	}
	prepareMode(mode)
	// Run the decryption
	mode.Decrypt(uint64(len(nonce)+1), uint64(getFileSize(args.input))-uint64(len(nonce)+1), ifile, ofile, ck, nonce)
	standardLog.Println("decryption stored in", ofile.Name())
}

// fatalPanic in case of a recovered panic logs and exits execution with code 1.
func fatalPanic() {
	// if r := recover(); r != nil {
	// 	errorLog.Fatal(r)
	// }
}

// checkKeySize checks the passed key size in bits, panics if invalid cipher key size.
func checkKeySize(k uint64) {
	switch cipher.CipherKeySize(k) {
	case cipher.CK128, cipher.CK192, cipher.CK256:
	default:
		panic(fmt.Sprintf("invalid cipher key size %d bits", k))
	}
}

// getCipherFactory configures and returns an cipher factory instance.
func getCipherFactory() cipher.CipherFactory {
	return func() *cipher.Cipher {
		c := cipher.NewCipher(cipher.CipherKeySize(args.keySize))
		c.ErrorLog = errorLog
		c.InfoLog = verboseLog
		c.DebugLog = veryVerboseLog
		return c
	}
}

// prepareMode sets the logs on the block cipher mode based on the command line arguments.
func prepareMode(mode modes.ModeInterface) {
	mode.SetErrorLog(errorLog)
	mode.SetInfoLog(standardLog)
	mode.SetDebugLog(verboseLog)
}

// prepareOutput prepares the output by prefixing with info about the initiliazation vector.
// Uses the following custom AES format :
//  1 Octet - length of nonce or IV in bytes
// nn Octet - nonce or IV
// nn Octet - encrypted message
func prepareOutput(f *os.File, iv []byte) {
	writeToFile(f, byte(len(iv)))
	writeToFile(f, iv...)
}

// processInput extracts the initialization vector from the input file, parsing the custom AES format.
// Panics if there is any problems processing the format.
func processInput(f *os.File) []byte {
	ivl := make([]byte, 1)
	if n, err := f.Read(ivl); err != nil && err != io.EOF {
		panic(err)
	} else if n != 1 {
		panic(fmt.Sprintf("iv length must be one byte, read %d bytes", n))
	}
	ivLen := int(ivl[0])
	iv := make([]byte, ivLen)
	if n, err := f.Read(iv); err != nil && err != io.EOF {
		panic(err)
	} else if n != ivLen {
		panic(fmt.Sprintf("iv length does not match, read %d bytes should have been %d bytes", n, ivLen))
	}
	return iv
}
