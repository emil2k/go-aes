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

func main() {
	// Parse command flags
	flag.BoolVar(&verbose, "v", false, "verbose output, debugging from block cipher mode")
	flag.BoolVar(&veryVerbose, "vv", false, "very verbose output, includes debugging from block cipher")
	flag.StringVar(&mode, "mode", "ctr", "block cipher mode, `ctr` for counter mode")
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
	default:
		errorLog.Fatalln("unknown mode chosen")
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
