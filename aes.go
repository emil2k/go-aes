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

// Command line arguments
var verbose bool
var mode string

func main() {
	flag.BoolVar(&verbose, "v", false, "verbose output")
	flag.StringVar(&mode, "mode", "ctr", "block cipher mode, `ctr` for counter mode.")
	flag.Parse()
	log.Println("Arguments")
	log.Println("verbose : ", verbose)
	log.Println("mode : ", mode)
	log.Println("args : ", flag.Args())
	c := cipher.NewCipher(4, 10)
	c.ErrorLog = log.New(os.Stderr, "error : ", 0)
	c.InfoLog = log.New(os.Stderr, "info : ", 0)
	if verbose {
		c.DebugLog = log.New(os.Stdout, "debug : ", 0)
	}
	mrand.Seed(time.Now().UnixNano())
	in := getRand(mrand.Intn(1000)) // random length input
	c.DebugLog.Println(len(in), "bytes in input")
	ck := getRand(16)
	c.DebugLog.Println(state.State(ck), "cipher key")
	switch mode {
	case "ctr", "cm", "icm", "sic":
		log.Println("counter mode chosen")
		mode := ctr.NewCounter()
		ct := mode.Encrypt(in, ck)
		log.Printf("cipher text after counter mode encryption\n%s\n", hex.Dump(ct))
	default:
		log.Fatalln("unknown mode chosen")
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
