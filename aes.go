package main

import (
	"crypto/rand"
	"flag"
	"log"
	"os"

	"github.com/emil2k/go-aes/cipher"
)

// Command line arguments
var verbose bool

func main() {
	flag.BoolVar(&verbose, "v", false, "verbose output")
	flag.Parse()
	log.Println("Arguments")
	log.Println("verbose : ", verbose)
	log.Println("args : ", flag.Args())
	c := cipher.NewCipher(4, 10)
	c.ErrorLog = log.New(os.Stderr, "error : ", 0)
	c.InfoLog = log.New(os.Stderr, "info : ", 0)
	if verbose {
		c.DebugLog = log.New(os.Stdout, "debug : ", 0)
	}
	in := getRand(16)
	ck := getRand(16)
	ct := c.Encrypt(in, ck)
	c.Decrypt(ct, ck)
}

// getRand provides a n-byte slice of random data
// uses a "cryptographically secure pseudorandom number generator"
func getRand(n int) []byte {
	r := make([]byte, n)
	if _, err := rand.Read(r); err != nil {
		log.Panicln(err)
		return nil
	}
	return r
}
