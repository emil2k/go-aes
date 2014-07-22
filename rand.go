package main

import (
	"crypto/rand"
)

// getRand provides a n-byte slice of random data
// uses a "cryptographically secure pseudorandom number generator"
func getRand(n int) []byte {
	r := make([]byte, n)
	if _, err := rand.Read(r); err != nil {
		errorLog.Fatalln(err)
		return nil
	}
	return r
}
