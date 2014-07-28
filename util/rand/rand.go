package rand

import (
	"crypto/rand"
)

// GetRand provides a n-byte slice of random data uses a "cryptographically secure
// pseudorandom number generator". Panic if encounters an error.
func GetRand(n int) []byte {
	out := make([]byte, n)
	if _, err := rand.Read(out); err != nil {
		panic(err.Error())
	}
	return out
}
