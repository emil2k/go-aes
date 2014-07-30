package ctr

import (
	"github.com/emil2k/go-aes/cipher"
	"github.com/emil2k/go-aes/modes"
	"github.com/emil2k/go-aes/util/rand"
	"testing"
)

func BenchmarkEncrypt(b *testing.B) {
	ck := rand.GetRand(16) // random 128 bit cipher key
	nonce := rand.GetRand(8)
	cf := func() *cipher.Cipher {
		return cipher.NewCipher(cipher.CK128)
	}
	counter := NewCounter(cf)
	modes.BenchmarkEncrypt(b, counter, ck, nonce)
}
