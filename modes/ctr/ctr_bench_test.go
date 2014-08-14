package ctr

import (
	"github.com/emil2k/go-aes/cipher"
	"github.com/emil2k/go-aes/modes"
	"github.com/emil2k/go-aes/state"
	"github.com/emil2k/go-aes/util/bytes"
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
	modes.EncryptBenchmark(b, counter, ck, nonce)
}

func BenchmarkProcessBlockPayload(b *testing.B) {
	ck := rand.GetRand(16) // random 128 bit cipher key
	in := *state.NewStateFromBytes(rand.GetRand(16))
	nonce := bytes.DecodeIntFromBytes(rand.GetRand(8))
	block := newBlockPayload(cipher.NewCipher(cipher.CK128), 100000, in, getCounterBlock(nonce, 100000), ck)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		block.process()
	}
}

func BenchmarkGetCounterBlock(b *testing.B) {
	nonce := bytes.DecodeIntFromBytes(rand.GetRand(8))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		getCounterBlock(nonce, 100000)
	}
}
