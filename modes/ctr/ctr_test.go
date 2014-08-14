package ctr

import (
	"github.com/emil2k/go-aes/cipher"
	"github.com/emil2k/go-aes/modes"
	"github.com/emil2k/go-aes/state"
	"github.com/emil2k/go-aes/util/bytes"
	"github.com/emil2k/go-aes/util/rand"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	ck := rand.GetRand(16) // random 128 bit cipher key
	nonce := rand.GetRand(8)
	cf := func() *cipher.Cipher {
		return cipher.NewCipher(cipher.CK128)
	}
	counter := NewCounter(cf)
	modes.EncryptDecryptTest(t, counter, ck, nonce)
}

func TestGetCounterBlock(t *testing.T) {
	var nonce, counter uint64 = bytes.DecodeIntFromBytes(rand.GetRand(8)), 255
	cb := state.State{High: counter, Low: nonce}
	if x := getCounterBlock(nonce, 255); x != cb {
		t.Errorf("Getting counter block failed %s", x)
	}
}
