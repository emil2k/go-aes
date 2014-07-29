package ctr

import (
	"bytes"
	"encoding/hex"
	"github.com/emil2k/go-aes/cipher"
	"github.com/emil2k/go-aes/modes"
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
	modes.TestEncryptDecrypt(t, counter, ck, nonce)
}

func TestGetCounterBlock(t *testing.T) {
	nonce := rand.GetRand(8)
	counter := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff}
	cb := append(nonce, counter...)
	c := Counter{nonce: nonce}
	if x := c.getCounterBlock(1<<8 - 1); !bytes.Equal(x, cb) {
		t.Errorf("Getting counter block failed %s", hex.EncodeToString(x))
	}
}
