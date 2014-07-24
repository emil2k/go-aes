package cbc

import (
	"bytes"
	"encoding/hex"
	"github.com/emil2k/go-aes/cipher"
	"github.com/emil2k/go-aes/modes"
	"io/ioutil"
	"log"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	log := log.New(ioutil.Discard, "", 0)
	in := []byte{0x01, 0x02, 0x03}
	ck := []byte{0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a}
	cf := func() *cipher.Cipher {
		c := cipher.NewCipher(cipher.CK128)
		c.ErrorLog, c.DebugLog, c.InfoLog = log, log, log
		return c
	}
	nonce, _ := modes.NewNonce(16)
	chain := NewChain(cf)
	if out := chain.Decrypt(chain.Encrypt(in, ck, nonce), ck, nonce); !bytes.Equal(out, in) {
		t.Errorf("Encryption followed by decryption failed with %s", hex.EncodeToString(out))
	}
}
