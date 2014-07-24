package ctr

import "bytes"
import "encoding/hex"
import "github.com/emil2k/go-aes/cipher"
import "github.com/emil2k/go-aes/modes"
import "io/ioutil"
import "log"
import "testing"

func TestEncryptDecrypt(t *testing.T) {
	log := log.New(ioutil.Discard, "", 0)
	in := []byte{0x01, 0x02, 0x03}
	ck := []byte{0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a}
	cf := func() *cipher.Cipher {
		c := cipher.NewCipher(cipher.CK128)
		c.ErrorLog, c.DebugLog, c.InfoLog = log, log, log
		return c
	}
	nonce, _ := modes.NewNonce(8)
	counter := NewCounter(cf)
	if out := counter.Decrypt(counter.Encrypt(in, ck, nonce), ck, nonce); !bytes.Equal(out, in) {
		t.Errorf("Encryption followed by decryption failed with %s", hex.EncodeToString(out))
	}
}

func TestGetCounterBlock(t *testing.T) {
	nonce, _ := modes.NewNonce(8)
	counter := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff}
	cb := append(nonce, counter...)
	c := Counter{nonce: nonce}
	if x := c.getCounterBlock(1<<8 - 1); !bytes.Equal(x, cb) {
		t.Errorf("Getting counter block failed %s", hex.EncodeToString(x))
	}
}

func TestGetCounterBlockPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != "over maximum counter 256" {
			t.Errorf("Get counter block panic failed with %s", r)
		}
	}()
	c := Counter{}
	c.getCounterBlock(1 << 8) // should panic because the counter can only hold an 8 bit number
}
