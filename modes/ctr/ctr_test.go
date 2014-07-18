package ctr

import "bytes"
import "encoding/hex"
import "github.com/emil2k/go-aes/cipher"
import "log"
import "os"
import "testing"

func TestEncryptDecrypt(t *testing.T) {
	log := log.New(os.Stdout, "", 0)
	in := []byte{0x01, 0x02, 0x03}
	ck := []byte{0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a}
	cf := func() *cipher.Cipher {
		c := cipher.NewCipher(cipher.CK128)
		c.ErrorLog, c.DebugLog, c.InfoLog = log, log, log
		return c
	}
	nonce, _ := NewNonce()
	counter := NewCounter(cf)
	counter.ErrorLog, counter.DebugLog, counter.InfoLog = log, log, log
	if out := counter.Decrypt(counter.Encrypt(in, ck, nonce), ck, nonce); !bytes.Equal(out, in) {
		t.Errorf("Encryption followed by decryption failed with %s", hex.EncodeToString(out))
	}
}

func TestAddPadding(t *testing.T) {
	in := []byte{0x67, 0x8b, 0x95, 0x77, 0x53, 0x3f, 0x38, 0xaa, 0x09, 0x9b, 0x97}
	out := []byte{0x67, 0x8b, 0x95, 0x77, 0x53, 0x3f, 0x38, 0xaa, 0x09, 0x9b, 0x97, 0x05, 0x05, 0x05, 0x05, 0x05}
	c := Counter{in: in}
	if c.addPadding(); !bytes.Equal(c.in, out) {
		t.Errorf("Adding padding failed with %s", hex.EncodeToString(c.in))
	}
}

func TestRemovePadding(t *testing.T) {
	in := []byte{0x67, 0x8b, 0x95, 0x77, 0x53, 0x3f, 0x38, 0xaa, 0x09, 0x9b, 0x97, 0x05, 0x05, 0x05, 0x05, 0x05}
	out := []byte{0x67, 0x8b, 0x95, 0x77, 0x53, 0x3f, 0x38, 0xaa, 0x09, 0x9b, 0x97}
	c := Counter{out: in}
	if c.removePadding(); !bytes.Equal(c.out, out) {
		t.Errorf("Remove padding failed with %s", hex.EncodeToString(c.out))
	}
}

func TestGetCounterBlock(t *testing.T) {
	nonce, _ := NewNonce()
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

func TestGetBlock(t *testing.T) {
	in := []byte{0x67, 0x8b, 0x95, 0x77, 0x53, 0x3f, 0x38, 0xaa, 0x09, 0x9b, 0x97, 0x05, 0x05, 0x05, 0x05, 0x05}
	out := []byte{0x67, 0x8b, 0x95, 0x77, 0x53, 0x3f, 0x38, 0xaa, 0x09, 0x9b, 0x97, 0x05, 0x05, 0x05, 0x05, 0x05}
	for i := 0; i < 32; i++ {
		in = append(in, 0x00)
	}
	c := Counter{in: in}
	if b := c.getBlock(0); !bytes.Equal(b, out) {
		t.Errorf("Get block failed with %s", hex.EncodeToString(b))
	}
}

func TestNonceLength(t *testing.T) {
	n, _ := NewNonce()
	if len(n) != 8 {
		t.Errorf("Nonce is not 8 bytes long")
	}
}
