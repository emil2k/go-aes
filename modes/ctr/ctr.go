package ctr

import (
	"crypto/rand"
	"fmt"
)
import "github.com/emil2k/go-aes/cipher"

// Counter keeps track of the state of a counter cipher mode
// used for encryption or decryption
type Counter struct {
	i         int    // keeps track of the counter
	isDecrypt bool   // whether decryption, otherwise encryption
	nonce     []byte // initialization vector
	ck        []byte // cipher key
	in        []byte // input plain or cipher text
	out       []byte // output cipher or plain text
}

// NewCounter creates a new counter, nothing interesting
func NewCounter() *Counter {
	return &Counter{}
}

// initCounter initializes a counter either for encryption or decryption
func (c *Counter) initCounter(in []byte, ck []byte, isDecrypt bool) {
	c.i = 0
	c.in = in
	c.out = make([]byte, 0)
	c.ck = ck
	c.isDecrypt = isDecrypt
}

// Encrypt encrypts the input using CTR mode with 128-bit AES as the block cipher
func (c *Counter) Encrypt(in []byte, ck []byte) []byte {
	c.initCounter(in, ck, false)
	c.addPadding()
	blocks := len(c.in) / 16
	aes := cipher.NewCipher(4, 10)
	for c.i < blocks {
		cc := aes.Encrypt(c.getCounterBlock(c.i), ck) // cipher text from encrypting cipher block
		ib := c.getBlock(c.i)                         // input block
		for i, _ := range ib {
			ib[i] ^= cc[i]
		}
		c.out = append(c.out, ib...)
		c.i++
	}
	return c.out
}

// Decrypt decrypts the input using CTR mode with 128-bit AES as the cipher block
func (c *Counter) Decrypt(in []byte, ck []byte) []byte {
	c.initCounter(in, ck, true)
	blocks := len(c.in) / 16
	aes := cipher.NewCipher(4, 10)
	for c.i < blocks {
		cc := aes.Encrypt(c.getCounterBlock(c.i), ck) // cipher text from encrypting cipher block
		ib := c.getBlock(c.i)                         // input block
		for i, _ := range ib {
			ib[i] ^= cc[i]
		}
		c.out = append(c.out, ib...)
		c.i++
	}
	c.removePadding()
	return c.out
}

// addPadding pads the input to get a positive number of 16 byte blocks
// padded with n bytes of n value bytes, if already divides into 16 byte block
// attach a full 16 byte block with 16 stored in each byte
func (c *Counter) addPadding() {
	pad := 16 - (len(c.in) % 16)
	for i := 0; i < pad; i++ {
		c.in = append(c.in, byte(pad))
	}
}

// removePadding removes the padding of a decrypted plaintext output
func (c *Counter) removePadding() {
	pad := int(c.out[len(c.out)-1])
	c.out = c.out[:len(c.out)-pad]
}

// getCounterBlock gets the ith counter 16 byte block copies the data into a
// slice with a new underlying array.
// The first 8 bytes of the block are the nonce the last 8 bytes consist of all
// zeroes with the last byte being the count will panic if surpasses maximum count of 1 << 8
func (c *Counter) getCounterBlock(i int) []byte {
	if i >= 1<<8 {
		panic(fmt.Sprintf("over maximum counter %d", 1<<8))
	}
	t := make([]byte, 16)
	copy(t, c.nonce)
	t[15] = byte(i) // set the last byte to the counter
	return t
}

// getBlock gets the ith input block copies data into a slice
// with a new underlying array
func (c *Counter) getBlock(i int) []byte {
	t := make([]byte, 16)
	copy(t, c.in[i*16:(i+1)*16])
	return t
}

// newNonce generates a new 8 byte nonce, returns nonce slice and error
func newNonce() ([]byte, error) {
	nonce := make([]byte, 8)
	_, err := rand.Read(nonce)
	return nonce, err
}
